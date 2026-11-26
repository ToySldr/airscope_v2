"""In-memory index over captures/ plus the single write path for capture
artifacts. Loaded once at startup and refreshed on each save, so reads never
re-scan the directory. Wraps persist.save + persist.capture_history."""
from __future__ import annotations

import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterator, List, Optional

from airscope.models import CaptureType, PersistedCapture
from airscope.persist import save
from airscope.persist.capture_validation import PACKET_SUFFIXES
from airscope.persist.capture_history import load_capture_index, summarize
from airscope.persist.common import LEGACY_CAPTURE_RE, bssid_to_dashed, safe_ssid
from airscope.persist.config import Config
from airscope.persist.save import SaveResult

if TYPE_CHECKING:
    from airscope.models import AccessPoint


def _open_in_file_manager(path: Path) -> None:
    if sys.platform.startswith("win"):
        import os
        os.startfile(path)                                        # noqa: S606 (Windows only)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class Vault:
    """Caches the on-disk capture index (from Config.captures_dir) and is the
    sole read/write path for handshake, PMKID, WEP, and WPS artifacts."""

    # Capture-kind -> human label, in display order. The one place these map.
    _KIND_LABELS = {
        CaptureType.HS: "Handshake",
        CaptureType.PMKID: "PMKID",
        CaptureType.WEP: "WEP Key",
        CaptureType.WPS_PIN: "WPS PIN",
        CaptureType.WPS_PBC: "WPS PBC",
        CaptureType.CRACKED: "Cracked PSK",
        CaptureType.EVILTWIN_PSK: "EvilTwin PSK",
        CaptureType.SAE: "SAE",
    }

    def __init__(self) -> None:
        self._index: Dict[str, List[PersistedCapture]] = {}
        self.refresh()

    def refresh(self) -> None:
        """Re-scan Config.captures_dir into the cache."""
        self._index = load_capture_index()

    # ----- reads -----

    def persisted(self, bssid: str) -> List[PersistedCapture]:
        """This AP's saved captures, newest-first (empty if none)."""
        return self._index.get(bssid, [])

    def all_captures(self) -> List[PersistedCapture]:
        """Every saved capture across all APs, unordered (callers sort as needed)."""
        return [c for caps in self._index.values() for c in caps]

    def capture_payload(self, capture: PersistedCapture) -> str:
        """Copyable text for a capture: its stored value (WEP/WPS), else the file's
        own contents (HS/PMKID hashlines). Empty string if unreadable."""
        if capture.value is not None:
            return capture.value
        if Path(capture.path).suffix.lower() in PACKET_SUFFIXES:
            return ""
        try:
            return Path(capture.path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""

    def summary(self) -> Optional[str]:
        """One-line count of every saved capture, e.g. '3 handshakes, 1 WEP key',
        or None when nothing is saved."""
        hs, pmkid, wep, wps, cracked = summarize(self._index)
        parts = []
        if hs:
            parts.append(f"{hs} handshake{'s' * (hs != 1)}")
        if pmkid:
            parts.append(f"{pmkid} PMKID{'s' * (pmkid != 1)}")
        if wep:
            parts.append(f"{wep} WEP key{'s' * (wep != 1)}")
        if wps:
            parts.append(f"{wps} WPS PSK{'s' * (wps != 1)}")
        if cracked:
            parts.append(f"{cracked} cracked PSK{'s' * (cracked != 1)}")
        return ", ".join(parts) or None

    def detailed_summary(self, ap: "AccessPoint") -> dict[str, tuple[PersistedCapture, int]]:
        """Per-kind rollup for the Focus 'Existing captures' panel:
        ``{human label: (newest_capture, count)}``, absent kinds omitted, kind order."""
        caps = self.persisted(ap.bssid)
        result: dict[str, tuple[PersistedCapture, int]] = {}
        for kind, label in self._KIND_LABELS.items():
            matching = [c for c in caps if c.type == kind]
            if matching:
                result[label] = (max(matching, key=lambda c: c.timestamp), len(matching))
        return result

    def known_psk(self, ap: "AccessPoint") -> Optional[str]:
        """The passphrase held for this AP: recovered this session (PBC/PIN/crack)
        or loaded from a prior session's file, else None. A WPS PIN alone does
        not count."""
        return (
            ap.wps_pbc_psk
            or ap.wps_pin_psk
            or next((p.value for p in self.persisted(ap.bssid)
                      if p.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC,
                                    CaptureType.CRACKED, CaptureType.EVILTWIN_PSK)
                      and p.value), None)
        )

    def has_psk(self, ap: "AccessPoint") -> bool:
        """True once we hold this AP's passphrase (see known_psk)."""
        return self.known_psk(ap) is not None

    def has_handshake(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.HS)

    def has_pmkid(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.PMKID)

    def has_wep_key(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.WEP)

    def iter_psk_items(self) -> Iterator[tuple[str, str]]:
        """(bssid, psk) for every stored passphrase (cracked / eviltwin / PBC / PIN) across APs."""
        seen: set[str] = set()
        for bssid, caps in self._index.items():
            for c in caps:
                if (c.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC,
                               CaptureType.CRACKED, CaptureType.EVILTWIN_PSK)
                        and c.value and c.value not in seen):
                    seen.add(c.value)
                    yield bssid, c.value

    def has_wps_psk(self, ap: "AccessPoint") -> bool:
        return any(c.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC)
                   for c in self.persisted(ap.bssid))

    def wps_capture(self, ap: "AccessPoint") -> Optional[PersistedCapture]:
        """Newest saved WPS credential for this AP (PIN- or PBC-derived), or None."""
        return next((c for c in self.persisted(ap.bssid)
                     if c.type in (CaptureType.WPS_PIN, CaptureType.WPS_PBC) and c.value), None)

    def _has(self, bssid: str, kind: CaptureType) -> bool:
        return any(c.type == kind for c in self.persisted(bssid))

    # ----- writes (persist to disk, then fold into the cache) -----

    def save_handshake(self, ap: "AccessPoint", client_mac: str) -> Optional[SaveResult]:
        result = save.save_handshake(ap, client_mac)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.HS, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid))
        return result

    def save_pmkid(self, ap: "AccessPoint", client_mac: str) -> Optional[SaveResult]:
        result = save.save_pmkid(ap, client_mac)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.PMKID, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid))
        return result

    def save_wep_key(self, ap: "AccessPoint", key: bytes) -> Optional[SaveResult]:
        result = save.save_wep_key(ap, key)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WEP, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid,
                                    value=key.hex()))
        return result

    def save_wps_pin(self, ap: "AccessPoint", pin: str, psk: str) -> Optional[SaveResult]:
        result = save.save_wps_pin(ap, pin, psk)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WPS_PIN, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid,
                                    value=psk, pin=pin))
        return result

    def save_wps_pbc(self, ap: "AccessPoint", psk: str) -> Optional[SaveResult]:
        result = save.save_wps_pbc(ap, psk)
        if result and result.was_new:
            self._index.setdefault(ap.bssid, []).insert(
                0, PersistedCapture(type=CaptureType.WPS_PBC, timestamp=int(time.time()),
                                    path=str(result.path), bssid=ap.bssid, ssid=ap.ssid,
                                    value=psk))
        return result

    def save_cracked_psk(self, bssid: str, ssid: str | None, psk: str, tool: str) -> Optional[SaveResult]:
        bssid = bssid.lower()
        result = save.save_cracked_psk(bssid, ssid, psk, tool)
        if result is None:
            return None
        self.refresh()
        if not any(c.type == CaptureType.CRACKED and Path(c.path).resolve() == result.path.resolve()
                   and c.value == psk and (not ssid or c.ssid == ssid)
                   for c in self.persisted(bssid)):
            return None
        return result

    def has_cracked_psk(self, bssid: str) -> bool:
        return self._has(bssid, CaptureType.CRACKED)

    def save_sae(self, ap: "AccessPoint", frames: list[tuple[bytes, float]]) -> Optional[SaveResult]:
        result = save.save_sae(ap, frames)
        if result and result.was_new:
            self.refresh()   # re-index so the pair count comes from the parser
        return result

    def has_sae(self, ap: "AccessPoint") -> bool:
        return self._has(ap.bssid, CaptureType.SAE)

    # ----- filesystem ops (the screen goes through these, never touches disk) -----

    def _safe_capture_file(self, file_path: str) -> Path:
        """Permit deleting only an existing capture file inside configured captures/."""
        root = Path(Config.captures_dir).resolve()
        path = Path(file_path).resolve()
        if not path.is_relative_to(root) or path == root:
            raise ValueError(f"Refusing to delete a file outside captures/: {file_path}")
        if not path.is_file():
            raise FileNotFoundError(f"Capture file missing or not a regular file: {file_path}")
        return path

    def network_capture_paths(self, bssid: str) -> list[Path]:
        """Distinct indexed files for one BSSID, including companion hash/PCAP."""
        return sorted({Path(c.path) for c in self.persisted(bssid)}, key=str)

    def delete_capture(self, capture: PersistedCapture) -> int:
        """Delete exactly one selected indexed file, verify, then rebuild the cache."""
        if not any(c.path == capture.path and c.bssid == capture.bssid
                   for c in self.all_captures()):
            raise ValueError("Selected capture is no longer indexed; refresh and retry")
        path = self._safe_capture_file(capture.path)
        try:
            path.unlink()  # no missing_ok: silently ignoring missing files hid errors
            if path.exists():
                raise OSError(f"Capture still exists after deletion: {path}")
        finally:
            self.refresh()  # Reconcile the Vault cache with the real filesystem.
        return 1

    def delete_network_captures(self, bssid: str) -> int:
        """Delete all indexed files for one BSSID, never files from other networks.

        Preflight every file before deleting. An OS error mid-way is reported and
        the cache is refreshed, so the UI can show any remaining files.
        """
        paths = self.network_capture_paths(bssid)
        if not paths:
            raise ValueError("No indexed files for the selected network")
        selected_paths = {str(p) for p in paths}
        shared = [c.path for c in self.all_captures()
                  if c.bssid != bssid and c.path in selected_paths]
        if shared:
            raise ValueError("A capture file is also indexed under another BSSID; "
                             "network-wide deletion blocked to protect other networks")
        safe_paths = [self._safe_capture_file(str(path)) for path in paths]
        removed = 0
        try:
            for path in safe_paths:
                path.unlink()
                removed += 1
                if path.exists():
                    raise OSError(f"File still exists after deletion: {path}")
        except OSError as exc:
            raise OSError(f"Removed {removed} of {len(safe_paths)} files before failure: {exc}") from exc
        finally:
            self.refresh()
        return removed

    def zip_captures(self, captures: List[PersistedCapture],
                     save_as: Optional[Path] = None) -> Optional[Path]:
        """Zip the given captures' files (deduped) into ``save_as``, defaulting to a
        timestamped archive beside captures/. None if none of the files exist."""
        paths: List[Path] = []
        seen: set[str] = set()
        for c in captures:
            p = Path(c.path)
            if p.is_file() and str(p) not in seen:
                seen.add(str(p))
                paths.append(p)
        if not paths:
            return None
        if save_as is None:
            save_as = Path(Config.captures_dir).parent / f"airscope_captures_{int(time.time())}.zip"
        with zipfile.ZipFile(save_as, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                zf.write(p, arcname=p.name)
        return save_as

    def open_directory(self) -> None:
        """Reveal captures/ in the OS file manager."""
        _open_in_file_manager(Path(Config.captures_dir))

    # ----- legacy .hc22000 consolidation (temporary: pre-aggregate installs) ---

    def _legacy_hc_files(self) -> List[Path]:
        """Pre-aggregate per-capture .hc22000 files still on disk (one file per
        capture, vs today's one aggregate file per AP)."""
        root = Path(Config.captures_dir)
        if not root.is_dir():
            return []
        return [p for p in root.iterdir()
                if p.is_file() and (m := LEGACY_CAPTURE_RE.match(p.name))
                and m.group("ext") == "hc22000"]

    def legacy_hc_file_count(self) -> int:
        """Number of legacy per-capture .hc22000 files that could be consolidated."""
        return len(self._legacy_hc_files())

    def legacy_hc_unique_count(self) -> int:
        """Distinct SSID+BSSID the legacy files would collapse into (one file each)."""
        return len({f"{safe_ssid(m.group('ssid'))}_{bssid_to_dashed(m.group('bssid'))}"
                    for p in self._legacy_hc_files()
                    if (m := LEGACY_CAPTURE_RE.match(p.name))})

    def consolidate_legacy_hc_files(self) -> tuple[int, int]:
        """Merge legacy per-capture .hc22000 files into one per AP, then refresh the
        cache. Returns (migrated_ap_count, deleted_file_count)."""
        migrated, deleted = save.consolidate_hc_files(Path(Config.captures_dir))
        self.refresh()
        return migrated, deleted
