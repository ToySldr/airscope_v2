"""Read-only validation of selected Vault handshake files.

A successful extraction demonstrates that a converter produced a hash record,
not that its MIC has been cryptographically validated or its password recovered.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def _counts(lines: list[str]) -> tuple[int, int, int]:
    eapol = sum(s.startswith("WPA*02*") for s in lines)
    pmkid = sum(s.startswith("WPA*01*") for s in lines)
    other = sum(s.startswith(("WPA*03*", "WPA*04*")) for s in lines)
    return eapol, pmkid, other


def validate_capture(path: Path) -> str:
    path = Path(path)
    if not path.is_file():
        return "Missing capture file"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return f"Cannot read capture: {exc}"
    suffix = path.suffix.lower()
    if suffix in (".hc22000", ".22000"):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return f"Cannot read hash file: {exc}"
        eapol, pmkid, other = _counts(lines)
        return (f"{size} B | Saved hash records: EAPOL {eapol}, PMKID {pmkid}, "
                f"other WPA {other} (format markers only)")
    if suffix not in (".pcap", ".pcapng", ".cap"):
        return f"Unsupported file type: {suffix or '(none)'}"

    tshark_info = "EAPOL packets: unavailable"
    tshark = shutil.which("tshark")
    if tshark:
        try:
            result = subprocess.run(
                [tshark, "-r", str(path), "-Y", "eapol", "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if result.returncode == 0:
                tshark_info = f"EAPOL packets: {len(result.stdout.splitlines())}"
            else:
                tshark_info = f"tshark failed (exit {result.returncode})"
        except subprocess.TimeoutExpired:
            tshark_info = "tshark timed out"
        except OSError as exc:
            tshark_info = f"tshark error: {exc}"

    converter = shutil.which("hcxpcapngtool")
    if not converter:
        return f"{size} B | {tshark_info} | hcxpcapngtool not installed"
    try:
        with tempfile.TemporaryDirectory(prefix="airscope-validate-") as temp:
            dest = Path(temp) / "validation.hc22000"
            result = subprocess.run(
                [converter, "-o", str(dest), str(path)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            lines = dest.read_text(errors="replace").splitlines() if dest.is_file() else []
            eapol, pmkid, other = _counts(lines)
            status = f"extractor exit: {result.returncode}"
            if result.returncode:
                return f"{size} B | {tshark_info} | {status}; no reliable extraction result"
            return (f"{size} B | {tshark_info} | Extracted: EAPOL {eapol}, "
                    f"PMKID {pmkid}, other WPA {other} | {status}")
    except subprocess.TimeoutExpired:
        return f"{size} B | {tshark_info} | extraction timed out"
    except OSError as exc:
        return f"{size} B | {tshark_info} | extraction error: {exc}"


PACKET_SUFFIXES = frozenset({".cap", ".pcap", ".pcapng"})
HASH_SUFFIXES = frozenset({".hc22000", ".22000"})
_PCAP_MAGICS = {bytes.fromhex(value) for value in ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1")}


def validate_selected_capture(path: Path, bssid: str, expected_ssid: str | None = None) -> str:
    """Inspect packet metadata without deriving password-recovery material."""
    suffix = path.suffix.lower()
    if suffix in HASH_SUFFIXES:
        try:
            with path.open("r", encoding="utf-8") as records:
                lines = [line.strip() for line in records if line.strip()]
        except FileNotFoundError:
            return "Missing capture file"
        except UnicodeDecodeError:
            return "Invalid saved records: expected UTF-8 text"
        except OSError as exc:
            return f"Cannot read saved records: {exc}"
        if any("\x00" in line for line in lines):
            return "Invalid saved records: unexpected binary data"
        eapol, pmkid, other = _counts(lines)
        if not (eapol or pmkid or other):
            return "No WPA record markers in saved file"
        return (f"Saved hash records: EAPOL {eapol}, PMKID {pmkid}, other WPA {other} "
                "(format markers only; AP identity unverified)")
    if suffix not in PACKET_SUFFIXES:
        return f"Unsupported file type: {suffix or '(none)'}"
    try:
        with path.open("rb") as capture:
            header = capture.read(28)
    except FileNotFoundError:
        return "Missing capture file"
    except OSError as exc:
        return f"Cannot read capture: {exc}"

    if len(header) >= 24 and header[:4] in _PCAP_MAGICS:
        kind = "pcap"
    elif (len(header) >= 28 and header[:4] == bytes.fromhex("0a0d0d0a")
          and header[8:12] in (bytes.fromhex("1a2b3c4d"), bytes.fromhex("4d3c2b1a"))):
        kind = "pcapng"
    else:
        return "Unrecognized or truncated packet capture header"

    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", bssid, re.IGNORECASE):
        return f"{kind} | No valid selected BSSID"
    tshark = shutil.which("tshark")
    if not tshark:
        return f"{kind} | AP metadata unavailable: tshark not installed"
    try:
        result = subprocess.run(
            [tshark, "-n", "-r", str(path), "-Y", f"wlan.bssid == {bssid.lower()}",
             "-T", "fields", "-E", "occurrence=f", "-e", "frame.number",
             "-e", "wlan.ssid", "-e", "eapol.version"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except subprocess.TimeoutExpired:
        return f"{kind} | Packet inspection timed out"
    except OSError as exc:
        return f"{kind} | Packet inspection failed: {exc}"
    if result.returncode:
        return f"{kind} | Packet inspection failed (exit {result.returncode})"

    frames = result.stdout.splitlines()
    if not frames:
        return f"{kind} | No packets for BSSID {bssid}"
    ssids = set()
    eapol = 0
    for row in frames:
        _, _, fields = row.partition("\t")
        ssid, _, version = fields.partition("\t")
        if ssid:
            try:
                ssids.add(bytes.fromhex(ssid))
            except ValueError:
                return f"{kind} | Could not decode captured SSID metadata"
        eapol += bool(version)
    observed = ", ".join(repr(value.decode("utf-8", errors="backslashreplace"))
                         for value in sorted(ssids)) or "unavailable"
    match = ""
    if expected_ssid is not None:
        if not ssids:
            match = " | Exact SSID match unavailable"
        elif expected_ssid.encode("utf-8") in ssids:
            match = " | Exact SSID match"
        else:
            match = " | SSID mismatch"
    return (f"{kind} | BSSID {bssid} | Captured SSID: {observed}{match}"
            f" | EAPOL packets: {eapol}")
