"""In-app post-capture retention; only quarantines confidently negative WPA captures.

No hard deletion. Refuses files outside Config.captures_dir and files modified recently
or open by any process. Existing hash markers and inconclusive results remain untouched.
Called from a Textual background worker, never from the packet-capture loop.
"""
from __future__ import annotations

import csv
from datetime import datetime
import os
from pathlib import Path
import time

from airscope.persist.vault_validation_batch import inspect_capture

EXTENSIONS = {".pcap", ".pcapng", ".cap", ".hc22000", ".22000"}
MIN_AGE = 900  # Never quarantine a capture written within the last 15 minutes.


def _other_airscope_processes():
    """Refuse cleanup if another live Airscope process is present."""
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            argv = [x.decode("utf-8", "replace") for x in
                    (proc / "cmdline").read_bytes().split(b"\0") if x]
        except OSError:
            continue
        if (any(arg == "/usr/local/bin/airscope" or
                arg.endswith("/.venv/bin/airscope") for arg in argv) or
                (argv and Path(argv[0]).name == "airscope")):
            return True
    return False


def _open_files():
    """Get inode identities of open files, including in-progress capture files."""
    opened = set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        fd_dir = proc / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                st = fd.stat()
                opened.add((st.st_dev, st.st_ino))
            except OSError:
                continue
    return opened


def _safe_relative(path: Path, root: Path):
    if path.is_symlink() or not path.is_file():
        return None
    try:
        rel = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return rel if rel.parts else None


def quarantine_stale_wpa(captures, capture_root: Path, *, min_age=MIN_AGE):
    """Return a summary dict; never delete anything and never modify useful hashes.

    This function is designed to be run in asyncio.to_thread() from VaultView.
    Caller must refresh the Vault index and UI on completion.
    """
    root = Path(capture_root).resolve(strict=True)
    quarantine = root.parent / "quarantine-no-wpa"
    exports = root.parent / "exports"
    if quarantine.resolve() == root or root in quarantine.resolve().parents:
        raise ValueError("Quarantine location must be outside captures directory")
    if _other_airscope_processes():
        return {"checked": 0, "moved": 0, "skipped": 0,
                "message": "Another Airscope process is running; cleanup skipped", "report": ""}

    grouped = {}
    for capture in captures:
        grouped.setdefault(str(capture.path), []).append(capture)

    checked = moved = skipped = 0
    rows = []
    opened = _open_files()
    for name, items in sorted(grouped.items()):
        path = Path(name)
        rel = _safe_relative(path, root)
        if rel is None:
            skipped += 1
            continue
        try:
            original = path.stat()
        except OSError:
            skipped += 1
            continue
        types = {getattr(c.type, "value", str(c.type)).lower() for c in items}
        if (types - {"hs", "pmkid"} or
                path.suffix.casefold() not in EXTENSIONS or
                time.time() - original.st_mtime < min_age or
                (original.st_dev, original.st_ino) in opened):
            skipped += 1
            continue

        checked += 1
        status = "unverified"
        outcome = "KEEP"
        destination = ""
        try:
            result = inspect_capture(items[0])
            status = str(result.get("status", "unverified"))
            if status == "no_records":
                # A second independent extraction prevents decisions on transient errors.
                recheck = inspect_capture(items[0])
                current = path.stat()
                fresh = (current.st_dev == original.st_dev and
                         current.st_ino == original.st_ino and
                         current.st_size == original.st_size and
                         current.st_mtime_ns == original.st_mtime_ns)
                # Skip if a capture writer opened the file during validation.
                if (recheck.get("status") == "no_records" and fresh and
                        time.time() - current.st_mtime >= min_age and
                        (current.st_dev, current.st_ino) not in _open_files() and
                        not _other_airscope_processes() and
                        _safe_relative(path, root) == rel):
                    dst = quarantine / rel
                    if dst.exists() or dst.is_symlink():
                        outcome = "SKIP: quarantine path exists"
                    else:
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        # Hard-link creation is atomic and refuses an existing destination.
                        # Both directories share a filesystem in this custom setup.
                        os.link(path, dst, follow_symlinks=False)
                        try:
                            linked = dst.stat()
                            source = path.stat()
                            if ((linked.st_dev, linked.st_ino) !=
                                    (original.st_dev, original.st_ino) or
                                    (source.st_dev, source.st_ino) !=
                                    (original.st_dev, original.st_ino)):
                                raise OSError("Source changed while quarantining")
                            path.unlink()
                        except Exception:
                            dst.unlink(missing_ok=True)
                            raise
                        destination = str(dst)
                        moved += 1
                        outcome = "QUARANTINED"
                else:
                    outcome = "SKIP: file changed or revalidation disagreed"
            elif status in ("extractable", "saved_hash_markers"):
                outcome = "KEEP: WPA record"
            else:
                outcome = "KEEP: unsupported, missing, or unverified"
        except Exception as exc:
            outcome = f"KEEP: error {type(exc).__name__}: {exc}"
        rows.append({
            "file_path": name, "bssids": ",".join(sorted({c.bssid for c in items})),
            "size_bytes": original.st_size, "validation_status": status,
            "decision": outcome, "destination": destination,
        })

    report_path = ""
    # Write a CSV audit report only when something was quarantined or an inspection errored.
    if moved or any(r["decision"].startswith("KEEP: error") for r in rows):
        exports.mkdir(parents=True, exist_ok=True)
        report = exports / ("airscope_inapp_retention_" +
                            datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".csv")
        with report.open("x", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "file_path", "bssids", "size_bytes", "validation_status",
                "decision", "destination"])
            writer.writeheader()
            writer.writerows(rows)
        report_path = str(report)
    return {"checked": checked, "moved": moved, "skipped": skipped,
            "report": report_path, "message": ""}
