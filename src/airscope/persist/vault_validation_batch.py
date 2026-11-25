"""Classify Airscope capture files for read-only Vault batch reports.

Status extractable means a converter emitted an EAPOL/PMKID WPA record.
Status saved_hash_markers means an existing text file has WPA format markers.
Neither proves MIC validity or a known password; no cracking is performed.
"""
from __future__ import annotations

from pathlib import Path
import re

from airscope.persist.capture_validation import validate_capture

_SUPPORTED = {".pcap", ".pcapng", ".cap", ".hc22000", ".22000"}
_COUNTS = re.compile(r"(?:Extracted|Saved hash records): EAPOL (\d+), PMKID (\d+), other WPA (\d+)")
_PACKETS = re.compile(r"EAPOL packets: (\d+)")


def inspect_capture(capture) -> dict[str, str | int]:
    path = Path(capture.path)
    blank = {
        "size_bytes": 0,
        "status": "unverified",
        "eapol_packets": "",
        "eapol_records": 0,
        "pmkid_records": 0,
        "other_wpa_records": 0,
        "details": "",
    }
    if path.suffix.lower() not in _SUPPORTED:
        return {**blank, "status": "skipped", "details": "Not a WPA packet/hash file"}
    if not path.is_file():
        return {**blank, "status": "missing", "details": "Indexed file missing"}
    try:
        size = path.stat().st_size
        message = validate_capture(path)
    except Exception as exc:
        return {**blank, "status": "unverified", "details": f"{type(exc).__name__}: {exc}"}

    match = _COUNTS.search(message)
    packet_match = _PACKETS.search(message)
    eapol, pmkid, other = (map(int, match.groups()) if match else (0, 0, 0))
    status = "unverified"
    if match:
        if "Saved hash records:" in message:
            status = "saved_hash_markers" if eapol + pmkid + other else "no_records"
        elif "extractor exit: 0" in message:
            status = "extractable" if eapol + pmkid + other else "no_records"
    return {
        "size_bytes": size,
        "status": status,
        "eapol_packets": int(packet_match.group(1)) if packet_match else "",
        "eapol_records": eapol,
        "pmkid_records": pmkid,
        "other_wpa_records": other,
        "details": message,
    }
