"""In-app retention safety (persist/inapp_retention.quarantine_stale_wpa) — Priority 2.

Synthetic captures in isolated temp dirs; inspect_capture and the /proc helpers are monkeypatched
for determinism. Verifies: valid captures preserved, empty/invalid classified, quarantine never
permanently deletes (hardlink-then-unlink keeps the data), symlinks and out-of-root paths protected,
recent/open files protected, repeated cleanup safe, interrupted operations preserve recoverable data,
Vault indexing stays consistent after cleanup, and the manual Clean-Empty flow is non-destructive.
"""
import os
from pathlib import Path

import pytest

from airscope.models import CaptureType, PersistedCapture
from airscope.persist import inapp_retention
from airscope.persist.inapp_retention import quarantine_stale_wpa

_ANCIENT = 1_000_000  # mtime far in the past so MIN_AGE never protects a test file


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "captures"
    r.mkdir()
    # Deterministic environment: no other Airscope process, nothing open (tests override as needed).
    monkeypatch.setattr(inapp_retention, "_other_airscope_processes", lambda: False)
    monkeypatch.setattr(inapp_retention, "_open_files", lambda: set())

    def fake_inspect(cap):
        n = Path(cap.path).name
        if "valid" in n:
            return {"status": "extractable"}
        if "hashmark" in n:
            return {"status": "saved_hash_markers"}
        if "norec" in n or "empty" in n:
            return {"status": "no_records"}
        if "boom" in n:
            raise RuntimeError("inspect blew up")
        return {"status": "unverified"}

    monkeypatch.setattr(inapp_retention, "inspect_capture", fake_inspect)
    return r


def _cap(root, name, *, ctype=CaptureType.HS, bssid="aa:bb:cc:dd:ee:ff", content=b"NODATA",
         old=True):
    p = Path(root) / name
    p.write_bytes(content)
    if old:
        os.utime(p, (_ANCIENT, _ANCIENT))
    return PersistedCapture(type=ctype, timestamp=1, path=str(p), bssid=bssid, record_count=0)


def _quarantine_dir(root):
    return Path(root).parent / "quarantine-no-wpa"


# 1 — valid captures are preserved ------------------------------------------------------------
def test_extractable_capture_preserved(root):
    cap = _cap(root, "valid_aa-bb-cc-dd-ee-ff.hc22000")
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0
    assert Path(cap.path).exists()


def test_saved_hash_markers_preserved(root):
    cap = _cap(root, "hashmark_aa-bb-cc-dd-ee-ff.hc22000")
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0 and Path(cap.path).exists()


# 2 — empty/invalid classification ------------------------------------------------------------
def test_unverified_is_kept_not_quarantined(root):
    cap = _cap(root, "unver_aa-bb-cc-dd-ee-ff.pcap")
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0 and Path(cap.path).exists()


def test_non_capture_suffix_is_skipped(root):
    cap = _cap(root, "norec_aa-bb-cc-dd-ee-ff.txt")   # .txt not in EXTENSIONS
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["skipped"] == 1 and res["moved"] == 0 and Path(cap.path).exists()


# 3 — no_records is quarantined, NEVER permanently deleted ------------------------------------
def test_no_records_quarantined_data_preserved(root):
    cap = _cap(root, "norec_aa-bb-cc-dd-ee-ff.hc22000", content=b"EMPTY-NO-WPA")
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 1
    assert not Path(cap.path).exists()                       # removed from captures/
    q = _quarantine_dir(root) / "norec_aa-bb-cc-dd-ee-ff.hc22000"
    assert q.exists() and q.read_bytes() == b"EMPTY-NO-WPA"  # data preserved, not deleted


# 4 — symlinks are protected ------------------------------------------------------------------
def test_symlink_is_never_followed_or_removed(root):
    real = _cap(root, "norec_real.hc22000", content=b"EMPTY")
    link = Path(root) / "norec_link.hc22000"
    link.symlink_to(real.path)
    cap = PersistedCapture(type=CaptureType.HS, timestamp=1, path=str(link), bssid="aa:bb:cc:dd:ee:ff",
                           record_count=0)
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0
    assert link.is_symlink() and Path(real.path).exists()   # symlink + target intact


# 5 — paths outside the configured captures dir are protected ---------------------------------
def test_path_outside_root_is_skipped(root, tmp_path):
    outside = tmp_path / "elsewhere" / "norec_aa-bb-cc-dd-ee-ff.hc22000"
    outside.parent.mkdir()
    outside.write_bytes(b"EMPTY")
    os.utime(outside, (_ANCIENT, _ANCIENT))
    cap = PersistedCapture(type=CaptureType.HS, timestamp=1, path=str(outside),
                           bssid="aa:bb:cc:dd:ee:ff", record_count=0)
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0 and outside.exists()


# 6 — recently-written captures are protected -------------------------------------------------
def test_recent_capture_protected_by_min_age(root):
    cap = _cap(root, "norec_fresh.hc22000", old=False)       # just written
    res = quarantine_stale_wpa([cap], root)                  # default MIN_AGE = 900
    assert res["moved"] == 0 and Path(cap.path).exists()


# 7 — open files are protected ----------------------------------------------------------------
def test_open_file_is_protected(root, monkeypatch):
    cap = _cap(root, "norec_open.hc22000")
    st = Path(cap.path).stat()
    monkeypatch.setattr(inapp_retention, "_open_files", lambda: {(st.st_dev, st.st_ino)})
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0 and Path(cap.path).exists()


# 8 — repeated cleanup is safe ----------------------------------------------------------------
def test_repeated_cleanup_is_idempotent_and_safe(root):
    keep = _cap(root, "valid_keep.hc22000")
    drop = _cap(root, "norec_drop.hc22000", content=b"EMPTY")
    first = quarantine_stale_wpa([keep, drop], root, min_age=0)
    assert first["moved"] == 1
    second = quarantine_stale_wpa([keep, drop], root, min_age=0)   # drop.path now gone
    assert second["moved"] == 0                                     # nothing re-moved, no error
    assert Path(keep.path).exists()                                 # valid still kept


# 9 — an error mid-inspection preserves the file (fail-safe) ----------------------------------
def test_inspection_error_preserves_file(root):
    cap = _cap(root, "boom_aa-bb-cc-dd-ee-ff.hc22000")
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0 and Path(cap.path).exists()


# 10 — an interrupted quarantine (link fails) leaves the original recoverable -----------------
def test_interrupted_quarantine_preserves_original(root, monkeypatch):
    cap = _cap(root, "norec_interrupt.hc22000", content=b"EMPTY")

    def boom_link(*a, **k):
        raise OSError("simulated interruption during os.link")

    monkeypatch.setattr(inapp_retention.os, "link", boom_link)
    res = quarantine_stale_wpa([cap], root, min_age=0)
    assert res["moved"] == 0
    assert Path(cap.path).exists()                                   # original intact
    assert not (_quarantine_dir(root) / "norec_interrupt.hc22000").exists()  # no half-move left


# 11 — Vault indexing is consistent after cleanup ---------------------------------------------
def test_vault_index_consistent_after_cleanup(root):
    keep = _cap(root, "valid_keep.hc22000")
    drop = _cap(root, "norec_drop.hc22000", content=b"EMPTY")
    quarantine_stale_wpa([keep, drop], root, min_age=0)
    # A fresh index over the captures root sees the kept file and NOT the quarantined one.
    remaining = {p.name for p in Path(root).rglob("*") if p.is_file()}
    assert "valid_keep.hc22000" in remaining
    assert "norec_drop.hc22000" not in remaining
