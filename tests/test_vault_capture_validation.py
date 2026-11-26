"""Regression checks for passive capture validation and Vault selection."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from airscope.persist import capture_validation as validation
from airscope.persist.capture_history import load_capture_index
from airscope.ui.screens import vault_item

BSSID = "aa:bb:cc:dd:ee:ff"
SSID = "HomeNet 5G"
PCAP = bytes.fromhex("d4c3b2a1") + bytes(20)
PCAPNG = bytes.fromhex("0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000")


@pytest.mark.parametrize("suffix, header, kind", [
    (".cap", PCAP, "pcap"), (".pcap", PCAP, "pcap"), (".PCAPNG", PCAPNG, "pcapng"),
])
def test_packet_validation_uses_exact_wire_ssid(tmp_path, monkeypatch, suffix, header, kind):
    source = tmp_path / ("HomeNet_5G" + suffix)
    source.write_bytes(header)
    fields = f"1\t{SSID.encode().hex()}\t\n2\t\t2\n"
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=fields))
    monkeypatch.setattr(validation.shutil, "which", lambda name: name)
    monkeypatch.setattr(validation.subprocess, "run", run)
    result = validation.validate_selected_capture(source, BSSID, SSID)
    assert result.startswith(kind + " |")
    assert "Exact SSID match" in result
    assert repr(SSID) in result
    assert result.endswith("EAPOL packets: 1")
    assert "SSID mismatch" in validation.validate_selected_capture(source, BSSID, "HomeNet_5G")
    assert f"wlan.bssid == {BSSID}" in run.call_args.args[0]
    assert source.read_bytes() == header


def test_truncated_capture_and_saved_hash_markers(tmp_path, monkeypatch):
    run = Mock()
    monkeypatch.setattr(validation.subprocess, "run", run)
    capture = tmp_path / "broken.cap"
    capture.write_bytes(PCAP[:4])
    assert "truncated" in validation.validate_selected_capture(capture, BSSID)
    records = tmp_path / "saved.hc22000"
    records.write_text("WPA*02*fixture\n")
    assert "EAPOL 1" in validation.validate_selected_capture(records, BSSID)
    run.assert_not_called()


def test_packet_tool_failure_is_reported(tmp_path, monkeypatch):
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(PCAP)
    monkeypatch.setattr(validation.shutil, "which", lambda name: name)
    monkeypatch.setattr(validation.subprocess, "run", Mock(return_value=SimpleNamespace(returncode=2)))
    assert validation.validate_selected_capture(capture, BSSID) == "pcap | Packet inspection failed (exit 2)"


@pytest.mark.asyncio
async def test_old_validation_cannot_replace_selected_file_status(monkeypatch):
    started, finished = asyncio.Event(), asyncio.Event()

    async def inspect(function, path, bssid):
        assert path == Path("first.cap")
        assert bssid == BSSID
        started.set()
        await finished.wait()
        return "old result"

    monkeypatch.setattr(vault_item.asyncio, "to_thread", inspect)
    panel = SimpleNamespace(_validation_request=1, query_one=Mock())
    selected = SimpleNamespace(path="first.cap", bssid=BSSID)
    job = asyncio.create_task(vault_item._CapturePanel._validate_selected(panel, selected, 1))
    await asyncio.wait_for(started.wait(), timeout=2)
    panel._validation_request = 2
    finished.set()
    await asyncio.wait_for(job, timeout=2)
    panel.query_one.assert_not_called()


def test_vault_ignores_internal_artifacts(tmp_path):
    folder = tmp_path / "HomeNet_5G_AABBCCDDEEFF"
    folder.mkdir()
    for name in ("actual.cap", ".airscope-aircrack.key", ".airscope-crack-job.hc22000"):
        (folder / name).touch()
    internal = folder / ".airscope-job"
    internal.mkdir()
    (internal / "scratch.pcap").touch()
    assert [Path(item.path).name for item in load_capture_index()[BSSID]] == ["actual.cap"]


@pytest.mark.parametrize("suffix", [".cap", ".PCAP", ".pcapng"])
def test_binary_capture_payload_is_not_copied_as_text(tmp_path, suffix):
    from airscope.persist.vault import Vault

    path = tmp_path / ("payload" + suffix)
    path.write_bytes(PCAP)
    capture = SimpleNamespace(path=str(path), value=None)
    assert Vault().capture_payload(capture) == ""


@pytest.mark.parametrize("contents, diagnostic", [
    (PCAP, "expected UTF-8 text"),
    (b"header\x00", "unexpected binary data"),
    (b"ordinary text\n", "No WPA record markers"),
])
def test_invalid_saved_records_report_failure(tmp_path, contents, diagnostic):
    path = tmp_path / "invalid.hc22000"
    path.write_bytes(contents)
    assert diagnostic in validation.validate_selected_capture(path, BSSID)
