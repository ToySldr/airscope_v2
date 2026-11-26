"""Offline regression checks for Vault job lifecycle and capture indexing."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from airscope.crack import external
from airscope.models import CaptureType
from airscope.persist.capture_history import load_capture_index
from airscope.ui.screens.vault_item import _CapturePanel


@pytest.mark.asyncio
async def test_cancellation_kills_and_waits_for_child(monkeypatch):
    reading = asyncio.Event()

    async def readline():
        reading.set()
        await asyncio.Future()

    child = SimpleNamespace(
        stdout=SimpleNamespace(readline=readline),
        returncode=None, kill=Mock(), wait=AsyncMock(),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=child))
    task = asyncio.create_task(external.run_crack(["mock-child"], "mock"))
    try:
        await asyncio.wait_for(reading.wait(), timeout=2)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    child.kill.assert_called_once_with()
    child.wait.assert_awaited_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_vault_removes_temporary_input(tmp_path, monkeypatch, cancelled):
    source = tmp_path / "source.cap"
    source.write_text("fixture")
    selected = SimpleNamespace(type=CaptureType.HS, ssid="Fixture", bssid="aa:bb:cc:dd:ee:ff")
    panel = SimpleNamespace(
        _crack_pending=("hashcat", "mock-child", str(source), None, selected),
        _crack_note=Mock(), _crack_worker=object(), _status=SimpleNamespace(exit_code=None),
    )
    outputs = []

    async def simulated_helper(args):
        output = Path(args[args.index("-o") + 1])
        output.write_text("temporary fixture")
        outputs.append(output)
        if cancelled:
            raise asyncio.CancelledError
        return 2, ""

    monkeypatch.setattr(external, "run_capture_output", simulated_helper)
    if cancelled:
        with pytest.raises(asyncio.CancelledError):
            await _CapturePanel._run_crack(panel, "unused")
        panel._crack_note.assert_called_with("Stopped.", "CANCELLED")
    else:
        await _CapturePanel._run_crack(panel, "unused")
        panel._crack_note.assert_called_with("Capture conversion failed (exit 2).")
        assert panel._status.exit_code == 2
    assert len(outputs) == 1
    assert not outputs[0].parent.exists()
    assert source.read_text() == "fixture"
    assert panel._crack_worker is None


def test_stale_key_file_is_never_indexed_as_capture(tmp_path):
    folder = tmp_path / "Example_AABBCCDDEEFF"
    folder.mkdir()
    for name in ("selected.cap", "selected.pcap", ".airscope-aircrack.key"):
        (folder / name).touch()
    captures = load_capture_index()["aa:bb:cc:dd:ee:ff"]
    assert {Path(capture.path).name for capture in captures} == {"selected.cap", "selected.pcap"}
    assert (folder / ".airscope-aircrack.key").is_file()


@pytest.mark.asyncio
async def test_cancellation_after_stdout_eof_kills_child(monkeypatch):
    waiting = asyncio.Event()

    async def wait():
        if not waiting.is_set():
            waiting.set()
            await asyncio.Future()

    child = SimpleNamespace(
        stdout=SimpleNamespace(readline=AsyncMock(return_value=b"")),
        returncode=None, kill=Mock(), wait=wait,
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=child))
    task = asyncio.create_task(external.run_crack(["mock-child"], "mock"))
    await asyncio.wait_for(waiting.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)
    child.kill.assert_called_once_with()
