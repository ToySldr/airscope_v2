"""Exercise Vault modal resume with a harmless background job."""

import asyncio
import logging
from types import SimpleNamespace

import pytest
from textual.widgets import Button, Input
from textual.worker import WorkerState
from textual.worker_manager import WorkerManager

from airscope.ui.app import AirscopeApp
from airscope.ui.screens import vault_item


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_modal_resume_and_table_refresh_preserve_worker(tmp_path, monkeypatch, caplog):
    (tmp_path / "Example_aa-bb-cc-dd-ee-ff_1000_handshake.pcap").touch()
    input_file = tmp_path / "fixture.txt"
    input_file.touch()
    started, finish = asyncio.Event(), asyncio.Event()
    lifecycle = []

    async def simulated_job(panel, value):
        lifecycle.append("started")
        started.set()
        try:
            await finish.wait()
        except asyncio.CancelledError:
            lifecycle.append("cancelled")
            raise
        lifecycle.append("completed")

    original_cancel_node = WorkerManager.cancel_node

    def track_cancel_node(manager, node):
        workers = original_cancel_node(manager, node)
        if isinstance(node, vault_item._CapturePanel) and workers:
            lifecycle.append("panel unmount cancelled worker")
        return workers

    monkeypatch.setattr(WorkerManager, "cancel_node", track_cancel_node)
    monkeypatch.setattr(vault_item._CapturePanel, "_run_crack", simulated_job)
    monkeypatch.setattr(vault_item.crack_ext, "detect_tools",
                        lambda: SimpleNamespace(hashcat="simulated", aircrack=None))
    monkeypatch.setattr(vault_item.crack_ext, "find_wordlist", lambda: None)
    app = AirscopeApp()
    caplog.set_level(logging.DEBUG, logger="airscope.vault.crack")

    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        view = app.screen
        monkeypatch.setattr(view, "_start_inapp_retention", lambda: None)
        panel = view.query_one(vault_item._CapturePanel)
        panel.query_one(".crack", Button).press()
        await pilot.pause()
        modal = app.screen
        modal.query_one("#crack-wordlist", Input).value = str(input_file)
        modal.query_one("#crack-start", Button).press()
        await asyncio.wait_for(started.wait(), timeout=2)
        await pilot.pause()
        assert lifecycle == ["started"]
        assert view.query_one(vault_item._CapturePanel) is panel
        job = panel._crack_worker

        panel._crack_modal_closed(str(input_file))
        assert panel._crack_worker is job
        view._reload_table()
        await pilot.pause()
        assert view.query_one(vault_item._CapturePanel) is panel
        assert job.is_running
        finish.set()
        await asyncio.wait_for(job.wait(), timeout=2)
        assert job.state is WorkerState.SUCCESS
        assert lifecycle == ["started", "completed"]
        assert not any("cancel requested" in record.message for record in caplog.records)
