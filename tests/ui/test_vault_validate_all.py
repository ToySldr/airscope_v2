"""Validate All reports each unique file while retaining every indexed CSV row."""
import asyncio
import csv
from threading import Event

import pytest
from textual.widgets import Button, Label

from airscope.persist.config import Config
from airscope.models import CaptureType, PersistedCapture
from airscope.ui.app import AirscopeApp
from airscope.ui.job_status import VaultJobStatus
from airscope.ui.screens import vault as ui


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_validate_all_counts_files_and_keeps_summary(tmp_path, monkeypatch):
    captures = tmp_path / "captures"
    captures.mkdir()
    monkeypatch.setattr(Config, "captures_dir", str(captures))
    monkeypatch.setattr(ui.VaultView, "_start_inapp_retention", lambda self: None)
    results = ["extractable", "saved_hash_markers", "no_records", "missing", "skipped", "exception"]
    entries = [PersistedCapture(type=CaptureType.HS, timestamp=i, path=str(captures / status),
                                bssid="aa:bb:cc:dd:ee:ff") for i, status in enumerate(results)]
    calls = []
    blocked, release = Event(), Event()

    def inspect(entry):
        status = entry.path.split("/")[-1]
        calls.append(status)
        if status == "saved_hash_markers":
            blocked.set()
            assert release.wait(5)
        if status == "exception":
            raise OSError("fixture")
        return {"status": status}

    monkeypatch.setattr(ui, "inspect_capture", inspect)
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        view = app.screen
        monkeypatch.setattr(app.vault, "all_captures", lambda: [entries[0], *entries])
        job = VaultJobStatus("fixture.cap", "simulator")
        job.update("RUNNING")
        app.vault_job_status = job
        button = view.query_one("#vault-validate-all", Button)
        label = view.query_one("#vault-validation-status", Label)
        button.press()
        try:
            assert await asyncio.to_thread(blocked.wait, 3)
            assert "1/6 files reviewed" in label.content
            assert button.disabled
        finally:
            release.set()
        for _ in range(50):
            await pilot.pause(0.02)
            if not button.disabled:
                break
        assert not button.disabled
        assert calls == results
        message = label.content
        for part in ("6/6 files reviewed", "Checked 5", "Validated 1", "Markers only 1",
                     "Incomplete/no records 1", "Failed 2", "Skipped 1", "CSV saved"):
            assert part in message
        report = max((tmp_path / "exports").glob("airscope_validation_*.csv"))
        with report.open() as stream:
            rows = list(csv.DictReader(stream))
        assert len(rows) == 7
        assert rows[-1]["status"] == "unverified"
        view._retention_status("retention completed")
        assert label.content == message
        app.pop_screen()
        await pilot.pause()
        app.push_screen("vault")
        await pilot.pause()
        label = app.screen.query_one("#vault-validation-status", Label)
        assert label.content == message
        await pilot.press("v")
        assert label.content == "Ready"
        assert app.vault_job_status is job and job.phase == "RUNNING"
