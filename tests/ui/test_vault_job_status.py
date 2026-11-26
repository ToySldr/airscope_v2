"""Vault job reporting across Textual screen reconstruction."""
import pytest
from textual.widgets import Label
from airscope.ui.app import AirscopeApp
from airscope.ui.job_status import VaultJobStatus


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize("phase", ["COMPLETED", "CANCELLED", "FAILED", "NO MATCH", "RECOVERED", "FAILED TO SAVE"])
async def test_terminal_status_survives_screen_refresh(tmp_path, phase):
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        job = VaultJobStatus("capture.cap", "simulator")
        app.vault_job_status = job
        for state in ("QUEUED", "CONVERTING", "RUNNING", phase):
            job.update(state, "fixture")
            app.screen._render_job_status()
            assert state in str(app.screen.query_one("#vault-job-status", Label).content)
        assert job.ended is not None
        message = job.display()
        app.screen._reload_table()
        await pilot.pause()
        assert app.screen.query_one("#vault-job-status", Label).content == message
        app.screen.action_dismiss_job_status()
        assert app.vault_job_status is None
        assert app.screen.query_one("#vault-status-panel").visible
        assert app.screen.query_one("#vault-job-status").content == "IDLE - No active cracking job."


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_saved_identity_refreshes_list_and_survives_reopen(tmp_path):
    from textual.widgets import DataTable
    from airscope.persist.vault import Vault
    from airscope.models import CaptureType

    address = "aa:bb:cc:dd:ee:ff"
    (tmp_path / "Fixture_Net_aa-bb-cc-dd-ee-ff_100_handshake.pcap").touch()
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        screen = app.screen
        status = VaultJobStatus("capture.pcap", "simulator")
        app.vault_job_status = status
        saved = app.vault.save_cracked_psk(address, "Fixture Net", "dummy-only", "simulator")
        assert saved is not None
        status.update("RECOVERED", "Saved and verified in Vault.")
        screen._render_job_status()
        await pilot.pause()
        row = screen.query_one(DataTable).get_row_at(0)
        assert str(row[1]) == "Fixture Net  (RECOVERED)"
        assert row[3] == "1"
        panel = screen.query_one("#vault-status-panel")
        assert panel.region.y >= screen.query_one("#vault-body").region.bottom
        assert panel.border_title == "Cracking Status"
        indexed = Vault().persisted(address)
        assert any(c.type == CaptureType.CRACKED and c.ssid == "Fixture Net" for c in indexed)
        app.pop_screen()
        await pilot.pause()
        app.push_screen("vault")
        await pilot.pause()
        assert app.screen.query_one(DataTable).get_row_at(0) == row
        assert app.screen.query_one("#vault-job-status").content == status.display()
        await pilot.press("d")
        assert app.vault_job_status is None
        assert app.screen.query_one("#vault-status-panel").visible
        assert app.screen.query_one("#vault-job-status").content == "IDLE - No active cracking job."


def test_save_requires_readback(monkeypatch, tmp_path):
    from airscope.persist.vault import Vault
    from airscope.persist import save
    vault = Vault()
    monkeypatch.setattr(save, "save_cracked_psk",
                        lambda *args: save.SaveResult(path=tmp_path / "absent", was_new=True))
    assert vault.save_cracked_psk("aa:bb:cc:dd:ee:ff", "Fixture Net", "dummy-only", "simulator") is None

@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_password_disclosure_and_idle_after_restart(tmp_path, monkeypatch):
    from unittest.mock import Mock
    from textual.widgets import Button, DataTable

    for suffix in ("01", "02"):
        path = tmp_path / f"Example{suffix}_aa-bb-cc-dd-ee-{suffix}_100_cracked.txt"
        path.write_text(f"SSID: Example{suffix}\nPSK: dummy{suffix}\n")

    app = AirscopeApp()
    copy = Mock()
    monkeypatch.setattr(app, "copy_to_clipboard", copy)
    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        view = app.screen

        def field():
            return str(view.query_one(".fval-psk", Label).content)

        async def press(selector):
            view.query_one(selector, Button).press()
            await pilot.pause()

        assert view.query_one("#vault-job-status").content == "IDLE - No active cracking job."
        assert "********" in field()
        await press(".copy-psk")
        copy.assert_called_once_with("dummy01")
        await press(".toggle-password")
        assert "dummy01" in field()
        await press(".toggle-password")
        assert "********" in field()
        await press(".toggle-password")
        view.query_one(DataTable).move_cursor(row=1)
        await pilot.pause()
        assert "********" in field()
        await press(".toggle-password")
        assert "dummy02" in field()
        app.pop_screen()
        await pilot.pause()
        app.push_screen("vault")
        await pilot.pause()
        view = app.screen
        assert "********" in field()
