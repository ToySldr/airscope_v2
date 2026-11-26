"""Selected validation uses a snapshot of checked networks and preserves results."""
import asyncio
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest
from textual.widgets import Button, DataTable

from airscope.ui.app import AirscopeApp
from airscope.ui.screens import vault as ui


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_select_clear_review_and_cancel(tmp_path, monkeypatch):
    for n in range(3):
        (tmp_path / f"Demo{n}_aa-bb-cc-dd-ee-0{n}_100_handshake.pcap").touch()
    monkeypatch.setattr(ui.VaultView, "_start_inapp_retention", lambda self: None)
    entered, release = Event(), Event()
    calls = []

    def inspect(capture):
        calls.append(capture.bssid)
        entered.set()
        assert release.wait(5)
        return "No extractable handshake data"

    monkeypatch.setattr(ui, "inspect_selected_file", inspect)
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("vault")
        await pilot.pause()
        screen = app.screen
        table = screen.query_one(DataTable)
        screen.query_one("#select-networks", Button).press()
        await pilot.pause()
        assert len(screen._checked) == 3
        screen.query_one("#clear-networks", Button).press()
        await pilot.pause()
        assert not screen._checked
        table.focus()
        await pilot.press("space", "down", "space")
        assert screen._checked == {"aa:bb:cc:dd:ee:00", "aa:bb:cc:dd:ee:01"}
        assert screen._selected_bssid.endswith("01")
        assert screen.query_one(".crack", Button)
        screen._render_selected()
        screen.query_one("#validate-selected", Button).press()
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            screen.query_one("#cancel-selected", Button).press()
            await pilot.pause()
        finally:
            release.set()
        await pilot.pause(0.4)
        assert calls == ["aa:bb:cc:dd:ee:00"]
        assert "Cancelled | 1/2" in screen.query_one("#selected-results").content
        app.pop_screen()
        await pilot.pause()
        app.push_screen("vault")
        await pilot.pause()
        assert "No extractable handshake data" in app.screen.query_one("#selected-results").content


@pytest.mark.asyncio
async def test_validation_continues_after_error(monkeypatch):
    inspect = Mock(side_effect=[OSError("fixture"), "No extractable handshake data"])
    monkeypatch.setattr(ui, "inspect_selected_file", inspect)
    batch = ui.SelectedValidation(2)
    await batch.run([("First", Mock(path="one.cap")), ("Second", Mock(path="two.pcapng"))])
    assert batch.state == "Complete"
    assert "Validation error" in batch.results[0]
    assert "No extractable handshake data" in batch.results[1]


@pytest.mark.parametrize("filename,data,expected", [
    ("a.cap", b"bad", "truncated"),
    ("a.pcapng", b"", "truncated"),
    ("a.hc22000", b"ordinary text", "No WPA record markers"),
    ("a.pcap", None, "Missing capture"),
])
def test_inspection_failures(tmp_path, filename, data, expected):
    path = tmp_path / filename
    if data is not None:
        path.write_bytes(data)
    assert expected in ui.inspect_selected_file(Mock(path=path, bssid="aa:bb:cc:dd:ee:ff"))


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_mouse_selection_refresh_and_batch_snapshot(tmp_path, monkeypatch):
    addresses = [f"aa:bb:cc:dd:ee:0{n}" for n in range(5)]
    for n, addr in enumerate(addresses):
        kind = "handshake.pcap" if n != 4 else "wps_pin.txt"
        (tmp_path / f"Shared_{addr.replace(':', '-')}_100_{kind}").touch()
    monkeypatch.setattr(ui.VaultView, "_start_inapp_retention", lambda self: None)
    calls = []
    def inspect(capture):
        calls.append(capture.bssid)
        return "simulated"
    monkeypatch.setattr(ui, "inspect_selected_file", inspect)
    app = AirscopeApp()
    async with app.run_test(size=(130, 45)) as pilot:
        app.push_screen("vault")
        await pilot.pause()
        screen = app.screen
        table = screen.query_one(DataTable)
        original = screen._selected_bssid
        for n in (1, 2, 3):
            await pilot.click(table, offset=(2 * n, n + 2))
            assert screen._selected_bssid == original
            assert str(table.get_cell(addresses[n], "checked")) == "[x]"
        assert screen._checked == set(addresses[1:4])
        assert not screen.query_one("#validate-selected", Button).disabled
        await pilot.click(table, offset=(9, 6))
        assert screen._selected_bssid == addresses[4]
        screen._reload_table()
        await pilot.pause()
        assert screen._checked == set(addresses[1:4])
        await pilot.click("#validate-selected")
        await pilot.pause(0.3)
        assert calls == addresses[1:4]
        app.pop_screen()
        await pilot.pause()
        app.push_screen("vault")
        await pilot.pause()
        screen = app.screen
        table = screen.query_one(DataTable)
        assert [str(table.get_cell(key, "checked")) for key in addresses] == [
            "[ ]", "[x]", "[x]", "[x]", "[ ]"]
        await pilot.click("#select-networks")
        assert screen._checked == set(addresses[:4])
        await pilot.click("#clear-networks")
        assert not screen._checked
        assert screen.query_one("#validate-selected", Button).disabled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_results_table_fits_after_terminal_resize(tmp_path, monkeypatch):
    long_name = "LongNetworkName" * 5
    for n in range(24):
        stem = f"{long_name}{n}_aa-bb-cc-dd-ee-{n:02x}"
        (tmp_path / f"{stem}_100_handshake.pcap").touch()
        if n == 0:
            (tmp_path / f"{stem}_101_cracked.txt").write_text(
                f"SSID: {long_name}{n}\nPSK: fixture-only\n")
    monkeypatch.setattr(ui.VaultView, "_start_inapp_retention", lambda self: None)
    app = AirscopeApp()
    async with app.run_test(size=(100, 42)) as pilot:
        app.push_screen("vault")
        await pilot.pause()
        screen = app.screen
        table = screen.query_one(ui.NetworkTable)
        for width in (100, 120, 160, 100):
            await pilot.resize_terminal(width, 42)
            await pilot.pause()
            assert abs(table.region.width - screen.query_one("#vault-body").content_size.width * .55) <= 1
            assert table.virtual_size.width <= table.scrollable_content_region.width
            assert not table.show_horizontal_scrollbar
            header = table.render_line(0).text
            row = table.render_line(1).text
            assert "ESSID" in header and "HS" in header and "PW" in header
            assert "[ ]" in row and chr(8230) in row and "(RECOVERED)" in row
            assert next(table.get_column("checked")).cell_len == 3
            for selector in ("#vault-validate-all", "#validate-selected", "#cancel-selected",
                             ".crack", ".validate", ".copy-payload", ".actions .delete"):
                button = screen.query_one(selector, Button)
                assert button.region.width >= len(str(button.label))
                assert button.region.right <= width
                assert button.region.x >= 0
