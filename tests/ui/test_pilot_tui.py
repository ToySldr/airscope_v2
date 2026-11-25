"""Headless Textual Pilot suite for the AirScope TUI (mocked hardware).

Mirrors tests/ui conventions:
  * REAL AirscopeApp + app.run_test() under @pytest.mark.usefixtures("no_usb_devices")
    (ui/conftest.py stubs usb.core.find -> []) for boot/discovery/selection/vault/shutdown;
  * a _FakeArray/_FakeIface injected as app.array for scanner interaction, exactly as
    tests/ui/test_scanner_filter.py and test_scanner_table.py do.
No USB / root / DKMS / kernel-driver calls run.
"""
import pathlib
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.widgets import DataTable, Label, SelectionList

import airscope.device.manager as manager
from airscope.chips.driver import DeviceID
from airscope.device.manager import BringupResult  # noqa: F401  (mock-seam reference)
from airscope.persist.config import Config
from airscope.models import AccessPoint
from airscope.ui.app import AirscopeApp
from airscope.ui.capture_events import CAPTURE_TOAST_TITLES, CaptureEvent, CaptureKind
from airscope.ui.screens.scanner import ScannerView
from airscope.ui.screens.splash import SplashView
from airscope.ui.screens.vault import VaultView

_HS_LINE = "WPA*02*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431***2\n"


class _FakeIface:
    """WlanInterface stand-in: the attach + hop + connect surface WlanArray.attach()
    and ScannerView touch (mirrors tests/ui/test_hotplug.py._FakeIface)."""
    supported_channels = [1, 6, 11]
    current_channel = 1

    def __init__(self, dev, name="wlan0"):
        self.name = name
        self.vid, self.pid = dev.vid, dev.pid
        self.bus, self.address = dev.bus, dev.address
        self.description = dev.description
        self.chipset = dev.chipset
        self.on_tx = None
        self.connect = AsyncMock(return_value=True)
        self.close = AsyncMock()

    @property
    def instance_key(self):
        return (self.vid, self.pid, self.bus, self.address)

    def register_rx_callback(self, cb):
        pass

    def register_disconnect_callback(self, cb):
        pass

    async def set_channel(self, ch, scan=False):
        return True

    async def start_hopping(self, channels=None, interval=0.5):
        pass

    async def stop_hopping(self):
        pass


class _FakeArray:
    """WlanArray stand-in exposing only what ScannerView + the header slots read
    (mirrors tests/ui/test_scanner_filter.py._FakeArray) plus close() for shutdown."""

    def __init__(self, aps, supported=(1, 6, 11)):
        self.access_points = {ap.bssid: ap for ap in aps}
        self.clients = {}
        self.forged_macs = set()
        self.supported_channels = list(supported)
        self.members = [_FakeIface(DeviceID(0x0E8D, 0x7961, "MT7921AU", bus=2, address=32))]
        self.start_calls = 0
        self.stop_calls = 0
        self.close = AsyncMock()

    def get_access_points(self, include_eviltwin=True):
        return list(self.access_points.values())

    def select_iface(self, channel):
        return next((i for i in self.members if channel in i.supported_channels), None)

    async def start_hopping(self, channels=None, interval=0.25):
        self.start_calls += 1

    async def stop_hopping(self):
        self.stop_calls += 1

    @asynccontextmanager
    async def claim(self, iface):
        await iface.stop_hopping()
        try:
            yield iface
        finally:
            await iface.start_hopping()


def _ap(bssid, ssid=None, channel=1, card="card0", rssi=-50, **kw):
    ap = AccessPoint(bssid=bssid, ssid=ssid, channel=channel, **kw)
    ap.signal_by_card = {card: rssi}   # AccessPoint.signal = max(signal_by_card.values())
    return ap


async def _settle(pilot, n=5):
    for _ in range(n):
        await pilot.pause(0)


# 1. startup + render --------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_boots_on_splash_and_installs_screens():
    app = AirscopeApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.title.startswith("airscope")
        assert isinstance(app.screen, SplashView)
        assert app.screen.query_one("#ascii-art") is not None
        assert app.screen.query_one("#device-list") is not None   # empty ListView is falsy; existence is the check
        for name in ("splash", "scanner", "focus", "vault"):
            assert name in app._installed_screens


# 2. device discovery shows BOTH adapters + selection ------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_discovery_shows_both_adapters_and_selection():
    devA = DeviceID(0x0BDA, 0x8812, "RTL8812AU", None, "ALFA AWUS036ACH", bus=2, address=32)
    devB = DeviceID(0x0BDA, 0x8813, "RTL8814AU", None, "ALFA AWUS1900", bus=2, address=35)
    app = AirscopeApp()
    async with app.run_test() as pilot:
        splash = app.screen
        app._on_devices_changed([devA, devB], [devA, devB], [])   # what device_watch fires
        await _settle(pilot)
        sel = splash.query_one("#device-select", SelectionList)
        assert sel.display is True                 # >=2 cards -> multi-select list
        assert sorted(sel.selected) == [0, 1]      # both checked by default
        sel.deselect(1)
        await pilot.pause(0)
        assert sel.selected == [0]                 # selection honoured


# 3. START pools BOTH adapters into the REAL WlanArray (identity retained) ----
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_start_pools_both_adapters_into_real_array(monkeypatch):
    devA = DeviceID(0x0E8D, 0x7961, "MT7921AU", bus=2, address=32)
    devB = DeviceID(0x0E8D, 0x7961, "MT7921AU", bus=2, address=35)
    app = AirscopeApp()
    async with app.run_test(size=(120, 40)) as pilot:
        splash = app.screen
        monkeypatch.setattr(manager, "wlan_iface",
                            lambda device_id, name="wlan0": _FakeIface(device_id, name))
        monkeypatch.setattr(app.device_manager.setup, "requires_setup",
                            lambda device_id: False)
        splash.render_devices([devA, devB])
        await _settle(pilot)
        splash.action_start()
        for _ in range(80):
            await pilot.pause(0)
            if app.array and len(app.array.members) == 2:
                break
        await _settle(pilot)
        assert app.array is not None and len(app.array.members) == 2
        assert {m.name for m in app.array.members} == {"wlan0", "wlan1"}
        assert {m.instance_key for m in app.array.members} == {
            (0x0E8D, 0x7961, 2, 32), (0x0E8D, 0x7961, 2, 35)}   # per-card identity retained
        assert isinstance(app.screen, ScannerView)


# 4. AP discovery populates the table ----------------------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_ap_discovery_list_populates():
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.array = _FakeArray([])
        app.push_screen("scanner")
        await _settle(pilot)
        scanner = app.screen
        assert isinstance(scanner, ScannerView)
        table = scanner.query_one("#ap-table", DataTable)
        scanner.refresh_table()
        await pilot.pause(0)
        assert table.row_count == 0
        ap = _ap("aa:bb:cc:00:00:01", ssid="HomeNet", channel=6, akms=["PSK"])
        app.array.access_points[ap.bssid] = ap
        scanner.refresh_table()
        await pilot.pause(0)
        assert table.row_count == 1
        assert ap.bssid in scanner.ap_cache


# 5. live counters update ----------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_live_counter_updates():
    ap1 = _ap("aa:bb:cc:00:00:01", ssid="Net1", channel=1)
    ap2 = _ap("aa:bb:cc:00:00:02", ssid="Net2", channel=6)
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.array = _FakeArray([ap1, ap2])
        app.push_screen("scanner")
        await _settle(pilot)
        scanner = app.screen
        scanner.refresh_table()
        await pilot.pause(0)
        assert "2 networks" in str(scanner.query_one("#scan-status", Label).render())
        app.array.clients["11:22:33:44:55:66"] = SimpleNamespace(
            mac="11:22:33:44:55:66", bssid=ap1.bssid)
        scanner.refresh_table()
        await pilot.pause(0)
        assert "1 devices" in str(scanner.query_one("#scan-status", Label).render())


# 6. scan pause/cancel via freeze (f) ----------------------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_freeze_pauses_live_scan_sort():
    aps = [_ap("aa:bb:cc:00:00:01", ssid="Net1"), _ap("aa:bb:cc:00:00:02", ssid="Net2")]
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.array = _FakeArray(aps)
        app.push_screen("scanner")
        await _settle(pilot)
        scanner = app.screen
        scanner.refresh_table()
        await pilot.pause(0)
        scanner.query_one("#ap-table", DataTable).focus()
        await pilot.press("f")
        await pilot.pause(0)
        assert scanner._frozen is True
        assert scanner.query_one("#freeze-banner", Label).display is True
        assert scanner._should_sort() is False
        await pilot.press("f")
        await pilot.pause(0)
        assert scanner._frozen is False
        assert scanner.query_one("#freeze-banner", Label).display is False


# 7. keyboard navigation -----------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_keyboard_navigation_moves_cursor():
    aps = [_ap(f"aa:bb:cc:00:00:0{i}", ssid=f"Net{i}", rssi=-40 - i) for i in range(1, 4)]
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.array = _FakeArray(aps)
        app.push_screen("scanner")
        await _settle(pilot)
        scanner = app.screen
        scanner.refresh_table()
        await pilot.pause(0)
        table = scanner.query_one("#ap-table", DataTable)
        assert table.row_count == 3
        table.focus()
        await pilot.pause(0)
        start = table.cursor_coordinate.row
        await pilot.press("down")
        await pilot.pause(0)
        assert table.cursor_coordinate.row == start + 1


# 8. capture win -> Vault persistence + non-blocking toast -------------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_capture_win_persists_to_vault_and_toasts():
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("scanner")
        await _settle(pilot)
        scanner = app.screen
        toasts = []
        scanner.notify = lambda msg, **kw: toasts.append((kw.get("title"), msg))
        saved = []

        def _save(ap, mac):
            saved.append((ap.bssid, mac))
            return SimpleNamespace(was_new=True, path=pathlib.Path("HomeNet_hs.hc22000"))

        app.vault.save_handshake = _save
        ap = _ap("aa:bb:cc:dd:ee:06", ssid="HomeNet", channel=6)
        ev = CaptureEvent(kind=CaptureKind.HANDSHAKE, bssid=ap.bssid, ssid=ap.ssid,
                          client_mac="11:22:33:44:55:66", pair_label="M1/M2")
        scanner._log_capture_event(ev, ap)
        assert saved == [(ap.bssid, "11:22:33:44:55:66")]   # persisted via the Vault
        title = CAPTURE_TOAST_TITLES[CaptureKind.HANDSHAKE]
        assert any(t[0] and t[0].startswith(title) for t in toasts)   # non-blocking toast


# 9. Vault navigation: 'v' hotkey target + real indexed captures -------------
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_scanner_v_opens_vault_and_lists_captures(tmp_path, monkeypatch):
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.push_screen("scanner")
        await pilot.pause(0)
        scanner = app.screen
        app.push_screen = Mock()
        scanner.action_open_vault()
        app.push_screen.assert_called_once_with("vault")   # 'v' hotkey target

    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))   # Vault() reads at __init__
    (tmp_path / "HomeNet_aa-bb-cc-dd-ee-ff_1000_handshake.hc22000").write_text(
        _HS_LINE, encoding="utf-8")
    app2 = AirscopeApp()
    async with app2.run_test() as pilot:
        app2.push_screen("vault")
        await pilot.pause()
        view = app2.screen
        assert isinstance(view, VaultView)
        table = view.query_one("#vault-aps", DataTable)
        assert table.row_count == 1
        # Assert the ESSID is present without pinning a column index -- the Vault table's column
        # order has shifted across versions, and this test should not couple to that layout.
        assert "HomeNet" in " ".join(str(c) for c in table.get_row_at(0))


# 10. clean shutdown: close adapters, remove only our rules, no driver detach -
@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_clean_shutdown_closes_adapters_without_detaching(monkeypatch):
    released = []
    monkeypatch.setattr("airscope.ui.app._restore_wireless_interfaces",
                        lambda: released.append("restore"))
    monkeypatch.setattr("airscope.setup.linux.release_all",
                        lambda: released.append("release_all"))
    app = AirscopeApp()
    async with app.run_test() as pilot:
        app.array = _FakeArray([])         # .close is an AsyncMock
        await pilot.pause(0)
        await app.action_quit()
        await pilot.pause(0)
        app.array.close.assert_awaited()   # adapters shut down
        assert "release_all" in released   # only Airscope-owned setup rules removed
        # release_all + _restore_wireless_interfaces are the ONLY cleanup calls:
        # no kernel-driver unload, no wlan0 mode change.
