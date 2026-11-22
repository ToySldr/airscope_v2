import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from airscope.setup import usb_handover
from airscope.ui import app

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux USB handover")


@pytest.mark.asyncio
@pytest.mark.parametrize("close_fails", [False, True])
async def test_shutdown_order_and_failure_recovery(monkeypatch, close_fails):
    events = []

    async def close():
        events.append("close")
        if close_fails:
            raise RuntimeError("mock adapter busy")

    instance = SimpleNamespace(
        _quitting=False, array=SimpleNamespace(close=close), notify=Mock(),
        persist_config=Mock(), exit=lambda: events.append("exit"),
    )
    monkeypatch.setattr("airscope.setup.linux.release_all", lambda: events.append("release"))
    monkeypatch.setattr(app, "_restore_wireless_interfaces", lambda: events.append("restore"))
    await app.AirscopeApp.action_quit(instance)
    if close_fails:
        assert events == ["close"]
        assert not instance._quitting
        instance.array.close = AsyncMock()
        await app.AirscopeApp.action_quit(instance)
    await app.AirscopeApp.action_quit(instance)
    assert events == ["close", "release", "restore", "exit"]


def test_handover_claims_only_interface_zero(monkeypatch):
    dev = Mock(idVendor=0x0bda, idProduct=0x8813, bus=1, address=3)
    dev.is_kernel_driver_active.return_value = True
    monkeypatch.setattr(usb_handover, "opt_in", lambda selected: True)
    monkeypatch.setattr(usb_handover, "preflight_8814", lambda selected: (True, "idle"))
    claim = Mock()
    with monkeypatch.context() as patch:
        patch.setattr(usb_handover.os, "open", Mock(return_value=51))
        patch.setattr(usb_handover.fcntl, "flock", Mock())
        patch.setattr("usb.util.claim_interface", claim)
        assert usb_handover.claim_opted_in_8814(dev) == 51
    dev.detach_kernel_driver.assert_called_once_with(0)
    claim.assert_called_once_with(dev, 0)
    dev.reset.assert_not_called()


def test_restore_uses_exact_usb_identity(tmp_path, monkeypatch):
    devices = tmp_path / "devices"
    driver = tmp_path / "rtl8814au"
    driver.mkdir()
    node = devices / "1-3"
    node.mkdir(parents=True)
    for key, value in {"idVendor": "0bda", "idProduct": "8813", "busnum": "1", "devnum": "3"}.items():
        (node / key).write_text(value)
    interface = devices / "1-3:1.0"
    interface.mkdir()
    (interface / "driver").symlink_to(driver)
    monkeypatch.setattr(usb_handover, "Path",
                        lambda path: devices if path == "/sys/bus/usb/devices" else Path(path))
    monkeypatch.setattr(usb_handover.os, "geteuid", lambda: 0)
    dev = SimpleNamespace(idVendor=0x0bda, idProduct=0x8813, bus=1, address=3)
    assert usb_handover.restore_claimed_8814(dev, 51)
    dev.address = 4
    assert not usb_handover.restore_claimed_8814(dev, 51)
