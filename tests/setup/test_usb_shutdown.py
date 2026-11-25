"""USB-safety regression (v0.3.9).

Adapted from the original PR #2 (``review/v039-usb-safety``) to the current
``usb_handover`` API: the raw lock file descriptor was replaced by the
``UsbClaim`` dataclass, and ``restore_claimed_8814`` now takes that claim.

These cover the *opt-in* handover path that ``tests/test_no_auto_detach.py``
deliberately does not: the ordered adapter shutdown in ``action_quit``, claiming
ONLY interface 0 of the selected 0bda:8813, and refusing to rebind any device
whose USB identity does not match the recorded claim. Mocked only -- no live USB,
no real detach or rebind.
"""
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
    """action_quit closes adapters, then releases cards, then restores interfaces, then
    exits -- and a failed adapter close aborts the quit (re-arming it) rather than exiting
    mid-teardown."""
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
        # a failed close must abort the quit and re-arm it, never proceed to exit
        assert events == ["close"]
        assert not instance._quitting
        instance.array.close = AsyncMock()
        await app.AirscopeApp.action_quit(instance)
    await app.AirscopeApp.action_quit(instance)  # idempotent once _quitting latches
    assert events == ["close", "release", "restore", "exit"]


def test_handover_claims_only_interface_zero(monkeypatch):
    """The opt-in claim detaches and claims ONLY interface 0 of the selected device,
    and never resets it."""
    dev = Mock(idVendor=0x0BDA, idProduct=0x8813, bus=1, address=3)
    dev.is_kernel_driver_active.return_value = True
    monkeypatch.setattr(usb_handover, "opt_in", lambda selected: True)
    monkeypatch.setattr(usb_handover, "preflight_8814", lambda selected: (True, "idle"))
    # Bypass the sysfs snapshot; this test is about the claim surface, not device discovery
    # (discovery/identity is covered by test_restore_verifies_exact_usb_identity + preflight tests).
    sentinel = usb_handover.UsbClaim(
        fd=51, interface=Path("/sys/bus/usb/devices/1-3:1.0"),
        driver="rtl8814au", bus=1, address=3)
    monkeypatch.setattr(usb_handover, "_snapshot", lambda d, fd: sentinel)

    claim_interface = Mock()
    with monkeypatch.context() as patch:
        patch.setattr(usb_handover.os, "open", Mock(return_value=51))
        patch.setattr(usb_handover.fcntl, "flock", Mock())
        patch.setattr("usb.util.claim_interface", claim_interface)
        result = usb_handover.claim_opted_in_8814(dev)

    assert result is sentinel and result.fd == 51
    dev.detach_kernel_driver.assert_called_once_with(0)
    claim_interface.assert_called_once_with(dev, 0)
    dev.reset.assert_not_called()


def test_restore_verifies_exact_usb_identity(tmp_path, monkeypatch):
    """restore rebinds the recorded driver only when the live device's VID:PID + bus/address
    match the claim; any mismatch (wrong address, non-original driver, no claim) is refused."""
    monkeypatch.setattr(usb_handover.os, "geteuid", lambda: 0)
    base = tmp_path.resolve()  # resolve first so symlink comparison is stable regardless of /tmp
    devices = base / "devices"
    drivers = base / "drivers"
    root = devices / "1-3"
    root.mkdir(parents=True)
    for key, value in {"idVendor": "0bda", "idProduct": "8813",
                       "busnum": "1", "devnum": "3"}.items():
        (root / key).write_text(value)
    # the USB interface dir lives INSIDE its device root, so interface.parent == root
    interface = root / "1-3:1.0"
    interface.mkdir()
    rtl = drivers / "rtl8814au"
    rtl.mkdir(parents=True)
    (interface / "driver").symlink_to(rtl)  # simulate the device already bound to its driver
    monkeypatch.setattr(usb_handover, "USB_DRIVERS", drivers)

    claim = usb_handover.UsbClaim(fd=51, interface=interface, driver="rtl8814au", bus=1, address=3)
    dev = SimpleNamespace(idVendor=0x0BDA, idProduct=0x8813, bus=1, address=3)
    assert usb_handover.restore_claimed_8814(dev, claim) is True

    # exact-identity guard: a different USB address is a different device -> refuse
    dev.address = 4
    assert usb_handover.restore_claimed_8814(dev, claim) is False
    # a non-original recorded driver -> refuse
    bad = usb_handover.UsbClaim(fd=51, interface=interface, driver="not-a-real-driver",
                                bus=1, address=3)
    matched = SimpleNamespace(idVendor=0x0BDA, idProduct=0x8813, bus=1, address=3)
    assert usb_handover.restore_claimed_8814(matched, bad) is False
    # no claim -> refuse
    assert usb_handover.restore_claimed_8814(matched, None) is False
