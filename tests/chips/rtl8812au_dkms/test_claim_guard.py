"""RTL8812AU userspace _claim guard: refuse to detach a kernel driver whose USB disconnect is
known to hang this host (88XXau / rtw_dev_remove), failing closed instead of driving a detach no
timeout can interrupt. A clean driver is still detached (behavior preserved). Covers the fix in
chips/rtl8812au_dkms/driver.py."""
import pytest

import airscope.chips.rtl8812au_dkms.driver as drv_mod
from airscope.chips.rtl8812au_dkms.driver import (
    Rtl8812auDkmsDriver, _bound_kernel_driver, _HANG_PRONE_KERNEL_DRIVERS,
)
from airscope.errors import BringUpError


def _build_sysfs(tmp_path, entries):
    """entries: (dirname, busnum, devnum, driver_name_or_None). Mirrors /sys/bus/usb/devices."""
    root = tmp_path / "usbdevs"
    root.mkdir()
    drivers = root / "_drivers"
    drivers.mkdir()
    for name, bus, devnum, driver in entries:
        d = root / name
        intf = d / f"{name}:1.0"
        intf.mkdir(parents=True)
        (d / "busnum").write_text(str(bus))
        (d / "devnum").write_text(str(devnum))
        if driver is not None:
            drvdir = drivers / driver
            drvdir.mkdir(exist_ok=True)
            (intf / "driver").symlink_to(drvdir)
    return root


def test_bound_kernel_driver_reads_name(tmp_path):
    root = _build_sysfs(tmp_path, [("3-2", 3, 2, "rtl88XXau"), ("1-1", 1, 15, "rtl8814au")])
    assert _bound_kernel_driver(3, 2, usb_devices=root) == "rtl88XXau"
    assert _bound_kernel_driver(1, 15, usb_devices=root) == "rtl8814au"


def test_bound_kernel_driver_unbound_is_none(tmp_path):
    root = _build_sysfs(tmp_path, [("3-2", 3, 2, None)])
    assert _bound_kernel_driver(3, 2, usb_devices=root) is None


def test_bound_kernel_driver_absent_is_none(tmp_path):
    root = _build_sysfs(tmp_path, [("3-2", 3, 2, "rtl88XXau")])
    assert _bound_kernel_driver(9, 9, usb_devices=root) is None


def test_hang_prone_set_contains_88xxau():
    assert "rtl88XXau" in _HANG_PRONE_KERNEL_DRIVERS


class _FakeDev:
    def __init__(self, bus, address, *, kernel_active=True):
        self.bus = bus
        self.address = address
        self._kernel_active = kernel_active
        self.detached = False
        self.configured = False

    def is_kernel_driver_active(self, intf):
        return self._kernel_active

    def detach_kernel_driver(self, intf):
        self.detached = True

    def set_configuration(self):
        self.configured = True


class _FakeTransport:
    def __init__(self, dev):
        self.dev = dev


def _driver_with(dev):
    return Rtl8812auDkmsDriver(_FakeTransport(dev))


def test_claim_refuses_hang_prone_driver(monkeypatch):
    dev = _FakeDev(3, 2)
    drv = _driver_with(dev)
    monkeypatch.setattr(drv_mod, "_bound_kernel_driver", lambda bus, address, **k: "rtl88XXau")
    with pytest.raises(BringUpError) as ei:
        drv._claim()
    assert "rtl88XXau" in str(ei.value)
    # the hang-prone detach was NEVER attempted (that is the whole point)
    assert dev.detached is False
    assert dev.configured is False


def test_claim_detaches_clean_driver(monkeypatch):
    dev = _FakeDev(1, 15)
    drv = _driver_with(dev)
    monkeypatch.setattr(drv_mod, "_bound_kernel_driver", lambda bus, address, **k: "rtl8xxxu")
    monkeypatch.setattr(drv_mod.usb.util, "claim_interface", lambda d, n: None)
    drv._claim()
    # a clean (non-hang-prone) driver is still detached -> existing behavior preserved
    assert dev.detached is True
    assert dev.configured is True


def test_claim_no_kernel_driver_skips_detach(monkeypatch):
    dev = _FakeDev(1, 15, kernel_active=False)
    drv = _driver_with(dev)
    # if nothing is bound, neither the guard nor a detach fires (the intended blacklist-first flow)
    monkeypatch.setattr(drv_mod, "_bound_kernel_driver",
                        lambda *a, **k: pytest.fail("must not probe the driver when none is active"))
    monkeypatch.setattr(drv_mod.usb.util, "claim_interface", lambda d, n: None)
    drv._claim()
    assert dev.detached is False
    assert dev.configured is True
