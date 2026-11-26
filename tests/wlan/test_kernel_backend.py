"""Kernel-monitor backend selection + wiring. The kernel backend is the DEFAULT for 0bda:8812 /
0bda:8813 (live-validated 2026-11-23: both captured through the app on the kernel backend, no USB
detach). These prove each adapter resolves to KernelMonitorDriver and skips the setup gate, and that
the original "owned by the kernel" rejection is now reachable only under AIRSCOPE_CAPTURE=pyusb.
Covers device/manager.py (kernel_backend_selected / driver_for / resolve_driver) and
setup/linux.py (requires_setup)."""
import pytest

import airscope.device.manager as mgr
from airscope.chips.kernel_capture import KernelMonitorDriver
from airscope.models.device_id import DeviceID

_8812 = (0x0bda, 0x8812)
_8813 = (0x0bda, 0x8813)


@pytest.fixture(autouse=True)
def _clear_capture_env(monkeypatch):
    monkeypatch.delenv("AIRSCOPE_CAPTURE", raising=False)


# --- selection ---------------------------------------------------------------
def test_kernel_backend_is_default():
    assert mgr.kernel_backend_selected(*_8812)
    assert mgr.kernel_backend_selected(*_8813)


def test_pyusb_env_opts_out(monkeypatch):
    monkeypatch.setenv("AIRSCOPE_CAPTURE", "pyusb")
    assert not mgr.kernel_backend_selected(*_8812)
    assert not mgr.kernel_backend_selected(*_8813)


def test_not_for_other_adapters():
    assert not mgr.kernel_backend_selected(0x2357, 0x0137)   # a MediaTek id, not ours


# --- driver resolution -------------------------------------------------------
def test_driver_for_default_is_kernel_backend():
    for vid, pid in (_8812, _8813):
        cls, key = mgr.driver_for(vid, pid)
        assert cls is KernelMonitorDriver and key == "kernel-monitor"


def test_resolve_driver_default_is_kernel_backend():
    cls, key = mgr.resolve_driver(0x0bda, 0x8813, dev=None)   # the kernel path ignores dev
    assert cls is KernelMonitorDriver and key == "kernel-monitor"


def test_pyusb_env_resolves_userspace_driver(monkeypatch):
    monkeypatch.setenv("AIRSCOPE_CAPTURE", "pyusb")
    cls, _ = mgr.driver_for(*_8812)
    assert cls is not KernelMonitorDriver   # falls back to the PyUSB chip registry


# --- the regression: "owned by the kernel" rejection, and its bypass ---------
def test_requires_setup_false_by_default_for_kernel_backend():
    # default is the kernel backend -> kernel ownership is CORRECT -> no setup, no rejection
    from airscope.setup.linux import SetupLinux
    setup = SetupLinux()
    assert setup.requires_setup(DeviceID(*_8812, "RTL8812AU", bus=3, address=2)) is False
    assert setup.requires_setup(DeviceID(*_8813, "RTL8814AU", bus=1, address=2)) is False


def test_requires_setup_rejection_path_only_under_pyusb(monkeypatch):
    # The ORIGINAL failure ("Selected adapter is owned by the kernel") is now reachable ONLY when the
    # operator explicitly opts out to the PyUSB backend, which needs the detach setup.
    monkeypatch.setenv("AIRSCOPE_CAPTURE", "pyusb")
    import airscope.setup.linux as lin
    from airscope.setup.linux import SetupLinux
    monkeypatch.setattr(lin, "kernel_driver_bound", lambda ids: True)
    assert SetupLinux().requires_setup(DeviceID(*_8812, "RTL8812AU", bus=3, address=2)) is True


# --- dual-adapter: independent receiver instances ----------------------------
def test_dual_adapter_independent_driver_instances(monkeypatch):
    import airscope.chips.kernel_capture as kc
    monkeypatch.setattr(kc, "netdev_for",
                        lambda bus, address, **k: {(1, 2): "wlanA", (3, 2): "wlanB"}.get((bus, address)))

    class _Dev:
        def __init__(self, bus, addr):
            self.bus, self.address = bus, addr

    d1 = KernelMonitorDriver.from_usb_device(_Dev(1, 2), DeviceID(*_8813, "RTL8814AU"))
    d2 = KernelMonitorDriver.from_usb_device(_Dev(3, 2), DeviceID(*_8812, "RTL8812AU"))
    # distinct instances, distinct netdevs, independent (unopened) sockets/readers
    assert d1 is not d2
    assert (d1._netdev, d2._netdev) == ("wlanA", "wlanB")
    assert d1._sock is None and d2._sock is None
    assert d1._reader is None and d2._reader is None
