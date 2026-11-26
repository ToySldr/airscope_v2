"""Release gate (v0.3.9, items 1-2): the default kernel-monitor capture path NEVER auto-detaches a
kernel driver or falls back into the PyUSB backend. Every driver-detaching path is reachable ONLY
behind an explicit opt-in env flag (AIRSCOPE_CAPTURE=pyusb, or AIRSCOPE_8814_USB_HANDOVER=1 for the
legacy RTL8814AU handover) and otherwise fails closed. Mocked only -- no live USB, no real detach.
"""
import inspect
import sys
from pathlib import Path

import pytest

import airscope
import airscope.device.manager as manager
import airscope.setup.usb_handover as usb_handover
from airscope.chips.kernel_capture import KernelMonitorDriver
from airscope.errors import BringUpError

_LINUX = sys.platform.startswith("linux")
_IDS = [(0x0BDA, 0x8812), (0x0BDA, 0x8813)]
_linux_only = pytest.mark.skipif(not _LINUX, reason="kernel-monitor backend is Linux-only")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No capture-backend or handover override unless a test sets one explicitly."""
    monkeypatch.delenv("AIRSCOPE_CAPTURE", raising=False)
    monkeypatch.delenv("AIRSCOPE_8814_USB_HANDOVER", raising=False)


# --- item 1: normal startup selects the kernel backend, never the PyUSB (detach) driver ----------
@_linux_only
@pytest.mark.parametrize("vid,pid", _IDS, ids=["8812", "8813"])
def test_default_startup_selects_kernel_backend(vid, pid):
    assert manager.kernel_backend_selected(vid, pid) is True
    cls, key = manager.driver_for(vid, pid)
    assert cls is KernelMonitorDriver
    assert key == "kernel-monitor"


@_linux_only
@pytest.mark.parametrize("vid,pid", _IDS, ids=["8812", "8813"])
def test_explicit_kernel_env_also_selects_kernel(monkeypatch, vid, pid):
    monkeypatch.setenv("AIRSCOPE_CAPTURE", "kernel")
    assert manager.kernel_backend_selected(vid, pid) is True
    assert manager.driver_for(vid, pid)[0] is KernelMonitorDriver


# --- item 1/2: the detach-capable PyUSB driver is reachable ONLY via the explicit opt-in ---------
@_linux_only
@pytest.mark.parametrize("vid,pid", _IDS, ids=["8812", "8813"])
def test_pyusb_backend_requires_explicit_optin(monkeypatch, vid, pid):
    assert manager.driver_for(vid, pid)[0] is KernelMonitorDriver            # default = kernel
    monkeypatch.setenv("AIRSCOPE_CAPTURE", "pyusb")
    assert manager.kernel_backend_selected(vid, pid) is False
    cls, _ = manager.driver_for(vid, pid)
    assert cls is not None and cls is not KernelMonitorDriver                # a userspace PyUSB driver


def test_backend_choice_takes_no_failure_input():
    """kernel_backend_selected depends ONLY on (vid, pid) + env -- it takes no exception/failure
    argument, so a kernel-backend failure at runtime cannot flip the choice to PyUSB."""
    assert list(inspect.signature(manager.kernel_backend_selected).parameters) == ["vid", "pid"]


def test_kernel_selection_never_resolves_a_pyusb_driver(monkeypatch):
    """When the kernel backend is selected, driver_for returns KernelMonitorDriver WITHOUT ever
    consulting the PyUSB driver catalog -- there is no fall-through to a userspace detach driver."""
    monkeypatch.setattr(manager, "kernel_backend_selected", lambda v, p: True)
    monkeypatch.setattr(
        manager, "supported_ids",
        lambda: pytest.fail("kernel-backend path must not resolve a PyUSB driver"))
    cls, key = manager.driver_for(0x0BDA, 0x8813)
    assert cls is KernelMonitorDriver and key == "kernel-monitor"


# --- item 1/2: the legacy RTL8814AU handover fails closed without its explicit flag --------------
class _FakeDev8813:
    idVendor, idProduct = 0x0BDA, 0x8813

    def __init__(self, bus=3, address=4, kernel_active=True):
        self.bus, self.address = bus, address
        self._active = kernel_active
        self.detach_calls = 0

    def is_kernel_driver_active(self, intf):
        return self._active

    def detach_kernel_driver(self, intf):
        self.detach_calls += 1  # must never run on the fail-closed path


@_linux_only
def test_handover_without_flag_fails_closed_and_never_detaches():
    dev = _FakeDev8813(kernel_active=True)
    with pytest.raises(BringUpError) as ei:
        usb_handover.claim_opted_in_8814(dev)
    assert "AIRSCOPE_8814_USB_HANDOVER" in str(ei.value)
    assert dev.detach_calls == 0


def test_opt_in_and_preflight_are_false_without_flag():
    class _Id:
        vid, pid, bus, address = 0x0BDA, 0x8813, 3, 4
    assert usb_handover.opt_in(_Id) is False
    ok, reason = usb_handover.preflight_8814(_Id)
    assert ok is False and "not explicitly enabled" in reason


def test_handover_detach_is_not_wired_into_any_capture_path():
    """claim_opted_in_8814 -- the only USB-interface detach in the legacy handover -- is DEFINED but
    has no caller in the package: the unverified handover is not wired into any capture/bring-up path
    in v0.3.9. If a future change wires it, this guard fails and forces a deliberate review."""
    pkg = Path(airscope.__file__).parent
    offenders = []
    for py in pkg.rglob("*.py"):
        if py.name == "usb_handover.py" or "__pycache__" in py.parts:
            continue
        if "claim_opted_in_8814" in py.read_text(encoding="utf-8", errors="replace"):
            offenders.append(str(py.relative_to(pkg)))
    assert offenders == [], f"claim_opted_in_8814 referenced outside usb_handover.py: {offenders}"
