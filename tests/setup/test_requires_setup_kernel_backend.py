"""Regression: a device bound to its EXPECTED kernel driver is VALID for kernel-monitor capture,
so ``SetupLinux.requires_setup`` must NOT route it through the PyUSB detach preflight or the
"Selected adapter is owned by the kernel" rejection.

Guards the dual-adapter launch failure where both Alfa cards were reported "owned by Linux kernel
drivers" and refused: the kernel-monitor backend captures *through* the bound driver, so kernel
ownership is correct, not a setup trigger. On pristine HEAD (``return kernel_driver_bound(...)``)
the first test below fails -- it is a true regression guard."""
import sys

import pytest

import airscope.device.manager as manager
import airscope.setup.usb_handover as usb_handover
import airscope.setup.linux as linux_setup
from airscope.models import DeviceID

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="SetupLinux is Linux-only"
)

_8812 = DeviceID(vid=0x0BDA, pid=0x8812, chipset="RTL8812AU")
_8813 = DeviceID(vid=0x0BDA, pid=0x8813, chipset="RTL8814AU")


@pytest.fixture
def setup():
    return linux_setup.SetupLinux()


@pytest.mark.parametrize("dev", [_8812, _8813], ids=["8812", "8813"])
def test_kernel_backend_adapter_needs_no_setup(setup, dev, monkeypatch):
    """The kernel-monitor backend owns this VID:PID -> requires_setup returns False WITHOUT ever
    consulting the detach/legacy path. If the fix regressed and it fell through, the sentinel
    kernel_driver_bound would fail the test instead of returning cleanly."""
    monkeypatch.setattr(manager, "kernel_backend_selected", lambda vid, pid: True)
    monkeypatch.setattr(
        linux_setup, "kernel_driver_bound",
        lambda ids: pytest.fail("regressed: fell through to kernel_driver_bound"),
    )
    assert setup.requires_setup(dev) is False


def test_pyusb_opt_out_falls_through_to_legacy_gate(setup, monkeypatch):
    """With the guarded PyUSB backend chosen (kernel_backend_selected False), the exemption does not
    apply: the legacy "is a kernel driver bound?" gate still decides -- it is preserved, not removed."""
    monkeypatch.setattr(manager, "kernel_backend_selected", lambda vid, pid: False)
    monkeypatch.setattr(usb_handover, "opt_in", lambda dev: False)
    sentinel = object()
    monkeypatch.setattr(linux_setup, "kernel_driver_bound", lambda ids: sentinel)
    assert setup.requires_setup(_8812) is sentinel


def test_non_backend_device_uses_legacy_gate(setup, monkeypatch):
    """A device outside the kernel-backend set is unaffected and defers to the legacy gate."""
    monkeypatch.setattr(manager, "kernel_backend_selected", lambda vid, pid: False)
    monkeypatch.setattr(usb_handover, "opt_in", lambda dev: False)
    monkeypatch.setattr(linux_setup, "kernel_driver_bound", lambda ids: True)
    other = DeviceID(vid=0x1234, pid=0x5678, chipset="OTHER")
    assert setup.requires_setup(other) is True


def test_real_default_backend_exempts_validated_alfas(setup, monkeypatch):
    """End-to-end with the REAL kernel_backend_selected (not monkeypatched): on Linux, default
    backend, no PyUSB opt-out -> both validated Alfas are exempt from setup."""
    monkeypatch.delenv("AIRSCOPE_CAPTURE", raising=False)
    monkeypatch.setattr(
        linux_setup, "kernel_driver_bound",
        lambda ids: pytest.fail("real default should have exempted before the legacy gate"),
    )
    assert setup.requires_setup(_8812) is False
    assert setup.requires_setup(_8813) is False
