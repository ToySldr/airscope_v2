"""Conservative, opt-in PyUSB handover for *only* 0bda:8813 on this Pi.

This is NOT a module unload. It is a USB-interface detach, which can still
hang in a buggy kernel driver. Never detach a connected interface or AP.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import subprocess
import sys

from airscope.errors import BringUpError

VID_PID = (0x0bda, 0x8813)  # RTL8814AU; resolved to its live netdev by VID:PID, never a fixed name
FLAG = "AIRSCOPE_8814_USB_HANDOVER"
_LOCK = "/run/lock/airscope-rtl8814au-usb.lock"


def opt_in(device_id) -> bool:
    return (sys.platform.startswith("linux")
            and os.geteuid() == 0
            and os.environ.get(FLAG) == "1"
            and (device_id.vid, device_id.pid) == VID_PID)


def _run(*args: str) -> tuple[bool, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
        return p.returncode == 0, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


# sysfs roots, indirected so tests can point them at a synthetic tree.
_USB_DEVICES = Path("/sys/bus/usb/devices")
_NET_CLASS = Path("/sys/class/net")


def _usb_root(bus: int, addr: int) -> tuple[Path | None, str]:
    """The single USB device dir for VID_PID at (bus, addr); ``(root, "")`` or ``(None, reason)``."""
    roots = []
    try:
        for d in _USB_DEVICES.iterdir():
            if not (d / "idVendor").exists():
                continue
            try:
                ident = (int((d / "idVendor").read_text().strip(), 16),
                         int((d / "idProduct").read_text().strip(), 16),
                         int((d / "busnum").read_text().strip()),
                         int((d / "devnum").read_text().strip()))
            except (OSError, ValueError):
                continue
            if ident == (*VID_PID, bus, addr):
                roots.append(d.resolve())
    except OSError:
        return None, "Cannot inspect USB sysfs"
    if len(roots) != 1:
        return None, f"Expected exactly one selected RTL8814AU USB device; found {len(roots)}"
    return roots[0], ""


def _netdevs_under(root: Path) -> tuple[list[str] | None, str]:
    """Kernel netdev names whose ``/sys/class/net/<name>/device`` resolves under ``root``."""
    names = []
    try:
        for iface in _NET_CLASS.iterdir():
            try:
                d = (iface / "device").resolve()
            except OSError:
                continue
            if d == root or root in d.parents:
                names.append(iface.name)
    except OSError:
        return None, "Cannot inspect network-interface ownership"
    return names, ""


def selected_netdev(bus: int, addr: int) -> tuple[str | None, str]:
    """The kernel netdev name for the selected 0bda:8813 instance, resolved from VID:PID + the
    (bus, address) Airscope picked -- never a hardcoded wlanN. ``(name, "")`` or ``(None, reason)``;
    fails closed on 0 or >1 USB matches, 0 or >1 owning netdevs, or any sysfs read error."""
    root, reason = _usb_root(bus, addr)
    if root is None:
        return None, reason
    names, reason = _netdevs_under(root)
    if names is None:
        return None, reason
    if len(names) != 1:
        return None, (f"Protected adapter selection: expected exactly one netdev for the "
                      f"selected RTL8814AU (0bda:8813), found {names!r}")
    return names[0], ""


def preflight_8814(device_id) -> tuple[bool, str]:
    """Fail closed unless the selected USB instance owns exactly one idle netdev safe to hand over.

    Resolves the kernel interface name from the device's VID:PID + (bus, address) -- never a
    hardcoded wlanN -- then requires it in managed mode and not associated (iw), not carrying the
    default route (not a management path), and idle in NetworkManager. For NM, BOTH 'disconnected'
    and 'unmanaged' count as idle: an unmanaged device is one NM does not control, so it holds no
    active connection -- that is safe, not unsafe. Matches the bus/dev address from Airscope's
    selected DeviceID, not the first arbitrary USB device with that VID:PID.
    """
    if not opt_in(device_id):
        return False, "Direct USB handover not explicitly enabled for RTL8814AU/root"
    bus = getattr(device_id, "bus", None)
    addr = getattr(device_id, "address", None)
    if bus is None or addr is None:
        return False, "Missing USB bus/address; refusing ambiguous adapter selection"

    netdev, reason = selected_netdev(bus, addr)
    if netdev is None:
        return False, reason

    ok, info = _run('iw', 'dev', netdev, 'info')
    if not ok or not re.search(r'(?m)^\s*type\s+managed\s*$', info):
        return False, f"{netdev} is not confirmed managed mode (AP or monitor modes forbidden)"
    ok, link = _run('iw', 'dev', netdev, 'link')
    if not ok or 'Not connected.' not in link:
        return False, f"{netdev} is connected or wireless link status is unknown"
    # Never hand over a device that carries the default route -- that is a management path and
    # detaching it would cut connectivity. A benign local-subnet route does not block handover.
    ok, droute = _run('ip', 'route', 'show', 'default', 'dev', netdev)
    if ok and droute.strip():
        return False, f"{netdev} carries the default route; it is a management path, not idle"
    # NetworkManager state: 'disconnected' (managed + idle) AND 'unmanaged' (NM does not control
    # the device) are both SAFE -- neither holds an active connection, and the iw checks above
    # already confirmed managed mode + no association. Only reject when it is actively in use
    # (connected / connecting) or unusable (unavailable). 'unmanaged' is not unsafe.
    ok, nm = _run('nmcli', '-g', 'GENERAL.STATE', 'device', 'show', netdev)
    if not ok:
        return False, f"NetworkManager state for {netdev} is unknown: {nm!r}"
    nm_state = nm.lower()
    if 'disconnected' not in nm_state and 'unmanaged' not in nm_state:
        return False, f"NetworkManager reports {netdev} in use ({nm.strip()!r}); not safe to hand over"
    return True, f"Only {netdev} (0bda:8813) is idle ({nm.strip()}); other interfaces untouched"


ORIGINAL_DRIVERS = ("rtl8814au", "rtl88XXau")
USB_DRIVERS = Path("/sys/bus/usb/drivers")


@dataclass(frozen=True)
class UsbClaim:
    fd: int
    interface: Path
    driver: str
    bus: int
    address: int


def _identity(root):
    return (int((root / "idVendor").read_text(), 16), int((root / "idProduct").read_text(), 16),
            int((root / "busnum").read_text()), int((root / "devnum").read_text()))


def _snapshot(dev, fd):
    netdev, reason = selected_netdev(dev.bus, dev.address)
    if netdev is None:
        raise BringUpError("claim", f"Cannot resolve the RTL8814AU interface: {reason}")
    interface = (_NET_CLASS / netdev / "device").resolve(strict=True)
    root = interface.parent
    driver = (interface / "driver").resolve(strict=True)
    if (interface.name != root.name + ":1.0"
            or _identity(root) != (*VID_PID, dev.bus, dev.address)
            or driver.name not in ORIGINAL_DRIVERS or driver != USB_DRIVERS / driver.name):
        raise BringUpError("claim", f"Cannot verify the original {netdev} USB interface and driver")
    return UsbClaim(fd, interface, driver.name, dev.bus, dev.address)


def claim_opted_in_8814(dev) -> UsbClaim | None:
    """Take a process-wide lock and claim just interface 0 of 0bda:8813."""
    import usb.core
    import usb.util

    if not sys.platform.startswith('linux'):
        return None
    if (dev.idVendor, dev.idProduct) != VID_PID:
        return None

    class Selected:
        vid, pid = VID_PID
        bus, address = dev.bus, dev.address

    if not opt_in(Selected):
        # The previous device-manager setup gate normally blocks this path.
        # If it is already unbound, retain the existing non-detach behavior.
        try:
            if not dev.is_kernel_driver_active(0):
                return None
        except (usb.core.USBError, NotImplementedError) as exc:
            raise BringUpError('claim', f'Cannot check kernel driver: {exc}') from exc
        raise BringUpError('claim', 'Set AIRSCOPE_8814_USB_HANDOVER=1 to try guarded RTL8814AU handover')

    fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BringUpError('claim', 'Another Airscope RTL8814AU handover is active') from exc

        allowed, reason = preflight_8814(Selected)
        if not allowed:
            raise BringUpError('claim', reason)

        claim = _snapshot(dev, fd)
        try:
            dev.get_active_configuration()  # never reset the AP or reconfigure another USB device
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)  # potentially blocking kernel operation
            usb.util.claim_interface(dev, 0)
        except (usb.core.USBError, NotImplementedError, OSError) as exc:
            import logging
            log = logging.getLogger(__name__)
            try:
                usb.util.dispose_resources(dev)
            except Exception:
                log.exception("RTL8814AU claim failure: USB release failed")
            try:
                restored = restore_claimed_8814(dev, claim)
            except Exception:
                log.exception("RTL8814AU claim failure: restoration error")
                restored = False
            status = ("kernel driver restored" if restored
                      else "kernel driver NOT restored; inspect the RTL8814AU adapter")
            raise BringUpError(
                'claim', f'RTL8814AU interface handover failed: {exc}; {status}'
            ) from exc
        return claim
    except BaseException:
        os.close(fd)
        raise


def restore_claimed_8814(dev, claim: UsbClaim | None) -> bool:
    """Rebind the saved driver only to the USB instance detached by this claim."""
    import logging
    log = logging.getLogger(__name__)
    if (claim is None or os.geteuid() != 0 or claim.driver not in ORIGINAL_DRIVERS
            or (dev.idVendor, dev.idProduct, dev.bus, dev.address)
            != (*VID_PID, claim.bus, claim.address)):
        return False

    interface = claim.interface
    expected = USB_DRIVERS / claim.driver
    binding = interface / "driver"
    try:
        if (_identity(interface.parent) != (*VID_PID, claim.bus, claim.address)
                or not interface.is_dir() or not expected.is_dir()):
            return False
        if not binding.is_symlink():
            (expected / "bind").write_text(interface.name)
        return binding.resolve(strict=True) == expected
    except (OSError, ValueError) as exc:
        log.error("Could not verify or restore %s on %s: %s", claim.driver, interface.name, exc)
        return False


def release_claim_lock(claim: UsbClaim | None) -> None:
    if claim is not None:
        os.close(claim.fd)
