"""Conservative, opt-in PyUSB handover for *only* 0bda:8813.

Set AIRSCOPE_8814_USB_HANDOVER=1 and AIRSCOPE_8814_USB_INTERFACE to the
explicitly selected interface to opt in. This is NOT a module unload. It is a USB-interface detach, which can still
hang in a buggy kernel driver. Never detach a connected interface or AP.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

if sys.platform.startswith('linux'):
    import fcntl

from airscope.errors import BringUpError

VID_PID = (0x0bda, 0x8813)  # RTL8814AU
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


def preflight_8814(device_id) -> tuple[bool, str]:
    """Fail closed unless exactly the explicitly configured interface belongs to the selected USB instance.

    Requires the iface to be managed, disconnected in iw AND NetworkManager.
    Matches bus/dev address from Airscope's selected DeviceID, not the first
    arbitrary USB device with that VID:PID.
    """
    if not opt_in(device_id):
        return False, "Direct USB handover not explicitly enabled for RTL8814AU/root"
    bus = getattr(device_id, "bus", None)
    addr = getattr(device_id, "address", None)
    if bus is None or addr is None:
        return False, "Missing USB bus/address; refusing ambiguous adapter selection"

    roots = []
    base = Path("/sys/bus/usb/devices")
    try:
        for d in base.iterdir():
            if not (d / "idVendor").exists():
                continue
            try:
                if (int((d / "idVendor").read_text().strip(), 16),
                    int((d / "idProduct").read_text().strip(), 16),
                    int((d / "busnum").read_text().strip()),
                    int((d / "devnum").read_text().strip())) == (*VID_PID, bus, addr):
                    roots.append(d.resolve())
            except (OSError, ValueError):
                continue
    except OSError:
        return False, "Cannot inspect USB sysfs"
    if len(roots) != 1:
        return False, f"Expected exactly one selected RTL8814AU USB device; found {len(roots)}"

    root = roots[0]
    interfaces = []
    try:
        for iface in Path('/sys/class/net').iterdir():
            d = (iface / 'device').resolve()
            if d == root or root in d.parents:
                interfaces.append(iface.name)
    except OSError:
        return False, "Cannot inspect network-interface ownership"
    expected = os.environ.get("AIRSCOPE_8814_USB_INTERFACE")
    if not expected or interfaces != [expected]:
        return False, f"Protected adapter selection: expected configured interface, found {interfaces!r}"

    ok, info = _run('iw', 'dev', expected, 'info')
    if not ok or not re.search(r'(?m)^\s*type\s+managed\s*$', info):
        return False, "selected interface is not confirmed managed mode (AP or monitor modes forbidden)"
    ok, link = _run('iw', 'dev', expected, 'link')
    if not ok or 'Not connected.' not in link:
        return False, "selected interface is connected or wireless link status is unknown"
    ok, nm = _run('nmcli', '-g', 'GENERAL.STATE', 'device', 'show', expected)
    if not ok or 'disconnected' not in nm.lower():
        return False, f"NetworkManager did not confirm selected interface disconnected: {nm!r}"
    return True, "Only selected interface (0bda:8813) is idle; other interfaces untouched"


def claim_opted_in_8814(dev) -> int | None:
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
        raise BringUpError('claim', 'Set AIRSCOPE_8814_USB_HANDOVER=1 to try guarded selected interface handover')

    fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BringUpError('claim', 'Another Airscope RTL8814AU handover is active') from exc

        allowed, reason = preflight_8814(Selected)
        if not allowed:
            raise BringUpError('claim', reason)

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
                restored = restore_claimed_8814(dev, fd)
            except Exception:
                log.exception("RTL8814AU claim failure: restoration error")
                restored = False
            status = ("kernel driver restored" if restored
                      else "kernel driver NOT restored; inspect selected interface")
            raise BringUpError(
                'claim', f'RTL8814AU interface handover failed: {exc}; {status}'
            ) from exc
        return fd
    except BaseException:
        os.close(fd)
        raise



def restore_claimed_8814(dev, lock_fd: int | None) -> bool:
    """Restore only the RTL8814AU claimed by this Airscope session."""
    import logging
    log = logging.getLogger(__name__)

    if lock_fd is None:
        return False
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        return False
    if (getattr(dev, "idVendor", None),
        getattr(dev, "idProduct", None)) != VID_PID:
        return False

    bus = getattr(dev, "bus", None)
    address = getattr(dev, "address", None)
    if bus is None or address is None:
        return False

    matches = []
    for root in Path("/sys/bus/usb/devices").iterdir():
        try:
            identity = (
                int((root / "idVendor").read_text().strip(), 16),
                int((root / "idProduct").read_text().strip(), 16),
                int((root / "busnum").read_text().strip()),
                int((root / "devnum").read_text().strip()),
            )
            if identity == (*VID_PID, bus, address):
                matches.append(root)
        except (OSError, ValueError):
            continue

    if len(matches) != 1:
        log.warning("RTL8814AU restore: selected USB device not unique")
        return False

    interface = Path(str(matches[0]) + ":1.0")
    if not interface.is_dir():
        log.warning("RTL8814AU restore: USB interface missing")
        return False

    binding = interface / "driver"
    if binding.is_symlink():
        return binding.resolve().name == "rtl8814au"

    kernel_driver = Path("/sys/bus/usb/drivers/rtl8814au")
    if not kernel_driver.is_dir():
        log.warning("RTL8814AU restore: kernel driver unavailable")
        return False

    try:
        (kernel_driver / "bind").write_text(interface.name)
    except OSError as exc:
        log.error("RTL8814AU restore: bind failed: %s", exc)
        return False

    restored = (
        binding.is_symlink()
        and binding.resolve().name == "rtl8814au"
    )

    if restored:
        log.info("RTL8814AU restored: %s", interface.name)
    else:
        log.error("RTL8814AU driver binding not confirmed")

    return restored


def release_claim_lock(fd: int | None) -> None:
    if fd is not None:
        os.close(fd)  # releases flock; PyUSB resources released separately
