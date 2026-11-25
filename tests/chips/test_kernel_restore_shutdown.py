"""KernelMonitorDriver shutdown safety (AirScope Priority 6).

Proves the kernel-monitor backend returns the adapter to the OS SAFELY on shutdown: ``_restore()``
(and the public ``close()`` that drives it) sets the interface back to its original mode with ``iw``
and shells out ONLY ``ip``/``iw`` against this adapter's OWN netdev. It must NEVER detach, unbind,
rmmod, modprobe, or USB-reset the kernel driver, and must NEVER touch another card's netdev (wlan0).

These tests pin the exact argv ``_restore()`` issues by recording the module-level ``_run_ok``
shell-out, so any regression that adds a destructive teardown -- or retargets a different interface --
fails loudly. (The pure radiotap logic is covered separately in ``test_kernel_capture.py``.)
"""
import asyncio

from airscope.chips import kernel_capture
from airscope.chips.kernel_capture import KernelMonitorDriver

# This adapter's OWN resolved netdev (the 8814au, 0bda:8813). Restore must target only this -- the
# backend resolves the real interface by USB identity, never a collided/fixed wlanN like wlan0.
_NETDEV = "wlan2"

# Driver/USB teardown operations the kernel-monitor shutdown must NEVER perform: detaching the kernel
# driver, unbinding/removing/re-probing it, or power-cycling the USB device.
_FORBIDDEN_TOKENS = ("detach", "rmmod", "modprobe", "unbind", "usbreset", "usb_modeswitch")


def _record_run_ok(monkeypatch):
    """Replace the MODULE-LEVEL ``_run_ok`` with a recorder that appends each ``(*args)`` argv tuple
    and returns True (as a successful shell-out would). Returns the list it records into."""
    recorded = []

    def fake_run_ok(*args):
        recorded.append(args)
        return True

    monkeypatch.setattr(kernel_capture, "_run_ok", fake_run_ok)
    return recorded


def _driver():
    """A fresh driver with the USB identity from the task and the usual original mode (managed)."""
    d = KernelMonitorDriver(_NETDEV, vid=0x0bda, pid=0x8813, bus=1, address=2)
    d._orig_type = "managed"
    return d


def test_restore_issues_exactly_the_three_managed_restore_commands(monkeypatch):
    # The whole of _restore(): bring the iface DOWN, set its type back to managed via `iw`, bring it
    # UP again -- exactly three commands, each targeting wlan2. No fourth command, no driver reset.
    recorded = _record_run_ok(monkeypatch)
    _driver()._restore()
    assert recorded == [
        ("ip", "link", "set", "dev", _NETDEV, "down"),
        ("iw", "dev", _NETDEV, "set", "type", "managed"),
        ("ip", "link", "set", "dev", _NETDEV, "up"),
    ]


def test_restore_returns_to_managed_through_iw_set_type(monkeypatch):
    # Managed-mode is restored by `iw dev <netdev> set type managed` -- the in-place, driver-
    # preserving path. There is exactly ONE iw invocation and it is that set-type call (no
    # `iw ... del`, no `iw phy`, nothing that would tear the interface or driver down).
    recorded = _record_run_ok(monkeypatch)
    _driver()._restore()
    iw_cmds = [cmd for cmd in recorded if cmd and cmd[0] == "iw"]
    assert iw_cmds == [("iw", "dev", _NETDEV, "set", "type", "managed")]


def test_restore_never_detaches_rebinds_or_resets_the_driver(monkeypatch):
    # Priority 6: shutdown NEVER performs a driver/USB teardown. No recorded argv may contain any of
    # the forbidden tokens anywhere (substring match, case-insensitive).
    recorded = _record_run_ok(monkeypatch)
    _driver()._restore()
    flat = " ".join(token.lower() for cmd in recorded for token in cmd)
    for forbidden in _FORBIDDEN_TOKENS:
        assert forbidden not in flat, f"{forbidden!r} appeared in restore commands: {flat!r}"


def test_restore_touches_only_its_own_netdev_never_wlan0(monkeypatch):
    # Every restore command addresses THIS adapter's own netdev (wlan2); none mentions wlan0.
    recorded = _record_run_ok(monkeypatch)
    _driver()._restore()
    assert recorded, "restore issued no commands"
    for cmd in recorded:
        assert _NETDEV in cmd, f"restore command does not target {_NETDEV}: {cmd!r}"
    flat = " ".join(token for cmd in recorded for token in cmd)
    assert "wlan0" not in flat, f"restore touched wlan0: {flat!r}"


def test_restore_preserves_the_original_iface_type_not_a_hardcoded_managed(monkeypatch):
    # _restore() restores the type captured at monitor-entry (self._orig_type), passed through
    # VERBATIM via `self._orig_type or "managed"` -- it does not hardcode "managed". Here the adapter
    # read as an AP before capture (the string `iw dev info` reports), so restore must set type AP.
    recorded = _record_run_ok(monkeypatch)
    d = KernelMonitorDriver(_NETDEV, vid=0x0bda, pid=0x8813, bus=1, address=2)
    d._orig_type = "AP"
    d._restore()
    assert recorded == [
        ("ip", "link", "set", "dev", _NETDEV, "down"),
        ("iw", "dev", _NETDEV, "set", "type", "AP"),
        ("ip", "link", "set", "dev", _NETDEV, "up"),
    ]


def test_restore_falls_back_to_managed_when_orig_type_is_empty(monkeypatch):
    # The source expression is `self._orig_type or "managed"`: a falsy stored type coerces to managed
    # so the card is never left without a usable mode.
    recorded = _record_run_ok(monkeypatch)
    d = KernelMonitorDriver(_NETDEV, vid=0x0bda, pid=0x8813, bus=1, address=2)
    d._orig_type = ""
    d._restore()
    assert ("iw", "dev", _NETDEV, "set", "type", "managed") in recorded


def test_close_runs_the_safe_restore_and_nothing_destructive(monkeypatch):
    # The PUBLIC shutdown entrypoint close() drives _restore() (a fresh driver has no reader/socket,
    # so those branches are skipped and close() just awaits _restore in the executor). The full
    # shutdown path therefore issues ONLY the safe managed-restore commands -- never a detach/reset.
    recorded = _record_run_ok(monkeypatch)
    d = _driver()
    asyncio.run(d.close())
    assert recorded == [
        ("ip", "link", "set", "dev", _NETDEV, "down"),
        ("iw", "dev", _NETDEV, "set", "type", "managed"),
        ("ip", "link", "set", "dev", _NETDEV, "up"),
    ]
    flat = " ".join(token.lower() for cmd in recorded for token in cmd)
    for forbidden in _FORBIDDEN_TOKENS:
        assert forbidden not in flat, f"{forbidden!r} appeared in close() commands: {flat!r}"
    assert "wlan0" not in flat
