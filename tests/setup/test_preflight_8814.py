"""RTL8814AU handover preflight: an 'unmanaged' interface is a SAFE idle state (NetworkManager is
not controlling it), not a reason to refuse the handover -- while still rejecting anything actually
in use (AP/monitor mode, an association, an active NM connection, or the default route). Covers the
fix to setup/usb_handover.preflight_8814."""
import airscope.setup.usb_handover as uh
from airscope.setup.usb_handover import preflight_8814


class _DevId:
    vid, pid = 0x0bda, 0x8813
    bus, address = 1, 15


def _mk_run(*, info_type="managed", link="Not connected.", route="", nm="30 (disconnected)"):
    """Fake _run dispatching on the argv the preflight issues."""
    def _run(*args):
        a = list(args)
        if a[:2] == ["iw", "dev"] and a[-1] == "info":
            return True, f"Interface {a[2]}\n\ttype {info_type}\n"
        if a[:2] == ["iw", "dev"] and a[-1] == "link":
            return True, link
        if a[0] == "ip" and "route" in a:
            return True, route
        if a[0] == "nmcli":
            return True, nm
        return False, ""
    return _run


def _patch(monkeypatch, run):
    monkeypatch.setattr(uh, "opt_in", lambda d: True)
    monkeypatch.setattr(uh, "selected_netdev", lambda bus, addr: ("wlan2", ""))
    monkeypatch.setattr(uh, "_run", run)


def test_preflight_passes_when_unmanaged(monkeypatch):
    # the regression this fix targets: the 8814AU became the AP interface, so NM reports it
    # 'unmanaged' -- which is idle/safe, not unsafe.
    _patch(monkeypatch, _mk_run(nm="10 (unmanaged)"))
    ok, reason = preflight_8814(_DevId)
    assert ok, reason


def test_preflight_passes_when_disconnected(monkeypatch):
    _patch(monkeypatch, _mk_run(nm="30 (disconnected)"))
    ok, reason = preflight_8814(_DevId)
    assert ok, reason


def test_preflight_rejects_connected(monkeypatch):
    _patch(monkeypatch, _mk_run(nm="100 (connected)"))
    ok, reason = preflight_8814(_DevId)
    assert not ok and "in use" in reason


def test_preflight_rejects_ap_mode(monkeypatch):
    _patch(monkeypatch, _mk_run(info_type="AP"))
    ok, reason = preflight_8814(_DevId)
    assert not ok and "managed mode" in reason


def test_preflight_rejects_associated_link(monkeypatch):
    _patch(monkeypatch, _mk_run(link="Connected to aa:bb:cc:dd:ee:ff (on wlan2)"))
    ok, reason = preflight_8814(_DevId)
    assert not ok and "connected" in reason.lower()


def test_preflight_rejects_default_route(monkeypatch):
    # new safety check: never hand over a device carrying the default route (a management path)
    _patch(monkeypatch, _mk_run(route="default via 192.168.1.1 proto dhcp"))
    ok, reason = preflight_8814(_DevId)
    assert not ok and "management path" in reason


def test_preflight_requires_opt_in(monkeypatch):
    monkeypatch.setattr(uh, "opt_in", lambda d: False)
    ok, reason = preflight_8814(_DevId)
    assert not ok and "not explicitly enabled" in reason
