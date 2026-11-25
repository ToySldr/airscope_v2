"""Dual-adapter RX attribution regression (Priority 2).

With two Alfa cards in the pool -- wlan1 = RTL8812AU (0bda:8812), wlan2 = RTL8814AU (0bda:8813) --
every received frame must retain its ORIGINATING adapter identity. Traffic the SECOND card hears is
never collapsed onto the FIRST (members[0]): attribution flows from the per-member RX closure
(attach() binds `i=iface`) through `_ingest`'s `card_id = iface.name` into the sink's per-card maps
(`signal_by_card`). These tests pin that contract so a future refactor cannot silently regress it to
a members[0]-style aggregate. They PASS today -- that is the point: they lock in correct behavior.

(The `members[0].name` in WlanArray.note_own_beacon is a SELF-emitted evil-twin beacon seed, not a
received frame; see test_note_own_beacon_* for its isolated, labelled behavior.)"""
from types import SimpleNamespace

from airscope.chips.driver import FakeMacSupport
from airscope.wlan.array import WlanArray
from tests.frames import pkt


class FakeIface:
    """The slice of WlanInterface the array touches, with an emit() test hook (mirrors test_array)."""

    def __init__(self, name, channels=(1, 6, 11)):
        self.name = name
        self.description = name
        self._channels = list(channels)
        self.current_channel = self._channels[0]
        self.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE,
                                      SUPPORTED_CHANNELS=list(channels))
        self.on_tx = None
        self._rx = []
        self._disc = []

    @property
    def supported_channels(self):
        return self._channels

    def register_rx_callback(self, cb):
        self._rx.append(cb)

    def register_disconnect_callback(self, cb):
        self._disc.append(cb)

    def emit(self, packet):
        for cb in list(self._rx):
            cb(packet)


def _beacon(bssid, rssi, *, seq=b"\x10\x00", channel=6, ssid="AP"):
    """A beacon whose raw bytes are keyed by (BSSID, seq) so distinct APs dedupe distinctly and a
    repeat of the SAME (BSSID, seq) is a cross-card duplicate."""
    a2 = bytes.fromhex(bssid.replace(":", ""))
    raw = b"\x80\x00\x00\x00" + b"\xff\xff\xff\xff\xff\xff" + a2 + a2 + seq + b"\x00" * 12
    return pkt({"type": "beacon", "bssid": bssid, "source": bssid, "dest": "ff:ff:ff:ff:ff:ff",
                "rssi": rssi, "ssid": ssid, "channel": channel, "raw": raw})


def _pool(*ifaces):
    a = WlanArray()
    for i in ifaces:
        a.attach(i)
    return a


AP_A = "aa:bb:cc:dd:ee:ff"
AP_B = "11:22:33:44:55:66"


def test_each_adapter_unique_ap_attributed_to_itself():
    """wlan1 hears AP_A, wlan2 hears a DIFFERENT AP_B: each AP's signal is attributed to the exact
    card that heard it, and to no other."""
    w1 = FakeIface("wlan1")
    w2 = FakeIface("wlan2")
    a = _pool(w1, w2)
    w1.emit(_beacon(AP_A, -42))
    w2.emit(_beacon(AP_B, -55))
    aps = a.access_points
    assert aps[AP_A].signal_by_card == {"wlan1": -42}
    assert aps[AP_B].signal_by_card == {"wlan2": -55}


def test_shared_ap_retains_both_adapter_signals():
    """Both cards hear the SAME beacon (same raw): folded once, but BOTH antennas' signals are kept
    under their own card_id -- not merged onto members[0]."""
    w1 = FakeIface("wlan1")
    w2 = FakeIface("wlan2")
    a = _pool(w1, w2)
    folds = {"n": 0}
    real = a._sink.update

    def counting(*args, **kwargs):
        folds["n"] += 1
        return real(*args, **kwargs)

    a._sink.update = counting
    w1.emit(_beacon(AP_A, -70))     # novel: wlan1 folds it in
    w2.emit(_beacon(AP_A, -55))     # duplicate: only wlan2's signal (record_signal)
    ap = a.access_points[AP_A]
    assert ap.signal_by_card == {"wlan1": -70, "wlan2": -55}
    assert ap.signal == -55          # strongest antenna wins the Power reading
    assert ap.beacons == 1           # counted once (deduped), not double
    assert folds["n"] == 1           # sink.update folded the novel copy exactly once


def test_second_adapter_frame_never_collapses_to_first():
    """A frame ONLY the second member (wlan2) hears is attributed to wlan2 -- members[0] (wlan1) does
    NOT appear in its attribution. This is the exact 'both cards -> members[0]' concern, refuted."""
    w1 = FakeIface("wlan1")
    w2 = FakeIface("wlan2")
    a = _pool(w1, w2)
    w2.emit(_beacon(AP_B, -48))
    ap = a.access_points[AP_B]
    assert ap.signal_by_card == {"wlan2": -48}
    assert "wlan1" not in ap.signal_by_card      # members[0] was never credited


def test_member_order_does_not_decide_attribution():
    """Attach wlan2 FIRST (so members[0] is wlan2), then wlan1. A frame wlan1 hears is still
    attributed to wlan1 -- attribution follows the receiving card, never the member index."""
    w2 = FakeIface("wlan2")
    w1 = FakeIface("wlan1")
    a = _pool(w2, w1)                 # members[0] is now wlan2
    assert a.members[0].name == "wlan2"
    w1.emit(_beacon(AP_A, -61))
    ap = a.access_points[AP_A]
    assert ap.signal_by_card == {"wlan1": -61}   # the actual receiver, not members[0]


def test_each_adapter_independent_signal_history_smoothing():
    """Per-card RSSI smoothing is independent: repeated samples on wlan1 do not bleed into wlan2's
    reading for the same AP."""
    w1 = FakeIface("wlan1")
    w2 = FakeIface("wlan2")
    a = _pool(w1, w2)
    for _ in range(4):
        w1.emit(_beacon(AP_A, -80))          # wlan1 sees a weak signal repeatedly
    w2.emit(_beacon(AP_A, -40))              # wlan2 sees it strong once
    ap = a.access_points[AP_A]
    assert ap.signal_by_card["wlan1"] == -80
    assert ap.signal_by_card["wlan2"] == -40
    assert ap.signal == -40                  # Power reading picks the strong antenna


def test_three_adapters_each_retained_for_shared_ap():
    """Three cards hear one AP: all three RSSIs are retained under their own card_id; none is merged
    onto members[0]; the AP is still folded exactly once."""
    w1, w2, w3 = FakeIface("wlan1"), FakeIface("wlan2"), FakeIface("wlan3")
    a = _pool(w1, w2, w3)
    w1.emit(_beacon(AP_A, -70))
    w2.emit(_beacon(AP_A, -55))
    w3.emit(_beacon(AP_A, -61))
    ap = a.access_points[AP_A]
    assert ap.signal_by_card == {"wlan1": -70, "wlan2": -55, "wlan3": -61}
    assert ap.signal == -55                  # strongest antenna
    assert ap.beacons == 1                    # one on-air AP, folded once


def test_note_own_beacon_seeds_under_sentinel_not_a_real_adapter():
    """A SELF-emitted twin beacon (note_own_beacon) is seeded under a non-adapter 'seed' label, so a
    real adapter's signal_by_card never carries a synthetic reading it did not measure. This is the
    exact flagged members[0].name line -- here pinned to the honest sentinel."""
    w1 = FakeIface("wlan1")
    w2 = FakeIface("wlan2")
    a = _pool(w1, w2)
    twin = "de:ad:be:ef:00:01"
    a2 = bytes.fromhex(twin.replace(":", ""))
    ssid = b"twinnet"
    body = (b"\x00" * 8 + (100).to_bytes(2, "little") + (0x0411).to_bytes(2, "little")
            + bytes([0, len(ssid)]) + ssid + bytes([1, 1, 0x82]))      # TSF, interval, cap, SSID, rates
    beacon = b"\x80\x00\x00\x00" + b"\xff\xff\xff\xff\xff\xff" + a2 + a2 + b"\x10\x00" + body
    a.note_own_beacon(twin, 6, beacon)
    ap = a.access_points.get(twin)
    assert ap is not None, "self-beacon should seed an AP entry so injected M1s can pair"
    assert "seed" in ap.signal_by_card
    assert "wlan1" not in ap.signal_by_card and "wlan2" not in ap.signal_by_card
