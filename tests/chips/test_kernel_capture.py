"""radiotap_strip: strip the radiotap header + trailing FCS off a monitor frame and recover the
802.11 MPDU + RSSI. Pure logic of the kernel-monitor capture backend (chips/kernel_capture.py)."""
import struct

from airscope.chips.kernel_capture import KernelMonitorDriver, radiotap_strip

# A plausible 802.11 beacon header (>=10 bytes; content irrelevant to radiotap stripping).
_FRAME = bytes([0x80, 0x00]) + bytes(30)
_FCS = b"\xDE\xAD\xBE\xEF"

_FLAGS_BIT = 1 << 1          # radiotap FLAGS present
_ANTSIG_BIT = 1 << 5        # radiotap DBM_ANTSIGNAL present
_FLAG_FCS = 0x10
_FLAG_BADFCS = 0x40


def _rt(present, *, flags=None, rssi=None):
    """Build a radiotap header + optional FLAGS/ANTSIGNAL fields (align-1, so consecutive)."""
    fields = b""
    if flags is not None:
        fields += struct.pack("<B", flags)
    if rssi is not None:
        fields += struct.pack("<b", rssi)
    it_len = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, it_len, present) + fields


def test_strips_radiotap_and_fcs_and_reads_rssi():
    buf = _rt(_FLAGS_BIT | _ANTSIG_BIT, flags=_FLAG_FCS, rssi=-42) + _FRAME + _FCS
    out = radiotap_strip(buf)
    assert out is not None
    frame, rssi = out
    assert frame == _FRAME          # radiotap header AND trailing FCS removed
    assert rssi == -42


def test_no_fcs_flag_keeps_full_frame():
    # FLAGS present but FCS bit clear -> nothing stripped from the tail
    buf = _rt(_FLAGS_BIT | _ANTSIG_BIT, flags=0x00, rssi=-55) + _FRAME
    out = radiotap_strip(buf)
    assert out is not None
    frame, rssi = out
    assert frame == _FRAME
    assert rssi == -55


def test_bad_fcs_is_dropped():
    buf = _rt(_FLAGS_BIT, flags=_FLAG_FCS | _FLAG_BADFCS) + _FRAME + _FCS
    assert radiotap_strip(buf) is None


def test_rssi_defaults_to_zero_when_absent():
    # only FLAGS present, no ANTSIGNAL field
    buf = _rt(_FLAGS_BIT, flags=0x00) + _FRAME
    out = radiotap_strip(buf)
    assert out is not None and out[1] == 0


def test_rejects_bad_version():
    buf = bytearray(_rt(0) + _FRAME)
    buf[0] = 1                      # it_version != 0
    assert radiotap_strip(bytes(buf)) is None


def test_rejects_itlen_past_buffer():
    bad = struct.pack("<BBHI", 0, 0, 200, 0) + _FRAME   # it_len 200 > len(buf)
    assert radiotap_strip(bad) is None


def test_rejects_too_short_payload():
    buf = _rt(_FLAGS_BIT, flags=0x00) + bytes(4)        # 4-byte payload < 10
    assert radiotap_strip(buf) is None


def test_rx_stats_and_kernel_netdev_expose_real_identity():
    # kernel_netdev is the REAL Linux interface (resolved by USB identity), and rx_stats carries
    # per-adapter counters -- the evidence that each receiver is live on its own.
    d = KernelMonitorDriver("wlan2", vid=0x0bda, pid=0x8813, bus=1, address=2)
    assert d.kernel_netdev == "wlan2"
    d._rx_raw, d._rx_parsed, d._rx_beacons, d._rx_dropped = 100, 80, 40, 20
    d._channels_seen = {1, 6, 36}
    d._channel = 6
    s = d.rx_stats()
    assert s["netdev"] == "wlan2" and s["vidpid"] == "0bda:8813"
    assert (s["raw"], s["parsed"], s["beacons"], s["dropped"]) == (100, 80, 40, 20)
    assert s["channels_seen"] == [1, 6, 36] and s["channel"] == 6


def test_extended_present_words_are_skipped():
    # First present word has FLAGS+ANTSIGNAL AND the ext bit (31); a second (ext) present word
    # with no fields follows. The fields are located AFTER both present words.
    present0 = _FLAGS_BIT | _ANTSIG_BIT | (1 << 31)
    second = 0
    it_len = 8 + 4 + 2           # base present + one ext word + FLAGS + ANTSIGNAL
    hdr = struct.pack("<BBH", 0, 0, it_len) + struct.pack("<I", present0) + struct.pack("<I", second)
    buf = hdr + struct.pack("<Bb", _FLAG_FCS, -30) + _FRAME + _FCS
    out = radiotap_strip(buf)
    assert out is not None
    frame, rssi = out
    assert frame == _FRAME       # radiotap (incl ext word) + FCS both stripped
    assert rssi == -30
