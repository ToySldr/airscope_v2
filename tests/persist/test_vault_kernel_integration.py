"""Vault integration for a kernel-backend-shaped capture (AirScope Priorities 4 & 6).

Distinct from the standalone hashcat proof: here a WPA handshake built the way the kernel-monitor
sink assembles one (AccessPoint + Handshake(M1 ANonce donor, M2 MIC keystone)) is persisted through
the REAL Vault.save_handshake, then INDEXED and RETRIEVED by a fresh Vault (disk-scan path), and --
when hashcat is present -- the Vault's OWN aggregate .hc22000 is cracked end to end, recovering the
known PSK. Hermetic: a temp captures dir; no interface / kernel driver / wlan0 touched.
"""
import shutil
import subprocess

import pytest

from airscope.crack import external as crack_ext
from airscope.crack import wpa_psk
from airscope.dot11.eapol import eapol_key, set_mic
from airscope.models import AccessPoint, CaptureType, Handshake, HandshakeMessage
from airscope.persist.config import Config
from airscope.persist.vault import Vault

SSID = "LiveNet"
PSK = "integration-pass"            # the known passphrase hashcat must recover
BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"
_RSN = bytes.fromhex("30140100000fac040100000fac040100000fac020000")   # WPA2-PSK/CCMP, 22 bytes


def _m1_payload() -> bytes:
    """A complete 802.1X EAPOL-Key M1 body (ANonce donor; MIC bit clear, MIC field zero)."""
    pl = bytearray(99)
    pl[0], pl[1] = 0x02, 0x03
    pl[2:4] = (95).to_bytes(2, "big")
    pl[4] = 0x02
    pl[5:7] = b"\x00\x8a"            # key info: pairwise + ack, no MIC
    return bytes(pl)


def _real_mic_ap(tmp_path, monkeypatch):
    """An AccessPoint carrying a GENUINE WPA2 handshake for PSK, captures redirected to tmp_path."""
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))   # Vault() reads this at __init__
    aa = bytes.fromhex(BSSID.replace(":", ""))
    spa = bytes.fromhex(CLIENT.replace(":", ""))
    anonce = bytes(range(32))
    snonce = bytes(range(64, 96))

    m2z = eapol_key(key_info=0x010A, key_len=0, replay=1, nonce=snonce, key_data=_RSN)
    mic = wpa_psk.mic_for(PSK, SSID, aa, spa, anonce, snonce, m2z)      # real HMAC-SHA1-128 MIC
    m2 = set_mic(m2z, mic)

    m1 = HandshakeMessage(raw=b"\x00" * 24, msg_num=1, replay_hex=(1).to_bytes(8, "big").hex(),
                          nonce=anonce, mic=b"\x00" * 16, key_data_len=0, eapol_payload=_m1_payload())
    m2_msg = HandshakeMessage(raw=b"\x00" * 24, msg_num=2, replay_hex=(1).to_bytes(8, "big").hex(),
                              nonce=snonce, mic=mic, key_data_len=22, eapol_payload=m2)

    ap = AccessPoint(bssid=BSSID, ssid=SSID)
    hs = Handshake(bssid=BSSID, client_mac=CLIENT, beacon_frame=b"BEACON")
    hs.messages.extend([m1, m2_msg])
    ap.handshakes[CLIENT] = hs
    return ap


def test_kernel_handshake_written_indexed_and_retrieved(tmp_path, monkeypatch):
    ap = _real_mic_ap(tmp_path, monkeypatch)

    # WRITE through the real Vault (the call the scanner makes on a live CaptureEvent).
    vault = Vault()
    result = vault.save_handshake(ap, CLIENT)
    assert result is not None and result.was_new is True
    assert result.path.name == "LiveNet_aa-bb-cc-dd-ee-ff.hc22000"
    assert result.path.exists()
    body = result.path.read_text(encoding="utf-8")
    assert body.count("WPA*02*") == 1 and "WPA*01*" not in body
    assert len(list(tmp_path.glob("*_handshake.pcap"))) == 1          # pcap companion written

    # INDEX + RETRIEVE from a FRESH Vault (disk-scan via load_capture_index).
    fresh = Vault()
    caps = fresh.persisted(BSSID)
    assert caps, "the saved handshake was not indexed from disk"
    hs_caps = [c for c in caps if c.type == CaptureType.HS]
    assert len(hs_caps) == 2                 # the aggregate .hc22000 + its _handshake.pcap companion
    agg = [c for c in hs_caps if c.path.endswith(".hc22000")]
    assert len(agg) == 1
    cap = agg[0]
    assert cap.bssid == BSSID and cap.ssid == SSID and cap.record_count == 1
    assert fresh.has_handshake(ap) is True
    assert "handshake" in fresh.summary().lower()


@pytest.mark.skipif(crack_ext.detect_tools().hashcat is None,
                    reason="hashcat not installed; conversion/crack leg is tool-gated")
def test_saved_vault_handshake_cracks_with_hashcat(tmp_path, monkeypatch):
    ap = _real_mic_ap(tmp_path, monkeypatch)
    vault = Vault()
    result = vault.save_handshake(ap, CLIENT)
    assert result is not None and result.path.exists()

    hashcat = crack_ext.detect_tools().hashcat
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("\n".join(["password", "letmein123", PSK, "admin123"]) + "\n",
                        encoding="utf-8")
    potfile = tmp_path / "as.pot"
    cmd = crack_ext.build_hashcat_cmd(hashcat, result.path, wordlist, potfile)
    subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    show = subprocess.run(crack_ext.build_hashcat_show(hashcat, result.path, potfile),
                          capture_output=True, text=True, timeout=30).stdout
    assert show.strip().endswith(":" + PSK), f"hashcat did not recover the PSK: {show!r}"
