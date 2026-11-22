from pathlib import Path

from airscope.persist.vault import Vault


def test_vault_excludes_internal_files_and_keeps_packet_captures_binary(tmp_path):
    folder = tmp_path / "Fixture_AABBCCDDEEFF"
    folder.mkdir()
    for name in ("packet.cap", "packet.pcap", "packet.pcapng", ".airscope-aircrack.key",
                 ".airscope-job.hc22000", "notes.txt"):
        (folder / name).write_bytes(b"fixture")
    internal = folder / ".airscope-job"
    internal.mkdir()
    (internal / "scratch.pcap").touch()

    vault = Vault()
    captures = vault.persisted("aa:bb:cc:dd:ee:ff")
    assert {Path(c.path).name for c in captures} == {"packet.cap", "packet.pcap", "packet.pcapng"}
    assert all(vault.capture_payload(c) == "" for c in captures)
