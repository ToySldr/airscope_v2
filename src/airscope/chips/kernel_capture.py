"""Kernel-driver monitor-mode capture backend.

Captures through the card's **existing kernel driver** in monitor mode -- no USB detach, no
firmware upload, no PyUSB handover. It sets the resolved netdev to monitor mode, opens an
``AF_PACKET`` raw socket on it, strips the radiotap header (and trailing FCS) off each frame, and
feeds the decoded 802.11 frames to the same sink/pipeline as the userspace drivers. On ``close()``
it restores the interface's original mode; it never detaches or rebinds the kernel driver.

Preferred for adapters whose kernel driver already does monitor-mode RX (the patched ``88XXau`` for
0bda:8812, the dedicated ``8814au`` for 0bda:8813). The PyUSB drivers remain available as an
optional, guarded backend. Linux-only (``AF_PACKET`` + ``iw``); backend selection must gate on that.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import subprocess
from pathlib import Path
from typing import Callable, ClassVar, List, Optional

import usb.core

from airscope.chips.driver import DeviceID, Driver, FakeMacSupport
from airscope.chips.rx_reader import RxReaderThread
from airscope.dot11.parser import WlanFrameParser
from airscope.errors import BringUpError

logger = logging.getLogger(__name__)

_ETH_P_ALL = 0x0003
_SYS_NET = Path("/sys/class/net")
_SYS_USB = Path("/sys/bus/usb/devices")

# 2.4 GHz 1..14 + 5 GHz non-DFS. Both kernel drivers tune these in monitor; DFS stays passive-only.
_CHANNELS_2G = list(range(1, 15))
_CHANNELS_5G = [36, 40, 44, 48, 149, 153, 157, 161, 165]


# --------------------------------------------------------------------------- #
# radiotap (pure -- unit-tested; no I/O)                                       #
# --------------------------------------------------------------------------- #
# (present-bit, size, align) for the standard prefix we need, up to DBM_ANTSIGNAL (bit 5).
_RT_FIELDS = ((0, 8, 8), (1, 1, 1), (2, 1, 1), (3, 4, 2), (4, 2, 2), (5, 1, 1))
_RT_FLAGS_BIT, _RT_ANTSIG_BIT = 1, 5
_RT_FLAG_FCS, _RT_FLAG_BADFCS = 0x10, 0x40


def radiotap_strip(buf: bytes) -> Optional[tuple[bytes, int]]:
    """``(802.11 MPDU without FCS, rssi_dbm)`` for a radiotap-prefixed frame, or ``None`` if it is
    malformed, too short, or flagged bad-FCS.

    Validates the radiotap header (version 0, sane ``it_len``), parses the standard present word up
    to DBM_ANTSIGNAL (enough for RSSI and the FCS flag), strips the radiotap header via ``it_len``,
    and strips the trailing 4-byte FCS when the FLAGS field marks it present (the Realtek monitor
    RCR keeps FCS). Fields align to a multiple of their size from the header start, per the spec.
    """
    if len(buf) < 8 or buf[0] != 0:            # it_version must be 0
        return None
    it_len = struct.unpack_from("<H", buf, 2)[0]
    if it_len < 8 or it_len > len(buf):
        return None
    present0 = struct.unpack_from("<I", buf, 4)[0]
    present, off = present0, 8
    while present & (1 << 31):                 # skip any extended present words
        if off + 4 > it_len:
            return None
        present = struct.unpack_from("<I", buf, off)[0]
        off += 4
    flags: Optional[int] = None
    rssi = 0
    for bit, size, align in _RT_FIELDS:
        if not (present0 & (1 << bit)):
            continue
        off = (off + align - 1) & ~(align - 1)
        if off + size > it_len:
            break
        if bit == _RT_FLAGS_BIT:
            flags = buf[off]
        elif bit == _RT_ANTSIG_BIT:
            rssi = struct.unpack_from("<b", buf, off)[0]   # signed dBm
        off += size
    frame = buf[it_len:]
    if flags is not None and (flags & _RT_FLAG_FCS):
        if flags & _RT_FLAG_BADFCS:
            return None                        # drop bad-FCS frames, as the chip RCR would
        frame = frame[:-4] if len(frame) >= 4 else b""
    if len(frame) < 10:                        # too short to be a useful 802.11 frame
        return None
    return frame, rssi


# --------------------------------------------------------------------------- #
# netdev / sysfs helpers (thin shell-outs; the tested logic is radiotap above) #
# --------------------------------------------------------------------------- #
def netdev_for(bus: int, address: int, *, usb_root: Path = _SYS_USB) -> Optional[str]:
    """The single kernel netdev owned by the USB device at ``(bus, address)``, via sysfs, or None
    (unresolved / 0 or >1 netdevs). Identifies the card by USB path, never a fixed wlanN."""
    try:
        for root in usb_root.iterdir():
            b, d = root / "busnum", root / "devnum"
            if not b.exists() or not d.exists():
                continue
            try:
                if int(b.read_text()) != bus or int(d.read_text()) != address:
                    continue
            except (OSError, ValueError):
                continue
            for intf in root.glob(f"{root.name}:*"):
                net = intf / "net"
                if net.is_dir():
                    names = [p.name for p in net.iterdir()]
                    if len(names) == 1:
                        return names[0]
    except OSError:
        return None
    return None


def _run_ok(*args: str) -> bool:
    try:
        return subprocess.run(args, capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _iface_type(netdev: str) -> Optional[str]:
    try:
        out = subprocess.run(["iw", "dev", netdev, "info"], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(?m)^\s*type\s+(\S+)", out)
    return m[1] if m else None


def _read_mac(netdev: str) -> Optional[str]:
    try:
        return (_SYS_NET / netdev / "address").read_text().strip() or None
    except OSError:
        return None


def _ifindex(netdev: str) -> Optional[int]:
    try:
        return int((_SYS_NET / netdev / "ifindex").read_text().strip())
    except (OSError, ValueError):
        return None


def _driver_of(netdev: str) -> Optional[str]:
    """Kernel driver bound to ``netdev``'s device, via sysfs (for the identity cross-reference)."""
    try:
        return (_SYS_NET / netdev / "device" / "driver").resolve().name
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# the backend                                                                  #
# --------------------------------------------------------------------------- #
class KernelMonitorDriver(Driver):
    """Monitor-mode capture via the card's bound kernel driver (no USB detach)."""

    SUPPORTED_CHANNELS: ClassVar[List[int]] = _CHANNELS_2G + _CHANNELS_5G
    FAKE_MAC = FakeMacSupport.UNIMPLEMENTED
    AP_MODE = False
    LINUX_REPLUG_AFTER_MODPROBE = False        # uses the bound kernel driver as-is; no modprobe
    DEVICE_REENUMERATES = False

    def __init__(self, netdev: str, *, vid: int = 0, pid: int = 0, bus: int = 0, address: int = 0):
        super().__init__()
        self._netdev = netdev
        self._vid, self._pid, self._bus, self._address = vid, pid, bus, address
        self.mac_address: Optional[str] = None
        self._channel: Optional[int] = None
        self.is_warm = False
        self._sock: Optional[socket.socket] = None
        self._reader: Optional[RxReaderThread] = None
        self._rx_cb: Optional[Callable] = None
        self._on_lost: Optional[Callable] = None
        self._orig_type: str = "managed"
        # Per-adapter RX stats (incremented on the reader thread; GIL-atomic int increments).
        self._rx_raw = 0            # frames read off the AF_PACKET socket for THIS netdev
        self._rx_parsed = 0         # successfully decoded 802.11 frames
        self._rx_beacons = 0        # of which beacons (FC 0x80)
        self._rx_dropped = 0        # radiotap-malformed / bad-FCS / unparseable
        self._channels_seen: set = set()

    @property
    def kernel_netdev(self) -> Optional[str]:
        """The REAL Linux interface this backend captures on, resolved by USB identity (never a
        collided app-internal label). The source of truth for logging/display."""
        return self._netdev

    def rx_stats(self) -> dict:
        """Independent per-adapter receive counters, for proving this receiver is live on its own."""
        return {"netdev": self._netdev, "vidpid": f"{self._vid:04x}:{self._pid:04x}",
                "channel": self._channel, "channels_seen": sorted(self._channels_seen),
                "raw": self._rx_raw, "parsed": self._rx_parsed,
                "beacons": self._rx_beacons, "dropped": self._rx_dropped}

    @classmethod
    def from_usb_device(cls, dev: usb.core.Device, id_entry: DeviceID) -> "KernelMonitorDriver":
        netdev = netdev_for(dev.bus, dev.address)
        if netdev is None:
            raise BringUpError("discover", f"no kernel netdev for USB {dev.bus}:{dev.address}")
        return cls(netdev, vid=id_entry.vid, pid=id_entry.pid, bus=dev.bus, address=dev.address)

    def register_rx_callback(self, cb: Callable) -> None:
        self._rx_cb = cb

    def register_disconnect_callback(self, cb: Callable) -> None:
        self._on_lost = cb

    async def connect(self, progress_cb=None) -> bool:
        loop = asyncio.get_running_loop()
        if progress_cb:
            progress_cb(0.1, f"{self._netdev}: entering monitor mode (kernel driver)")
        await loop.run_in_executor(None, self._enter_monitor)
        self.mac_address = _read_mac(self._netdev)
        logger.info("kernel-monitor: %04x:%04x (USB bus %d addr %d) -> %s (ifindex %s, driver %s)",
                    self._vid, self._pid, self._bus, self._address, self._netdev,
                    _ifindex(self._netdev), _driver_of(self._netdev))
        if progress_cb:
            progress_cb(0.6, "opening capture socket")
        self._sock = await loop.run_in_executor(None, self._open_socket)
        await self.set_channel(_CHANNELS_2G[0])   # cold default, like the userspace drivers
        self._reader = RxReaderThread(
            loop, self._read_once, self._dispatch, name=f"kernelmon-{self._netdev}-rx",
            on_fatal=lambda e: self._on_lost and self._on_lost(e))
        self._reader.start()
        if progress_cb:
            progress_cb(1.0, f"{self._netdev}: monitor capture active")
        return True

    def _enter_monitor(self) -> None:
        self._orig_type = _iface_type(self._netdev) or "managed"
        _run_ok("ip", "link", "set", "dev", self._netdev, "down")
        if not _run_ok("iw", "dev", self._netdev, "set", "type", "monitor"):
            raise BringUpError("monitor", f"{self._netdev}: could not set monitor mode")
        _run_ok("ip", "link", "set", "dev", self._netdev, "up")

    def _open_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        s.bind((self._netdev, _ETH_P_ALL))
        s.settimeout(1.0)
        return s

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        await asyncio.get_running_loop().run_in_executor(None, self._tune, channel)
        self._channel = channel
        return True

    def _tune(self, channel: int) -> None:
        # Set via BOTH iw (nl80211; 8814au) and iwconfig (WEXT; 88XXau) -- each kernel driver
        # honours its own; the other path is a harmless no-op.
        self._channels_seen.add(channel)
        _run_ok("iw", "dev", self._netdev, "set", "channel", str(channel))
        _run_ok("iwconfig", self._netdev, "channel", str(channel))

    def _read_once(self) -> Optional[list]:
        s = self._sock
        if s is None:
            return None
        try:
            buf = s.recv(4096)
        except socket.timeout:
            return None
        self._rx_raw += 1
        res = radiotap_strip(buf)
        if res is None:
            self._rx_dropped += 1
            return None
        frame, rssi = res
        if len(frame) == 10 and frame[0] == 0xD4:   # ACK control frame -> ACK tally (reader thread)
            self.record_ack(frame)
            return None
        pkt = WlanFrameParser.parse_80211_frame(frame, rssi)
        if pkt is None:
            self._rx_dropped += 1
            return None
        self._rx_parsed += 1
        if frame[0] == 0x80:                        # 802.11 management beacon (FC type 0, subtype 8)
            self._rx_beacons += 1
        return [pkt]

    def _dispatch(self, pkts: list) -> None:
        cb = self._rx_cb
        if cb is None:
            return
        for pkt in pkts:
            cb(pkt)

    async def close(self) -> None:
        loop = asyncio.get_running_loop()
        if self._reader is not None:
            await self._reader.stop()
            self._reader = None
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        await loop.run_in_executor(None, self._restore)   # restore managed; never detached

    def _restore(self) -> None:
        _run_ok("ip", "link", "set", "dev", self._netdev, "down")
        _run_ok("iw", "dev", self._netdev, "set", "type", self._orig_type or "managed")
        _run_ok("ip", "link", "set", "dev", self._netdev, "up")

    # ---- TX / ACK: monitor-socket inject; the monitor vif already admits ACKs ----
    async def _inject_frame(self, frame_bytes: bytes) -> bool:
        s = self._sock
        if s is None:
            return False
        rt = struct.pack("<BBHI", 0, 0, 8, 0)     # minimal radiotap header (no fields)
        try:
            await asyncio.get_running_loop().run_in_executor(None, s.send, rt + frame_bytes)
            return True
        except OSError:
            return False

    def _stamp_tx_seq(self, frame_bytes: bytes) -> bytes:
        return frame_bytes

    async def _enable_rx_acks(self) -> None:
        return

    async def _disable_rx_acks(self) -> None:
        return
