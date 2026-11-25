"""Channel-hop resilience: a transient tune error must retry/skip and keep hopping, never
silently stop; only a physically-gone device is terminal. Covers the fix to
``WlanInterface._tune_for_hop`` / ``_hop_loop`` (wlan/interface.py)."""
import asyncio

import pytest

import airscope.wlan.interface as iface_mod
from airscope.wlan.interface import WlanInterface, _HOP_PER_CHANNEL_RETRIES


class _DeviceGone(Exception):
    """Stand-in for a device-gone fault; the autouse fixture makes is_device_gone match it."""


class _FakeHopIface(WlanInterface):
    """Minimal WlanInterface that exercises the hop retry logic without a real driver/USB.

    ``__new__``-free: defines its own ``__init__`` so ``WlanInterface.__init__`` (which needs a
    Driver + USB) never runs. Only the attributes/methods ``_tune_for_hop`` touches are provided.
    """

    def __init__(self, tune_outcomes):
        # each outcome: True (tune ok) or an Exception instance to raise
        self._outcomes = list(tune_outcomes)
        self._is_hopping = True
        self._tune_task = None
        self.lost = []
        self.tune_calls = 0

    @property
    def _chipset(self):
        return "FAKE8812"

    def _on_device_lost(self, exc):
        self.lost.append(exc)

    async def set_channel(self, channel, scan=False):
        self.tune_calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture(autouse=True)
def _device_gone(monkeypatch):
    monkeypatch.setattr(iface_mod, "is_device_gone", lambda e: isinstance(e, _DeviceGone))


def test_tune_for_hop_success():
    iface = _FakeHopIface([True])
    assert asyncio.run(iface._tune_for_hop(6)) is True
    assert iface.tune_calls == 1
    assert iface.lost == []


def test_tune_for_hop_recovers_after_transient():
    # one transient failure, then success within the retry budget -> True (hopping continues)
    iface = _FakeHopIface([RuntimeError("usb ctrl-transfer timeout"), True])
    assert asyncio.run(iface._tune_for_hop(6)) is True
    assert iface.tune_calls == 2
    assert iface.lost == []


def test_tune_for_hop_transient_exhausted_returns_false_not_raise():
    # every attempt fails transiently -> False (skip channel), NEVER raises, no device-lost.
    # This is the exact silent-stop bug being guarded: the old code let this break the loop.
    attempts = _HOP_PER_CHANNEL_RETRIES + 1
    iface = _FakeHopIface([RuntimeError("usb stall")] * attempts)
    assert asyncio.run(iface._tune_for_hop(6)) is False
    assert iface.tune_calls == attempts
    assert iface.lost == []


def test_tune_for_hop_device_gone_is_terminal():
    iface = _FakeHopIface([_DeviceGone("unplugged")])
    assert asyncio.run(iface._tune_for_hop(6)) is None
    assert iface.tune_calls == 1
    assert len(iface.lost) == 1


def test_tune_for_hop_stops_when_hopping_cleared():
    # stop_hopping() clears _is_hopping; a retry must not fire after that.
    iface = _FakeHopIface([RuntimeError("transient")])
    iface._is_hopping = False
    assert asyncio.run(iface._tune_for_hop(6)) is False
    assert iface.tune_calls == 0
