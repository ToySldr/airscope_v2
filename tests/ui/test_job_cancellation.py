import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from airscope.crack import external


@pytest.mark.asyncio
async def test_cancellation_kills_and_waits_for_child(monkeypatch):
    reading = asyncio.Event()

    async def readline():
        reading.set()
        await asyncio.Future()

    child = SimpleNamespace(
        stdout=SimpleNamespace(readline=readline),
        returncode=None, kill=Mock(), wait=AsyncMock(),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=child))
    task = asyncio.create_task(external.run_crack(["mock-child"], "mock"))
    try:
        await asyncio.wait_for(reading.wait(), timeout=2)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    child.kill.assert_called_once_with()
    child.wait.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_cancellation_after_stdout_eof_kills_child(monkeypatch):
    waiting = asyncio.Event()

    async def wait():
        if not waiting.is_set():
            waiting.set()
            await asyncio.Future()

    child = SimpleNamespace(
        stdout=SimpleNamespace(readline=AsyncMock(return_value=b"")),
        returncode=None, kill=Mock(), wait=wait,
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=child))
    task = asyncio.create_task(external.run_crack(["mock-child"], "mock"))
    await asyncio.wait_for(waiting.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)
    child.kill.assert_called_once_with()
