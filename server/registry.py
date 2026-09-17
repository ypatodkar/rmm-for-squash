from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

HEARTBEAT_INTERVAL_SECONDS = 10
OFFLINE_AFTER_SECONDS = 30


@dataclass
class DeviceConnection:
    device_id: str
    hostname: str
    os_version: str
    agent_version: str
    outbound: asyncio.Queue = field(default_factory=asyncio.Queue)
    last_seen: float = field(default_factory=time.monotonic)
    connected_at: float = field(default_factory=time.time)
    revoked: bool = False

    closed: asyncio.Event = field(default_factory=asyncio.Event)

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def drain_pending(self) -> int:
        """Discards work queued but not yet delivered."""
        dropped = 0
        while not self.outbound.empty():
            self.outbound.get_nowait()
            dropped += 1
        return dropped

    async def close(self) -> None:
        """Signals the socket handler to tear the connection down."""
        self.revoked = True
        self.closed.set()

    @property
    def seconds_since_last_seen(self) -> float:
        return round(time.monotonic() - self.last_seen, 1)

    @property
    def is_reachable(self) -> bool:
        return not self.revoked and (time.monotonic() - self.last_seen) < OFFLINE_AFTER_SECONDS


class DeviceRegistry:
    def __init__(self) -> None:
        self._devices: dict[str, DeviceConnection] = {}

    def register(self, connection: DeviceConnection) -> DeviceConnection:
        self._devices[connection.device_id] = connection
        return connection

    def remove(self, device_id: str, expected: DeviceConnection) -> None:
        if self._devices.get(device_id) is expected:
            del self._devices[device_id]

    def get(self, device_id: str) -> DeviceConnection | None:
        return self._devices.get(device_id)
