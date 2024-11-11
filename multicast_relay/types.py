import socket

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(eq=True, frozen=True)
class Transmitter:
    @dataclass(eq=True, frozen=True)
    class Relay:
        addr: str
        port: int

    relay: "Transmitter.Relay"
    interface: str
    addr: str
    mac: bytes
    netmask: str
    broadcast: str
    socket: socket.socket
    service: str


@dataclass
class RemoteAddr:
    addr: str
    socket: socket.socket | None
    connecting: bool
    connectFailure: float | None


@dataclass
class SSDPQuerier:
    addr: str
    port: int
    timestamp: float


Receiver: TypeAlias = socket.socket
