from typing import Protocol

from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.logging import Logger


class _TransmitDatagram(Protocol):
    def __call__(self, datagram: RawDatagram) -> None: ...


class _RegisterTransmitter(Protocol):
    def __call__(self, addr: str, *, interface: str | None = None): ...


class Handler(Protocol):
    identifier: str

    def __init__(self, logger: Logger, transmit: _TransmitDatagram): ...

    @staticmethod
    def can_handle_datagram(datagram: RawDatagram) -> bool: ...

    def register_additional_transmitters(
        self, register: _RegisterTransmitter
    ) -> None: ...
    def handle(self, datagram: UDPDatagram) -> UDPDatagram: ...
