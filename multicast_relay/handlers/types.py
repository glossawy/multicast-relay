from typing import Callable, Protocol

from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.logging import Logger


class Handler(Protocol):
    def __init__(self, logger: Logger, transmit: Callable[[UDPDatagram], None]): ...
    def can_handle_datagram(self, datagram: RawDatagram) -> bool: ...
    def handle(self, datagram: UDPDatagram) -> UDPDatagram: ...
