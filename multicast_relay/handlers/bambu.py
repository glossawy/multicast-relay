from dataclasses import dataclass
from typing import Callable
from multicast_relay import constants
from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.datagrams.ssdp import SSDPDatagram
from multicast_relay.handlers.types import Handler

from collections import deque

from multicast_relay.logging import Logger

BAMBU_SSDP_PORTS = [1990, 2021]
BAMBU_MCAST_PORT = 1990
BAMBU_UNICAST_PORT = 2021


@dataclass(eq=True, frozen=True)
class WaitingClient:
    address: str


class Bambu(Handler):
    def __init__(self, logger: Logger, transmit: Callable[[RawDatagram], None]) -> None:
        self.logger = logger
        self.transmit = transmit
        self.waiting_clients: deque[WaitingClient] = deque()

    def can_handle_datagram(self, datagram: RawDatagram) -> bool:
        return (
            "BAMBULAB-COM" in SSDPDatagram(datagram.payload).content
            and datagram.dst_address == constants.SSDP_MCAST_ADDR
            and datagram.dst_port in BAMBU_SSDP_PORTS
        )

    def handle(self, datagram: UDPDatagram) -> UDPDatagram:
        if datagram.src_port == constants.SSDP_MCAST_PORT:
            for client in self._unique_waiting_clients():
                tx_dgram = datagram.with_different_dst(
                    client.address, BAMBU_UNICAST_PORT
                )

                self.logger.info(
                    f"[Bambu]: Attempting to transmit to waiting client {client.address} at port {tx_dgram.dst_port} from {tx_dgram.src_address}:{tx_dgram.src_port}"
                )
                self.transmit(tx_dgram)

            self.waiting_clients.clear()
        elif datagram.src_port != constants.SSDP_MCAST_PORT:
            self.logger.info(
                f"Enqueued waiting Bambu client as {datagram.src_address}:{datagram.src_port}"
            )
            self._enqueue(WaitingClient(datagram.src_address))
        else:
            self.logger.info(
                f"[Bambu]: Encountered {datagram.src_address}:{datagram.src_port} -> {datagram.dst_address}:{datagram.dst_port} and did nothing with it?"
            )

        return datagram

    def _unique_waiting_clients(self):
        returned_set: set[WaitingClient] = set()

        while len(self.waiting_clients) > 0:
            client = self.waiting_clients.popleft()

            if client in returned_set:
                continue

            returned_set.add(client)

            yield client

    def _enqueue(self, client: WaitingClient) -> None:
        self.waiting_clients.append(client)

        if len(self.waiting_clients) > 255:
            self.waiting_clients.popleft()
