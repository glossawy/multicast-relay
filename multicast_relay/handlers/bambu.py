from dataclasses import dataclass
from multicast_relay import constants
from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.datagrams.ssdp import SSDPDatagram
from multicast_relay.handlers.types import Handler

from collections import deque

BAMBU_SSDP_PORTS = [1990, 2021]
BAMBU_MCAST_PORT = 1990
BAMBU_UNICAST_PORT = 2021


@dataclass
class WaitingClient:
    address: str


class Bambu(Handler):
    def __init__(self, transmit) -> None:
        self.transmit = transmit
        self.waiting_clients: deque[WaitingClient] = deque()

    def can_handle_datagram(self, datagram: RawDatagram) -> bool:
        return (
            isinstance(datagram, SSDPDatagram)
            and "BAMBULAB-COM" in datagram.content
            and datagram.dst_address == constants.SSDP_MCAST_ADDR
            and datagram.dst_port in BAMBU_SSDP_PORTS
        )

    def handle(self, datagram: UDPDatagram) -> UDPDatagram:
        if (
            datagram.src_port == constants.SSDP_MCAST_ADDR
            and datagram.dst_port in BAMBU_SSDP_PORTS
        ):
            for client in self._unique_waiting_clients():
                self.transmit(
                    datagram.with_different_dst(client.address, BAMBU_UNICAST_PORT)
                )
        elif (
            datagram.src_port != constants.SSDP_MCAST_PORT
            and datagram.dst_port in BAMBU_SSDP_PORTS
        ):
            self._enqueue(WaitingClient(datagram.src_address))

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
