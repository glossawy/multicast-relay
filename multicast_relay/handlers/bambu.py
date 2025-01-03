from dataclasses import dataclass

from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Callable
from multicast_relay import constants
from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.datagrams.ssdp import SSDPDatagram
from multicast_relay.handlers.types import Handler


from multicast_relay.logging import Logger

BAMBU_NOTIFY_PORT = constants.SSDP_MCAST_PORT
BAMBU_SEARCH_PORT = 1990
BAMBU_ANSWER_PORT = 2021

MAX_WAIT_BEFORE_REMOVAL = timedelta(minutes=5)


@dataclass(eq=True, frozen=True)
class _WaitingClient:
    address: str


_waiting_list: OrderedDict[_WaitingClient, datetime] = OrderedDict()


class Bambu(Handler):
    identifier = "Bambu"

    def __init__(self, logger: Logger, transmit: Callable[[RawDatagram], None]) -> None:
        self.logger = logger
        self.transmit = transmit

    def register_additional_transmitters(self, register) -> None:
        register(constants.SSDP_MCAST_ADDR)

    @staticmethod
    def can_handle_datagram(datagram: RawDatagram) -> bool:
        return (
            "BAMBULAB-COM" in SSDPDatagram(datagram.payload).content
            and datagram.dst_address == constants.SSDP_MCAST_ADDR
        )

    def handle(self, datagram: UDPDatagram) -> UDPDatagram:
        if datagram.src_port == constants.SSDP_MCAST_PORT:
            if len(_waiting_list) == 0:
                self.logger.info(
                    f"[Bambu]: No waiting M-SEARCH requests, forwarding NOTIFY to {constants.SSDP_MCAST_ADDR}:{constants.SSDP_MCAST_PORT}"
                )
                self.transmit(
                    datagram.with_different_dst(
                        constants.SSDP_MCAST_ADDR, BAMBU_NOTIFY_PORT
                    )
                )
            else:
                for client in self._unique_waiting_clients():
                    tx_dgram = datagram.with_different_dst(
                        client.address, BAMBU_ANSWER_PORT
                    )

                    self.logger.info(
                        f"[Bambu]: Attempting to transmit to waiting client {client.address} at port {tx_dgram.dst_port} from {tx_dgram.src_address}:{tx_dgram.src_port}"
                    )

                    self.transmit(tx_dgram)
        elif datagram.src_port != constants.SSDP_MCAST_PORT:
            self._enqueue(datagram.src_address)
        else:
            self.logger.info(
                f"[Bambu]: Encountered {datagram.src_address}:{datagram.src_port} -> {datagram.dst_address}:{datagram.dst_port} and did nothing with it?"
            )

        return datagram

    def _unique_waiting_clients(self):
        while len(_waiting_list) > 0:
            (client, _) = _waiting_list.popitem()
            yield client

    def _enqueue(self, addr: str) -> None:
        client = _WaitingClient(addr)
        is_new = client not in _waiting_list

        _waiting_list[client] = datetime.now()
        if is_new:
            self.logger.info(f"[Bambu]: Enqueued waiting Bambu client for {addr}")

        self._clear_old_entries()

    def _clear_old_entries(self) -> None:
        earliest_allowed = self._earliest_allowed_start_wait_time()
        while len(_waiting_list) > 0:
            (client, waiting_since) = _waiting_list.popitem(last=False)

            if waiting_since >= earliest_allowed:
                _waiting_list[client] = waiting_since
                _waiting_list.move_to_end(client, last=False)
                break

    def _earliest_allowed_start_wait_time(self) -> datetime:
        return datetime.now() - MAX_WAIT_BEFORE_REMOVAL
