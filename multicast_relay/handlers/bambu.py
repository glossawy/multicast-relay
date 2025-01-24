from collections.abc import Callable
from dataclasses import dataclass

from datetime import datetime, timedelta
import os
from cachetools import TTLCache
from multicast_relay import constants
from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.datagrams.ssdp import SSDPDatagram
from multicast_relay.handlers.types import Handler


from multicast_relay.logging import Logger

BAMBU_NOTIFY_PORT = constants.SSDP_MCAST_PORT
BAMBU_SEARCH_PORT = 1990
BAMBU_ANSWER_PORT = 2021

MAX_WAIT_BEFORE_REMOVAL = timedelta(minutes=5)

VERY_VERBOSE = os.environ.get('VERY_VERBOSE_BAMBU_BUS', None) is not None


@dataclass(eq=True, frozen=True)
class _WaitingClient:
    address: str


_waiting_list: TTLCache[_WaitingClient, datetime] = TTLCache(maxsize=10, ttl=MAX_WAIT_BEFORE_REMOVAL.total_seconds())

class Bambu(Handler):
    identifier = "Bambu"

    def __init__(self, logger: Logger, transmit: Callable[[RawDatagram], None]) -> None:
        self.logger = logger
        self.transmit = transmit

    def register_additional_transmitters(self, register) -> None:
        register(constants.SSDP_MCAST_ADDR)

    @staticmethod
    def can_handle_datagram(logger: Logger, datagram: RawDatagram) -> bool:
        _waiting_list.expire()

        logger.info(f'[Bambu]: CHECK - Received {datagram.src_address}:{
                    datagram.src_port} destined for {datagram.dst_address}:{datagram.dst_port}')

        logger.info(
            '[Bambu]: CHECK - Attempting to interpret as SSDP message')

        ssdp_message = SSDPDatagram(datagram.payload)

        if VERY_VERBOSE:
            logger.info("[Bambu]: CHECK - SSDP Message Payload START")
            for line in ssdp_message.content.splitlines():
                logger.info(line)
            logger.info("[Bambu]: CHECK - SSDP Message Payload END")

        if "BAMBULAB-COM" not in ssdp_message.content:
            logger.info(
                '[Bambu]: CHECK - SSDP message missing magic text, ignoring')
            return False

        if datagram.dst_address != constants.SSDP_MCAST_ADDR:
            logger.info(
                f'[Bambu]: CHECK - Destination is not {
                    constants.SSDP_MCAST_ADDR} (SSDP MCAST), ignoring'
            )
            return False

        if VERY_VERBOSE:
            if datagram.src_port == constants.SSDP_MCAST_PORT:
                logger.info(f'[Bambu]: CHECK - source port is {constants.SSDP_MCAST_PORT} and destination address is {
                            constants.SSDP_MCAST_ADDR}, this seems like a NOTIFY message from a printer')
            else:
                logger.info(
                    '[Bambu]: CHECK - source port is random, seems likely to be M-SEARCH')

        logger.info(f'[Bambu]: CHECK - Accepting {datagram.src_address}:{
                    datagram.src_port} -> {datagram.dst_address}:{datagram.dst_port} for processing')
        return True

    def handle(self, datagram: UDPDatagram) -> UDPDatagram:
        if datagram.src_port == constants.SSDP_MCAST_PORT:
            if len(_waiting_list) == 0:
                self.logger.info(
                    f"[Bambu]: No waiting M-SEARCH requests, forwarding NOTIFY to {
                        constants.SSDP_MCAST_ADDR}:{constants.SSDP_MCAST_PORT}"
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
                        f"[Bambu]: Attempting to transmit to waiting client {client.address} at port {
                            tx_dgram.dst_port} from {tx_dgram.src_address}:{tx_dgram.src_port}"
                    )

                    self.transmit(tx_dgram)
        elif datagram.src_port != constants.SSDP_MCAST_PORT:
            self._enqueue(datagram.src_address)
        else:
            self.logger.info(
                f"[Bambu]: Encountered {datagram.src_address}:{
                    datagram.src_port} -> {datagram.dst_address}:{datagram.dst_port} and did nothing with it?"
            )
            _waiting_list.expire()

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
            self.logger.info(
                f"[Bambu]: Enqueued waiting Bambu client for {addr}")
