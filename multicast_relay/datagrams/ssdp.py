from multicast_relay.datagrams.operations import OperationsMixin
from multicast_relay.datagrams.raw import RawDatagram


class SSDPDatagram(RawDatagram, OperationsMixin["SSDPDatagram"]):
    @property
    def content(self) -> str:
        return self.payload[self.ip_header_length + 8 :].decode("utf-8").upper()

    @property
    def is_query(self) -> bool:
        return "M-SEARCH" in self.content

    @property
    def is_notify(self) -> bool:
        return "NOTIFY" in self.content
