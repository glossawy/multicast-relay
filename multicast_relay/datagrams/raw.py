import socket
import struct

from multicast_relay.datagrams.operations import OperationsMixin
from multicast_relay.datagrams.types import DatagramWrapper


class RawDatagram(DatagramWrapper):
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    @property
    def payload(self) -> bytes:
        return self._payload

    @property
    def ttl(self):
        return struct.unpack("B", bytes([self.payload[8]]))[0]

    def with_ttl(self, new_ttl: int):
        return RawDatagram(
            self._replace_bytes(at=8, new_bytes=struct.pack("B", new_ttl))
        )

    @property
    def ip_checksum(self) -> int:
        return struct.unpack("!H", self.payload[10:12])[0]

    @property
    def ip_header_length(self) -> int:
        byte_buffer = bytes([self.payload[0]])
        return (struct.unpack("B", byte_buffer)[0] & 0x0F) * 4

    @property
    def payload_length(self) -> int:
        return len(self.payload) - self.ip_header_length

    @property
    def src_address(self) -> str:
        return socket.inet_ntoa(self.payload[12:16])

    @property
    def src_port(self) -> int:
        return struct.unpack("!H", self._slice_from_ip_header(0, 2))[0]

    @property
    def dst_address(self) -> str:
        return socket.inet_ntoa(self.payload[16:20])

    @property
    def dst_port(self) -> int:
        return struct.unpack("!H", self._slice_from_ip_header(2, 4))[0]

    @property
    def ip_header(self) -> bytes:
        return self.payload[: self.ip_header_length]

    @property
    def udp_header(self) -> bytes:
        return self.payload[self.ip_header_length : self.ip_header_length + 8]

    @property
    def udp_payload(self) -> bytes:
        return self.payload[self.ip_header_length + 8 :]

    def _replace_bytes(self, at: int, new_bytes: bytes, span: int = 1) -> bytes:
        return self.payload[:at] + new_bytes + self.payload[at + span :]

    def _slice_from_ip_header(self, from_byte: int, to_byte: int) -> bytes:
        return self.payload[
            self.ip_header_length + from_byte : self.ip_header_length + to_byte
        ]


class UDPDatagram(RawDatagram, OperationsMixin["UDPDatagram"]):
    pass
