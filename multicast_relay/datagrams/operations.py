import socket
import struct
from typing import Generic, TypeVar, TYPE_CHECKING

from multicast_relay.datagrams.utilities import calculate_ip_checksum, overwrite_bytes

if TYPE_CHECKING:
    from .types import DatagramWrapper


Datagram_T = TypeVar("Datagram_T", bound="DatagramWrapper")


class OperationsMixin(Generic[Datagram_T]):
    def with_different_src(
        self: Datagram_T,
        new_src_address: str | None = None,
        new_src_port: int | None = None,
    ) -> Datagram_T:
        if new_src_address is None and new_src_port is None:
            return self

        new_src_address = (
            new_src_address if new_src_address is not None else self.src_address
        )
        new_src_port = new_src_port if new_src_port is not None else self.src_port

        return OperationsMixin[Datagram_T].with_set_src_and_dst(
            self, new_src_address, new_src_port, self.dst_address, self.dst_port
        )

    def with_different_dst(
        self: Datagram_T,
        new_dst_address: str | None = None,
        new_dst_port: int | None = None,
    ) -> Datagram_T:
        if new_dst_address is None and new_dst_port is None:
            return self

        new_dst_address = (
            new_dst_address if new_dst_address is not None else self.dst_address
        )
        new_dst_port = new_dst_port if new_dst_port is not None else self.dst_port

        return OperationsMixin[Datagram_T].with_set_src_and_dst(
            self, self.src_address, self.src_port, new_dst_address, new_dst_port
        )

    def with_overwritten_bytes(
        self: Datagram_T, at_byte: int, new_bytes: bytes
    ) -> Datagram_T:
        new_payload = (
            self.payload[:at_byte]
            + new_bytes
            + self.payload[at_byte + len(new_bytes) :]
        )

        return type(self)(new_payload)

    def with_set_src_and_dst(
        self: Datagram_T, src_addr: str, src_port: int, dst_addr: str, dst_port: int
    ) -> Datagram_T:
        ip_header_bytes = socket.inet_aton(src_addr) + socket.inet_aton(dst_addr)
        udp_header_bytes = struct.pack(
            "!4H", src_port, dst_port, self.payload_length, 0
        )

        new_payload = overwrite_bytes(
            self.payload, at_byte=12, new_bytes=ip_header_bytes
        )
        new_payload = overwrite_bytes(
            new_payload, at_byte=self.ip_header_length, new_bytes=udp_header_bytes
        )

        return type(self)(calculate_ip_checksum(new_payload))
