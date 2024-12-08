

import collections
import collections.abc
from dataclasses import dataclass
import enum
import ipaddress
import struct
import typing

import trio


class _IPHeaderFlags(enum.IntFlag):
    RESERVED = 0b001
    DONT_FRAGMENT = 0b010
    MORE_FRAGMENTS = 0b100


@dataclass
class _IPHeader:
    content: bytes

    @property
    def length(self):
        return len(self.content)

    @property
    def total_length(self) -> int:
        return struct.unpack('!H', self.content[2:4])[0]

    @property
    def flags(self) -> _IPHeaderFlags:
        bits = typing.cast(int, struct.unpack(
            'B', bytes([self.content[6]]))[0] & 0b111)

        return _IPHeaderFlags(bits)

    @property
    def ttl(self) -> int:
        return struct.unpack('B', bytes([self.content[8]]))[0]

    @property
    def checksum(self) -> int:
        return struct.unpack('!H', self.content[10:12])[0]

    @property
    def src_address(self) -> str:
        return trio.socket.inet_ntoa(self.content[12:16])

    @property
    def dst_address(self) -> str:
        return trio.socket.inet_ntoa(self.content[16:20])


@dataclass
class _UDPDatagram:
    content: bytes

    @property
    def src_port(self) -> int:
        return struct.unpack('!H', self.content[0:2])[0]

    @property
    def dst_port(self) -> int:
        return struct.unpack('!H', self.content[2:4])[0]

    @property
    def data_segment_length(self) -> int:
        return struct.unpack('!H', self.content[4:6])[0]

    @property
    def checksum(self) -> int:
        return struct.unpack('!H', self.content[6:8])[0]

    @property
    def data(self) -> bytes:
        return self.content[8:8+self.data_segment_length]


@dataclass(frozen=True)
class InetUdpPacket(collections.abc.Sequence):
    payload: bytes

    @property
    def src_ip(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(f'{self.ip_header.src_address}')

    @property
    def dst_ip(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(f'{self.ip_header.dst_address}')

    @property
    def src_port(self) -> int:
        return self.udp_datagram.src_port

    @property
    def dst_port(self) -> int:
        return self.udp_datagram.dst_port

    @property
    def ip_header(self) -> _IPHeader:
        return _IPHeader(self[0:self._ip_header_length])

    @property
    def udp_datagram(self) -> _UDPDatagram:
        len(self.payload)
        return _UDPDatagram(self[self._ip_header_length:])

    @property
    def _ip_header_length(self) -> int:
        # Bits 4 through 8 represent the IP Header Length, the number of 4 byte groupings that
        # make up the variable length header
        ihl_bits = (self[0] & 0x0F)
        return ihl_bits * 4

    def _slice_after_ip_header(self, from_byte: int, to_byte: int) -> bytes:
        return self.payload[
            self._ip_header_length + from_byte: self._ip_header_length + to_byte
        ]

    def __len__(self) -> int:
        return len(self.payload)

    @typing.overload
    def __getitem__(self, idx: int) -> int:
        ...

    @typing.overload
    def __getitem__(self, idx: slice) -> bytes:
        ...

    def __getitem__(self, idx: int | slice) -> int | bytes:
        if isinstance(idx, int):
            return self.payload[idx]
        else:
            return self.payload[idx]
