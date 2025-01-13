from dataclasses import dataclass
import enum
import ipaddress
import struct
import typing


from .types import InetPacketCasting, RawData, InetAddress, CastablePacket_T


class InetHeaderFlags(enum.IntFlag):
    RESERVED = 0b001
    DONT_FRAGMENT = 0b010
    MORE_FRAGMENTS = 0b100


class InetHeader(typing.Protocol):
    @property
    def length(self) -> int: ...
    @property
    def total_length(self) -> int: ...
    @property
    def flags(self) -> InetHeaderFlags: ...
    @property
    def ttl(self) -> int: ...
    @property
    def checksum(self) -> int: ...
    @property
    def source_ip(self) -> InetAddress: ...
    @property
    def destination_ip(self) -> InetAddress: ...


@dataclass
class _IPHeader(InetHeader):
    content: RawData

    @property
    def length(self):
        return len(self.content)

    @property
    def total_length(self) -> int:
        return struct.unpack('!H', self.content[2:4])[0]

    @property
    def flags(self) -> InetHeaderFlags:
        bits = typing.cast(int, struct.unpack(
            'B', RawData([self.content[6]]))[0] & 0b111)

        return InetHeaderFlags(bits)

    @property
    def ttl(self) -> int:
        return struct.unpack('B', bytes([self.content[8]]))[0]

    @property
    def checksum(self) -> int:
        return struct.unpack('!H', self.content[10:12])[0]

    @property
    def source_ip(self) -> InetAddress:
        return ipaddress.ip_address(self.content[12:16])

    @property
    def destination_ip(self) -> InetAddress:
        return ipaddress.ip_address(self.content[16:20])


class InetPacket(InetPacketCasting, typing.Protocol):
    @staticmethod
    def parse(content: bytes) -> "InetPacket":
        return _InetPacket(content)

    @property
    def source_ip(self) -> InetAddress: ...
    @property
    def destination_ip(self) -> InetAddress: ...
    @property
    def ip_header(self) -> InetHeader: ...
    @property
    def payload(self) -> bytes: ...


@dataclass(frozen=True)
class _InetPacket(InetPacket):
    content: RawData

    @property
    def source_ip(self) -> InetAddress:
        return self.ip_header.source_ip

    @property
    def destination_ip(self) -> InetAddress:
        return self.ip_header.destination_ip

    @property
    def ip_header(self) -> _IPHeader:
        return _IPHeader(self[0:self._ip_header_length])

    @property
    def payload(self) -> bytes:
        return self.content[self._ip_header_length:]

    @property
    def _ip_header_length(self) -> int:
        # Bits 4 through 8 represent the IP Header Length, the number of 4 byte groupings that
        # make up the variable length header
        ihl_bits = (self[0] & 0x0F)
        return ihl_bits * 4

    def _slice_after_ip_header(self, from_byte: int, to_byte: int) -> RawData:
        return self.payload[
            self._ip_header_length + from_byte: self._ip_header_length + to_byte
        ]

    def __len__(self) -> int:
        return len(self.payload)

    @typing.overload
    def __getitem__(self, idx: int, /) -> int:
        ...

    @typing.overload
    def __getitem__(self, idx: slice, /) -> bytes:
        ...

    def __getitem__(self, idx: int | slice, /) -> int | bytes:
        if isinstance(idx, int):
            return self.payload[idx]
        else:
            return self.payload[idx]

    def into(self, target: type[CastablePacket_T]) -> CastablePacket_T | None:
        return target.derive_from_inet_packet(self)
