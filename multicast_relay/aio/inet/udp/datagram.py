from dataclasses import dataclass
import struct
from typing import Protocol
from multicast_relay.aio.inet import InetPacket, Port, RawData
from multicast_relay.aio.inet import port
from multicast_relay.aio.inet.types import InetCastable, InetTransported


class Datagram(InetCastable["Datagram"], InetTransported, Protocol):
    @classmethod
    def derive_from_inet_packet(cls, packet: InetPacket) -> "Datagram":
        return _UdpDatagram(wrapper=packet, content=packet.payload)

    @property
    def data_segment_length(self) -> int: ...
    @property
    def checksum(self) -> int: ...
    @property
    def data(self) -> RawData: ...


@dataclass(frozen=True)
class _UdpDatagram(Datagram):
    wrapper: InetPacket
    content: bytes

    @property
    def inet(self) -> InetPacket:
        return self.wrapper

    @property
    def source_port(self) -> Port:
        raw_value: int = struct.unpack('!H', self.content[0:2])[0]
        interpreted = port(raw_value)
        if interpreted is None:
            raise ValueError(
                f"UDP datagram should have a valid source port, but was #{raw_value}")

        return interpreted

    @property
    def destination_port(self) -> Port:
        raw_value: int = struct.unpack('!H', self.content[2:4])[0]
        interpreted = port(raw_value)
        if interpreted is None:
            raise ValueError(
                f"UDP datagram should have a valid destination port, but was #{raw_value}")

        return interpreted

    @property
    def data_segment_length(self) -> int:
        return struct.unpack('!H', self.content[4:6])[0]

    @property
    def checksum(self) -> int:
        return struct.unpack('!H', self.content[6:8])[0]

    @property
    def data(self) -> RawData:
        return self.content[8:8+self.data_segment_length]
