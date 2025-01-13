from typing import Generic, Protocol, TypeAlias, TypeVar, Any

import ipaddress

from multicast_relay.aio.inet import Endpoint, InetPacket, Port

InetAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
RawData: TypeAlias = bytes


Packet_Tco = TypeVar("Packet_Tco", bound="InetEmbedded", covariant=True)
CastablePacket_T = TypeVar(
    "CastablePacket_T", bound="InetCastable[Any]")


class InetCastable(Protocol, Generic[Packet_Tco]):
    @classmethod
    def derive_from_inet_packet(cls, packet: InetPacket) -> Packet_Tco: ...


class InetEmbedded(Protocol):
    @property
    def inet(self) -> InetPacket: ...

    @property
    def source_ip(self) -> InetAddress:
        return self.inet.source_ip

    @property
    def destination_ip(self) -> InetAddress:
        return self.inet.destination_ip


class PortProvider(Protocol):
    @property
    def source_port(self) -> Port: ...
    @property
    def destination_port(self) -> Port: ...


class InetTransported(InetEmbedded, PortProvider, Protocol):
    @property
    def source_endpoint(self) -> Endpoint:
        return Endpoint(self.source_ip, self.source_port)

    @property
    def destination_endpoint(self) -> Endpoint:
        return Endpoint(self.destination_ip, self.destination_port)


class InetPacketCasting(Protocol):
    def into(
        self, target: type[CastablePacket_T]) -> CastablePacket_T | None: ...
