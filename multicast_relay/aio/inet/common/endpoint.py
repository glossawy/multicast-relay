from dataclasses import dataclass

from multicast_relay.aio.inet import InetAddress, Port


@dataclass(frozen=True)
class Endpoint:
    address: InetAddress
    port: Port
