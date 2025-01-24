import socket
from typing import Literal, LiteralString, NamedTuple
from pypacker import pypacker

class _SpecialMacAddress[T: LiteralString](NamedTuple):
    as_str: T
    as_bytes: bytes

MAC_ADDR_UNKNOWN = MAC_ADDR_ZERO = _SpecialMacAddress(
    "00:00:00:00:00:00",
    b"\x00" * 6,
)

MULTICAST_MIN = "224.0.0.0"
MULTICAST_MAX = "239.255.255.255"
BROADCAST = "255.255.255.255"
SSDP_MCAST_ADDR = "239.255.255.250"
BAMBU_PORTS = [1990, 2021]
SSDP_MCAST_PORT = 1900

SSDP_UNICAST_PORT = 1901

MDNS_MCAST_ADDR = "224.0.0.251"
MDNS_MCAST_PORT = 5353

MAGIC = b"MRLY"

IPV4LEN = len(socket.inet_aton("0.0.0.0"))
