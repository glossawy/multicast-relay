import functools
import ipaddress
from dataclasses import dataclass
from typing import Literal, Never, NewType, TypeAlias, overload

import netifaces
from netifaces.defs import (
    Address as _NetifacesAddress,
)
from netifaces.defs import (
    AddressType as _NetifacesAddressType,
)
from netifaces.defs import (
    InterfaceType as _NetifacesIfType,
)

from multicast_relay.aio.layer2 import MacAddress

NetifacesEntry = dict[_NetifacesAddressType, _NetifacesAddress]
InterfaceName = NewType("InterfaceName", str)


class Interface:
    @dataclass(eq=True, frozen=True)
    class Addresses:
        ip4: ipaddress.IPv4Interface | None
        ip6: ipaddress.IPv6Interface | None
        mac: MacAddress | None

    name: InterfaceName

    Types = _NetifacesIfType
    _TranslatableLiterals: TypeAlias = (
        Literal[Types.AF_INET] | Literal[Types.AF_INET6] | Literal[Types.AF_PACKET]
    )

    def __init__(self, name: InterfaceName) -> None:
        self.name = name

    @functools.cached_property
    def addresses(self) -> "Interface.Addresses":
        return Interface.Addresses(
            ip4=self._first_address(as_type=Interface.Types.AF_INET),
            ip6=self._first_address(as_type=Interface.Types.AF_INET6),
            mac=self._first_address(as_type=Interface.Types.AF_PACKET),
        )

    @overload
    def all_addresses(
        self, as_type: Literal[Types.AF_INET]
    ) -> list[ipaddress.IPv4Interface]: ...

    @overload
    def all_addresses(
        self, as_type: Literal[Types.AF_INET6]
    ) -> list[ipaddress.IPv6Interface]: ...

    @overload
    def all_addresses(self, as_type: Literal[Types.AF_PACKET]) -> list[MacAddress]: ...

    def all_addresses(
        self, as_type: _TranslatableLiterals
    ) -> (
        list[MacAddress] | list[ipaddress.IPv4Interface] | list[ipaddress.IPv6Interface]
    ):
        entries = netifaces.ifaddresses(self.name).get(as_type, [])

        match as_type:
            case Interface.Types.AF_INET:
                return [
                    ipaddress.IPv4Interface((entry["addr"], entry["mask"]))
                    for entry in entries
                ]
            case Interface.Types.AF_INET6:
                # Mask = Prefix here
                return [
                    ipaddress.IPv6Interface((entry["addr"], entry["mask"]))
                    for entry in entries
                ]
            case Interface.Types.AF_PACKET:
                return [MacAddress(entry["addr"]) for entry in entries]

    @overload
    def _first_address(
        self, as_type: Literal[Types.AF_INET]
    ) -> ipaddress.IPv4Interface | None: ...

    @overload
    def _first_address(
        self, as_type: Literal[Types.AF_INET6]
    ) -> ipaddress.IPv6Interface | None: ...

    @overload
    def _first_address(
        self, as_type: Literal[Types.AF_PACKET]
    ) -> MacAddress | None: ...

    def _first_address(
        self, as_type: _TranslatableLiterals
    ) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface | MacAddress | Never | None:
        return self.all_addresses(as_type=as_type)[0]
