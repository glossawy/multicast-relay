import anyio
import anyio.streams
import trio
from trio import socket
import netaddr
from socket import IP_ADD_MEMBERSHIP, SO_BINDTODEVICE, SO_REUSEADDR, SOL_IP, SOL_SOCKET

# import socket
import netifaces
import rich.style
import rich.text
import typer

import rich
import rich.columns
import rich.constrain
from typing import Annotated, TypeAlias

from multicast_relay import constants
from multicast_relay.aio.inet import InetPacket, Interface, InterfaceName, UdpDatagram


app = typer.Typer(no_args_is_help=True)

interfaces_app = typer.Typer()
relay_app = typer.Typer()

AddressPair: TypeAlias = tuple[str, int]
SniffedPacket: TypeAlias = tuple[Interface, UdpDatagram]


# Source -> Drain -> Sink
# e.g. Bambu SSDP Source -> Bambu Handler -> Relay Sink (Sends out to all interfaces except source interface)
#      MDNS Source -> Query/Announcement

@interfaces_app.command("list")
def list_interfaces():
    available_interfaces = netifaces.interfaces()

    rich.print(
        rich.constrain.Constrain(
            rich.columns.Columns(
                sorted(available_interfaces),
                align="left",
                column_first=True,
                equal=True,
                width=20,
            ),
            width=100,
        )
    )


@interfaces_app.command("info")
def interface_info(interface: str):
    if interface not in netifaces.interfaces():
        rich.print(f"{interface} is not a valid interface.")
        raise typer.Exit(code=1)

    address_map = netifaces.ifaddresses(interface)

    rich.print(
        {
            "interface": interface,
            "addresses": {
                "AF_PACKET": address_map.get(netifaces.InterfaceType.AF_PACKET, []),
                "AF_INET": address_map.get(netifaces.InterfaceType.AF_INET, []),
                "AF_INET6": address_map.get(netifaces.InterfaceType.AF_INET6, []),
            },
        }
    )


async def start_multicast_sniffer(
    local_addr: AddressPair,
    interface: Interface,
    chan: trio.MemorySendChannel[SniffedPacket],
):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.setsockopt(
            SOL_IP,
            IP_ADD_MEMBERSHIP,
            socket.inet_aton(local_addr[0])
            + socket.inet_aton(str(interface.addresses.ip4)),
        )
        sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, interface.name.encode())

        await sock.bind(local_addr)

        while True:
            packet, (src_addr, src_port) = await sock.recvfrom(65535)
            inet_dgram = InetPacket.parse(packet).into(UdpDatagram)

            if inet_dgram is None:
                print(f"{src_addr}:{src_port} ({
                      interface.name}) => Received unexpected IP packet, could not interpret as UDP Datagram")
                continue

            print(
                f"{src_addr}:{src_port} ({interface.name}) => {inet_dgram.source_ip}:{
                    inet_dgram.source_port} -> {inet_dgram.destination_ip}:{inet_dgram.destination_port}"
            )

            await chan.send((interface, inet_dgram))


async def start_mock_traffic(local_addr: AddressPair, interface: Interface):
    async with await anyio.create_udp_socket(
        socket.AF_INET, local_host="127.0.0.1"
    ) as udp:
        while True:
            await udp.send(("This is a test message".encode(), local_addr))
            await anyio.sleep(5)


async def relay_between_interfaces(interfaces: list[Interface]):
    send, recv = trio.open_memory_channel[SniffedPacket](0)

    async with anyio.create_task_group() as tg:
        tg.start_soon(
            start_mock_traffic,
            (constants.SSDP_MCAST_ADDR, constants.SSDP_MCAST_PORT),
            interfaces[0],
        )

        for iface in interfaces:
            tg.start_soon(
                start_multicast_sniffer,
                (constants.SSDP_MCAST_ADDR, constants.SSDP_MCAST_PORT),
                iface,
                send.clone(),
            )

        async for interface, dgram in recv:
            print(f"{dgram.source_ip} -> {dgram.destination_ip} on {interface.name}")
            print(repr(dgram))
            print(dgram.data.decode())


def construct_interface(iface_name: str) -> Interface:
    if iface_name not in netifaces.interfaces():
        print(f"{iface_name} is not a valid interface.")

    address_map = netifaces.ifaddresses(iface_name)

    if len(address_map.get(Interface.Types.AF_INET, [])) == 0:
        print(
            f"{iface_name} is not a valid interface for relay, it does not have an ipv4 address."
        )
        raise typer.Exit(code=1)

    mac_addresses = address_map.get(Interface.Types.AF_PACKET, [])

    if len(mac_addresses) == 0:
        print(
            f"{iface_name} is not a valid interface for relay, it does not have a MAC address."
        )
        raise typer.Exit(code=1)
    else:
        try:
            netaddr.EUI(mac_addresses[0]["addr"])
        except ValueError as exc:
            print(
                f"{iface_name} is not a valid interface for relay, MAC address exists but cannot be parsed."
            )
            raise typer.Exit(code=1) from exc

    return Interface(InterfaceName(iface_name))


@relay_app.command()
def bambu(
    interface1: Annotated[Interface, typer.Argument(parser=construct_interface)],
    interface2: Annotated[Interface, typer.Argument(parser=construct_interface)],
    interfaces: Annotated[
        list[Interface] | None, typer.Argument(parser=construct_interface)
    ] = None,
):
    if interfaces is None:
        interfaces = []

    interfaces = [interface1, interface2, *interfaces]

    trio.run(relay_between_interfaces, interfaces)


if __name__ == "__main__":
    app.add_typer(interfaces_app, name="interface")
    app.add_typer(relay_app, name="relay")
    app()
