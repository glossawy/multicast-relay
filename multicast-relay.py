#!/usr/bin/env python

import argparse
import http.server
import os
import sys
import threading
from typing import Type

from multicast_relay import constants
from multicast_relay.handlers import bambu
from multicast_relay.handlers.types import Handler
from multicast_relay.netifaces import Netifaces
from multicast_relay.relay import PacketRelay
from multicast_relay.logging import Logger

# Al Smith <ajs@aeschi.eu> January 2018
# https://github.com/alsmith/multicast-relay

# {
#     "relay": {"addr": "239.255.255.250", "port": 1900},
#     "interface": "br3",
#     "addr": "192.168.3.1",
#     "mac": b"*pNe\x0c,",
#     "netmask": "255.255.255.0",
#     "broadcast": "192.168.3.255",
#     "service": "SSDP",
# }


class K8sCheck(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("OK", "utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--interfaces",
        nargs="+",
        required=True,
        help="Relay between these interfaces (minimum 2).",
    )
    parser.add_argument(
        "--noTransmitInterfaces",
        nargs="+",
        help="Do not relay packets via these interfaces, listen only.",
    )
    parser.add_argument(
        "--noQueryInterfaces",
        nargs="+",
        help="Interfaces from which queries (mDNS and SSDP) should not be relayed.",
    )
    parser.add_argument(
        "--ifFilter",
        help="JSON file specifying which interface(s) a particular source IP can relay to.",
    )
    parser.add_argument(
        "--ssdpUnicastAddr",
        help="IP address to listen to SSDP unicast replies, which will be"
        " relayed to the IP that sent the SSDP multicast query.",
    )
    parser.add_argument(
        "--oneInterface",
        action="store_true",
        help="Slightly dangerous: only one interface exists, connected to two networks.",
    )
    parser.add_argument(
        "--relay", nargs="*", help="Relay additional multicast address(es)."
    )
    parser.add_argument(
        "--noMDNS", action="store_true", help="Do not relay mDNS packets."
    )
    parser.add_argument(
        "--mdnsForceUnicast",
        action="store_true",
        help="Force mDNS packets to have the UNICAST-RESPONSE bit set.",
    )
    parser.add_argument(
        "--noSSDP", action="store_true", help="Do not relay SSDP packets."
    )
    parser.add_argument(
        "--noBambuDiscovery",
        action="store_true",
        help="Do not relay Bambu Lab 3D Printer discovery packets.",
    )
    parser.add_argument(
        "--noSonosDiscovery",
        action="store_true",
        help="Do not relay broadcast Sonos discovery packets.",
    )
    parser.add_argument(
        "--homebrewNetifaces",
        action="store_true",
        help="Use self-contained netifaces-like package.",
    )
    parser.add_argument(
        "--ifNameStructLen",
        type=int,
        default=40,
        help="Help the self-contained netifaces work out its ifName struct length.",
    )
    parser.add_argument(
        "--allowNonEther",
        action="store_true",
        help="Allow non-ethernet interfaces to be configured.",
    )
    parser.add_argument(
        "--masquerade",
        nargs="+",
        help="Masquerade outbound packets from these interface(s).",
    )
    parser.add_argument(
        "--wait", action="store_true", help="Wait for IPv4 address assignment."
    )
    parser.add_argument("--ttl", type=int, help="Set TTL on outbound packets.")
    parser.add_argument(
        "--listen",
        nargs="+",
        help="Listen for a remote connection from one or more remote addresses A.B.C.D.",
    )
    parser.add_argument(
        "--remote",
        nargs="+",
        help="Relay packets to remote multicast-relay(s) on A.B.C.D.",
    )
    parser.add_argument(
        "--remotePort",
        type=int,
        default=1900,
        help="Use this port to listen/connect to.",
    )
    parser.add_argument(
        "--remoteRetry",
        type=int,
        default=5,
        help="If the remote connection is terminated, retry at least N seconds later.",
    )
    parser.add_argument(
        "--noRemoteRelay",
        action="store_true",
        help="Only relay packets on local interfaces: don't relay packets out of --remote connected relays.",
    )
    parser.add_argument(
        "--aes", help="Encryption key for the connection to the remote multicast-relay."
    )
    parser.add_argument(
        "--k8sport",
        type=int,
        help="Run k8s liveness/readiness server on the given port.",
    )
    parser.add_argument("--foreground", action="store_true", help="Do not background.")
    parser.add_argument("--logfile", help="Save logs to this file.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument(
        "--noAdvertiseInterfaces",
        nargs="+",
        help="Interfaces to which mDNS advertisements should not be relayed.",
    )

    args = parser.parse_args()

    if (
        len(args.interfaces) < 2
        and not args.oneInterface
        and not args.listen
        and not args.remote
    ):
        print("You should specify at least two interfaces to relay between")
        return 1

    if args.remote and args.listen:
        print(
            "Relay role should be either --listen or --remote (or neither) but not both"
        )
        return 1

    if args.ttl and (args.ttl < 0 or args.ttl > 255):
        print("Invalid TTL (must be between 1 and 255)")
        return 1

    if not args.foreground:
        pid = os.fork()
        if pid != 0:
            return 0
        os.setsid()
        os.close(sys.stdin.fileno())

    logger = Logger(args.foreground, args.logfile, args.verbose)

    handlers: set[Type[Handler]] = set()
    relays = set()
    if not args.noMDNS:
        relays.add(
            (
                "%s:%d" % (constants.MDNS_MCAST_ADDR, constants.MDNS_MCAST_PORT),
                "mDNS",
            )
        )
    if not args.noSSDP:
        relays.add(
            (
                "%s:%d" % (constants.SSDP_MCAST_ADDR, constants.SSDP_MCAST_PORT),
                "SSDP",
            )
        )
    if not args.noBambuDiscovery:
        for port in [constants.SSDP_MCAST_PORT, *constants.BAMBU_PORTS]:
            if port != 1900 or args.noSSDP:
                relays.add((f"{constants.SSDP_MCAST_ADDR}:{port}", "Bambu Labs"))
        handlers.add(bambu.Bambu)
    if not args.noSonosDiscovery:
        relays.add(("%s:%d" % (constants.BROADCAST, 1900), "Sonos Discovery"))
        relays.add(("%s:%d" % (constants.BROADCAST, 6969), "Sonos Setup Discovery"))

    if args.ssdpUnicastAddr:
        relays.add(
            (
                "%s:%d" % (args.ssdpUnicastAddr, constants.SSDP_UNICAST_PORT),
                "SSDP Unicast",
            )
        )

    if args.relay:
        for relay in args.relay:
            relays.add((relay, None))

    packetRelay = PacketRelay(
        interfaces=args.interfaces,
        noTransmitInterfaces=args.noTransmitInterfaces,
        ifFilter=args.ifFilter,
        waitForIP=args.wait,
        ttl=args.ttl,
        handlers=handlers,
        oneInterface=args.oneInterface,
        netifaces=Netifaces(ifNameStructLen=args.ifNameStructLen),
        allowNonEther=args.allowNonEther,
        ssdpUnicastAddr=args.ssdpUnicastAddr,
        mdnsForceUnicast=args.mdnsForceUnicast,
        masquerade=args.masquerade,
        listen=args.listen,
        remote=args.remote,
        remotePort=args.remotePort,
        remoteRetry=args.remoteRetry,
        noRemoteRelay=args.noRemoteRelay,
        aes=args.aes,
        logger=logger,
        noQueryInterfaces=args.noQueryInterfaces,
        noAdvertiseInterfaces=args.noAdvertiseInterfaces,
    )

    for relay in relays:
        try:
            (addr, port) = relay[0].split(":")
            _ = PacketRelay.ip2long(addr)
            port = int(port)
        except Exception:
            errorMessage = (
                "%s:%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast or broadcast IP address and P is a valid port number"
                % relay
            )
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if PacketRelay.isMulticast(addr):
            relayType = "multicast"
        elif PacketRelay.isBroadcast(addr):
            relayType = "broadcast"
        elif args.ssdpUnicastAddr:
            relayType = "unicast"
        else:
            errorMessage = (
                "IP address %s is neither a multicast nor a broadcast address" % addr
            )
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if port < 0 or port > 65535:
            errorMessage = "UDP port %s out of range" % port
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        logger.info(
            "Adding %s relay for %s:%s%s"
            % (relayType, addr, port, relay[1] and " (%s)" % relay[1] or "")
        )
        packetRelay.addListener(addr, port, relay[1])

    if args.k8sport:
        webServer = http.server.HTTPServer(("0.0.0.0", args.k8sport), K8sCheck)
        threading.Thread(target=webServer.serve_forever, daemon=True).start()

    packetRelay.loop()


if __name__ == "__main__":
    sys.exit(main())
