from dataclasses import dataclass
import errno
import logging
import socket
import struct
import sys
import time
import binascii
import re
import select
from typing import Iterable, Type, cast

from multicast_relay import constants
from multicast_relay.datagrams.mdns import MDNSDatagram
from multicast_relay.datagrams.ssdp import SSDPDatagram
from multicast_relay.datagrams.utilities import (
    calculate_ip_checksum,
    calculate_udp_checksum,
)
from multicast_relay.handlers.types import Handler
from multicast_relay.netifaces import Netifaces
from multicast_relay.crypto import Cipher
from multicast_relay.logging import Logger
from multicast_relay.datagrams.raw import RawDatagram, UDPDatagram
from multicast_relay.types import Receiver, RemoteAddr, SSDPQuerier, Transmitter


class PacketRelay:
    def __init__(
        self,
        interfaces: list[str],
        noTransmitInterfaces: list[str],
        ifFilter: dict[str, list[str]],
        waitForIP: bool,
        ttl: int,
        netifaces: Netifaces,
        oneInterface: bool,
        allowNonEther: bool,
        ssdpUnicastAddr: str,
        mdnsForceUnicast: bool,
        handlers: Iterable[Type[Handler]],
        masquerade: list[str],
        listen: list[str],
        remote: list[str],
        remotePort: str,
        remoteRetry: bool,
        noRemoteRelay: bool,
        aes: str,
        logger: Logger,
        noQueryInterfaces: list[str],
        noAdvertiseInterfaces: list[str],
    ):
        self.interfaces = interfaces
        self.handlers = [hdlcls(logger, self.transmit_datagram) for hdlcls in handlers]
        self.noTransmitInterfaces = noTransmitInterfaces or []
        self.noAdvertiseInterfaces = noAdvertiseInterfaces or []

        self.ifFilter = ifFilter
        self.ssdpUnicastAddr = ssdpUnicastAddr
        self.mdnsForceUnicast = mdnsForceUnicast
        self.wait = waitForIP
        self.ttl = ttl
        self.oneInterface = oneInterface
        self.allowNonEther = allowNonEther
        self.masquerade = masquerade or []

        self.nif = netifaces
        self.logger = logger

        self.transmitters: list[Transmitter] = []
        self.receivers: list[Receiver] = []
        self.receiverInterfaces: dict[Receiver, str] = {}
        self.etherAddrs: dict[str, bytes | None] = {}
        self.etherType = struct.pack("!H", 0x0800)
        self.udpMaxLength = 1458

        self.recentChecksums: list[int] = []

        self.bindings: set[tuple[str, int]] = set()

        self.listenAddr = []
        if listen:
            for addr in listen:
                components = addr.split("/")
                if len(components) == 1:
                    components.append("32")
                if not components[1].isdigit():
                    raise ValueError("--listen netmask is not an integer")
                if int(components[1]) not in range(0, 33):
                    raise ValueError("--listen netmask specifies an invalid netmask")
                self.listenAddr.append(components)

        self.listenSock = None
        if remote:
            self.remoteAddrs = list(
                map(
                    lambda remote: RemoteAddr(
                        addr=remote,
                        socket=None,
                        connecting=False,
                        connectFailure=None,
                    ),
                    remote,
                )
            )
        else:
            self.remoteAddrs = []
        self.remotePort = remotePort
        self.remoteRetry = remoteRetry
        self.noRemoteRelay = noRemoteRelay
        self.aes = Cipher(aes)

        self.remoteConnections: list[Receiver] = []

        self.noQueryInterfaces = noQueryInterfaces or []

        if self.listenAddr:
            self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listenSock.bind(("0.0.0.0", self.remotePort))
            self.listenSock.listen(0)
        elif self.remoteAddrs:
            self.connectRemotes()
        self.ip_mac_map = {}
        for interface in self.interfaces:
            (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)
            self.ip_mac_map[ip] = mac

    def connectRemotes(self):
        for remote in self.remoteAddrs:
            if remote.socket:
                continue

            # Attempt reconnection at most once every N seconds
            if (
                remote.connectFailure
                and remote.connectFailure > time.time() - self.remoteRetry
            ):
                return

            remoteConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remoteConnection.setblocking(False)
            self.logger.info("REMOTE: Connecting to remote %s" % remote.addr)
            remote.connecting = True
            try:
                remoteConnection.connect((remote.addr, self.remotePort))
            except socket.error as e:
                if e.errno == errno.EINPROGRESS:
                    remote.socket = remoteConnection
                else:
                    remote.connecting = False
                    remote.connectFailure = time.time()

    def removeConnection(self, s):
        if s in self.remoteConnections:
            self.remoteConnections.remove(s)
            return

        for remote in self.remoteAddrs:
            if remote.socket == s:
                remote.socket = None
                remote.connecting = False
                remote.connectFailure = time.time()

    def remoteSockets(self) -> list[socket.socket]:
        return self.remoteConnections + [
            remote.socket for remote in self.remoteAddrs if remote.socket is not None
        ]

    def addListener(self, addr, port, service):
        if self.isBroadcast(addr):
            self.etherAddrs[addr] = self.broadcastIpToMac(addr)
        elif self.isMulticast(addr):
            self.etherAddrs[addr] = self.multicastIpToMac(addr)
        else:
            # Unicast -- we don't know yet which IP we'll want to send to
            self.etherAddrs[addr] = None

        # Set up the receiving socket and corresponding IP and interface information.
        # One receiving socket is required per multicast address per interface.
        # For unicast and broadcast, we'll also create a socket per interface to
        # ensure we can determine the receiving interface.

        if self.isMulticast(addr):
            # For each interface, create a socket bound to that interface
            for interface in self.interfaces:
                (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)
                rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                mreq = struct.pack("4s4s", socket.inet_aton(addr), socket.inet_aton(ip))
                rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                rx.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8")
                )
                rx.bind((addr, port))
                self.receivers.append(rx)
                self.receiverInterfaces[rx] = (
                    ifname  # Associate the receiver with the interface
                )

                if interface not in self.noTransmitInterfaces:
                    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                    tx.bind((ifname, 0))

                    transmitter = Transmitter(
                        relay=Transmitter.Relay(addr, port),
                        interface=ifname,
                        addr=ip,
                        mac=mac,
                        netmask=netmask,
                        broadcast=broadcast,
                        socket=tx,
                        service=service,
                    )

                    self.transmitters.append(transmitter)

        elif self.isBroadcast(addr):
            # For broadcast, similar handling
            for interface in self.interfaces:
                (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)
                rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                rx.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8")
                )
                rx.bind(("0.0.0.0", port))
                self.receivers.append(rx)
                self.receiverInterfaces[rx] = (
                    ifname  # Associate the receiver with the interface
                )

                if interface not in self.noTransmitInterfaces:
                    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                    tx.bind((ifname, 0))

                    transmitter = Transmitter(
                        relay=Transmitter.Relay(broadcast, port),
                        interface=ifname,
                        addr=ip,
                        mac=mac,
                        netmask=netmask,
                        broadcast=broadcast,
                        socket=tx,
                        service=service,
                    )

                    self.transmitters.append(transmitter)

        else:
            # Unicast handling
            for interface in self.interfaces:
                (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)

                # Create a receiver socket per interface
                rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8")
                )
                rx.bind((addr, port))
                self.receivers.append(rx)
                self.receiverInterfaces[rx] = (
                    ifname  # Associate the receiver with the interface
                )

                if interface not in self.noTransmitInterfaces:
                    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                    tx.bind((ifname, 0))

                    transmitter = Transmitter(
                        relay=Transmitter.Relay(addr, port),
                        interface=ifname,
                        addr=ip,
                        mac=mac,
                        netmask=netmask,
                        broadcast=broadcast,
                        socket=tx,
                        service=service,
                    )

                    self.transmitters.append(transmitter)

        self.bindings.add((addr, port))

    @staticmethod
    def unicastIpToMac(ip: str, procNetArp: str | None = None) -> str | None:
        """
        Return the mac address (as a string) of ip
        If procNetArp is not None, then it will be used instead
        of reading /proc/net/arp (useful for unit tests).
        """
        if procNetArp:
            arpTable = procNetArp
        else:
            # The arp table should be fairly small -- read it all in one go
            with open("/proc/net/arp", "r", encoding="utf-8") as fd:
                arpTable = fd.read()

        # Format:
        # IP address       HW type     Flags       HW address            Mask     Device
        # 192.168.0.1      0x1         0x2         18:90:22:bf:3c:23     *        wlp2s0
        matches = re.findall(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s.*?\s(([a-fA-F\d]{1,2}:){5}[a-fA-F\d]{1,2})",
            arpTable,
        )

        # Create a dictionary:
        ip2mac: dict = dict([t[0:2] for t in matches])

        # Default to None if key not in dict
        return ip2mac.get(ip, None)

    def register_ip_checksum(self, checksum: int) -> None:
        self.recentChecksums.append(checksum)
        if len(self.recentChecksums) > 256:
            self.recentChecksums = self.recentChecksums[1:]

    @staticmethod
    def computeUDPChecksum(ipHeader: bytes, udpHeader: bytes, data: bytes) -> bytes:
        pseudoIPHeader = ipHeader[12:20] + struct.pack(
            "!BBH", 0, ipHeader[9], len(udpHeader) + len(data)
        )

        udpPacket = pseudoIPHeader + udpHeader[:6] + struct.pack("!H", 0) + data
        if len(udpPacket) % 2:
            udpPacket += struct.pack("!B", 0)

        # Recompute the UDP header checksum
        checksum = 0
        for i in range(0, len(udpPacket), 2):
            checksum += struct.unpack("!H", udpPacket[i : i + 2])[0]

        while checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        checksum = ~checksum & 0xFFFF
        return udpHeader[:6] + struct.pack("!H", checksum)

    def transmit_datagram(self, dgram: RawDatagram):
        tx = self.find_transmitter(dgram.dst_address)
        dst_mac = self.find_mac_addr(dgram.dst_address)

        if tx is None:
            self.logger.info(
                f"Skipping transmission to {dgram.dst_address}:{dgram.dst_port} since no transmitter was found."
            )
            return
        if dst_mac is None:
            self.logger.info(
                f"Cannot resolve a MAC address for {dgram.dst_address}:{dgram.dst_port}."
            )
            return

        if self.can_transmit_datagram(tx, dgram):
            self.logger.info(
                f"Datagram transmission relayed from {dgram.src_address}:{dgram.src_port} to {dgram.dst_address}:{dgram.dst_port} ({dst_mac}) via {tx.interface}/{tx.addr}"
            )
            self.transmitPacket(tx.socket, tx.mac, dst_mac, dgram.payload)

    def can_transmit_datagram(self, tx: Transmitter, dgram: RawDatagram):
        for net in self.ifFilter:
            (network, netmask) = net.split("/") if "/" in net else (net, "32")
            if (
                self.onNetwork(
                    dgram.src_address,
                    network,
                    self.cidrToNetmask(int(netmask)),
                )
                and tx.interface not in self.ifFilter[net]
            ):
                self.logger.info(
                    f"Dropping packet from {dgram.src_address}:{dgram.src_port} related to {tx.interface} due to ifFilters"
                )
                return False

        if dgram.src_address == self.ssdpUnicastAddr and not self.onNetwork(
            dgram.src_address, tx.addr, tx.netmask
        ):
            self.logger.info(
                f"Dropping packet from {dgram.src_address}:{dgram.src_port} for {tx.interface}, SSDP unicast not on network"
            )
            return False

        return True

    def find_mac_addr(self, addr: str) -> bytes | None:
        if addr in self.ip_mac_map:
            return self.ip_mac_map[addr]
        else:
            mac = PacketRelay.unicastIpToMac(addr)
            if mac:
                return binascii.unhexlify(mac.replace(":", ""))
            else:
                return None

    def find_transmitter(self, dst_addr: str) -> Transmitter | None:
        for tx in self.transmitters:
            if self.onNetwork(dst_addr, tx.addr, tx.netmask):
                return tx

        return None

    def transmitPacket(
        self,
        sock: socket.socket,
        srcMac: bytes,
        destMac: bytes,
        ipPacket: bytes,
    ) -> None:
        raw_dgram = UDPDatagram(ipPacket)

        dont_fragment = ipPacket[6]
        if not isinstance(dont_fragment, int):
            dont_fragment = ord(dont_fragment)
        dont_fragment = (dont_fragment & 0x40) >> 6

        udp_header = calculate_udp_checksum(raw_dgram.payload)

        for boundary in range(0, len(raw_dgram.udp_payload), self.udpMaxLength):
            data_fragment = raw_dgram.udp_payload[
                boundary : boundary + self.udpMaxLength
            ]
            total_len = len(raw_dgram.ip_header) + len(udp_header) + len(data_fragment)
            more_fragments = boundary + self.udpMaxLength < len(raw_dgram.udp_payload)

            flag_offset = boundary & 0x1FFF
            if more_fragments:
                flag_offset |= 0x2000
            elif dont_fragment:
                flag_offset |= 0x4000

            ip_header = (
                raw_dgram.ip_header[:2]
                + struct.pack("!H", total_len)
                + raw_dgram.ip_header[4:6]
                + struct.pack("!H", flag_offset)
                + raw_dgram.ip_header[8:]
            )

            ip_packet_fragment = calculate_ip_checksum(
                ip_header + udp_header + data_fragment
            )
            self.register_ip_checksum(RawDatagram(ip_packet_fragment).ip_checksum)

            try:
                if srcMac != binascii.unhexlify("00:00:00:00:00:00".replace(":", "")):
                    ether_packet = (
                        destMac + srcMac + self.etherType + ip_packet_fragment
                    )
                    sock.send(ether_packet)
                else:
                    sock.send(ip_packet_fragment)
            except Exception as e:
                if hasattr(e, "errno") and e.errno == errno.ENXIO:
                    raise
                else:
                    self.logger.info("Error sending packet: %s" % str(e))

    def match(self, addr: str, port: int) -> bool:
        return ((addr, port)) in self.bindings

    def getReceivingInterface(self, sock: socket.socket) -> str:
        return self.receiverInterfaces.get(sock, "unknown")

    def loop(self) -> None:
        # Record where the most recent SSDP searches came from, to relay unicast answers
        # Modified to store multiple recent SSDP search sources with timestamps
        recentSsdpSearchSrc: list[SSDPQuerier] = []
        while True:
            if self.remoteAddrs:
                self.connectRemotes()

            additionalListeners: list[Receiver] = []
            if self.listenSock:
                additionalListeners.append(self.listenSock)
            additionalListeners.extend(self.remoteSockets())

            try:
                (inputready, _, _) = select.select(
                    additionalListeners + self.receivers, [], [], 1
                )
            except KeyboardInterrupt:
                break
            for s in cast(list[Receiver], inputready):
                if s == self.listenSock:
                    (remoteConnection, remoteAddr) = s.accept()
                    if not len(
                        list(
                            filter(
                                lambda addr: PacketRelay.onNetwork(
                                    remoteAddr[0],
                                    addr[0],
                                    PacketRelay.cidrToNetmask(int(addr[1])),
                                ),
                                self.listenAddr,
                            )
                        )
                    ):
                        self.logger.info(
                            "Refusing connection from %s - not in %s"
                            % (remoteAddr[0], self.listenAddr)
                        )
                        remoteConnection.close()
                    else:
                        self.remoteConnections.append(remoteConnection)
                        self.logger.info(
                            "REMOTE: Accepted connection from %s" % remoteAddr[0]
                        )
                    continue
                else:
                    if s in self.remoteSockets():
                        receivingInterface = "remote"
                        s.setblocking(True)
                        try:
                            (data, _) = s.recvfrom(2, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info("REMOTE: Connection closed (%s)" % str(e))
                            self.removeConnection(s)
                            continue

                        if not data:
                            s.close()
                            self.logger.info("REMOTE: Connection closed")
                            self.removeConnection(s)
                            continue

                        size = struct.unpack("!H", data)[0]
                        try:
                            (packet, _) = s.recvfrom(size, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info("REMOTE: Connection closed (%s)" % str(e))
                            self.removeConnection(s)
                            continue

                        packet = self.aes.decrypt(packet)

                        magic = packet[: len(constants.MAGIC)]
                        addr = socket.inet_ntoa(
                            packet[
                                len(constants.MAGIC) : len(constants.MAGIC)
                                + constants.IPV4LEN
                            ]
                        )
                        data = packet[len(constants.MAGIC) + constants.IPV4LEN :]

                        if magic != constants.MAGIC:
                            self.logger.info(
                                "REMOTE: Garbage data received, closing connection."
                            )
                            s.close()
                            self.removeConnection(s)
                            continue

                    else:
                        (data, addr) = s.recvfrom(10240)
                        addr = addr[0]
                        receivingInterface = self.getReceivingInterface(s)

                    datagram = RawDatagram(data)

                    if self.ttl:
                        datagram = datagram.with_ttl(self.ttl)

                    # Use IP checksum information to see if we have already seen this
                    # packet, since once we have retransmitted it on an interface
                    # we know that we will see it once again on that interface.
                    if datagram.ip_checksum in self.recentChecksums:
                        continue

                    if receivingInterface != "remote" and not self.match(
                        datagram.dst_address, datagram.dst_port
                    ):
                        continue

                    if (
                        self.remoteSockets()
                        and not (receivingInterface == "remote" and self.noRemoteRelay)
                        and datagram.src_address != self.ssdpUnicastAddr
                    ):
                        packet = self.aes.encrypt(
                            constants.MAGIC + socket.inet_aton(addr) + data
                        )
                        for remoteConnection in self.remoteSockets():
                            if remoteConnection == s:
                                continue
                            try:
                                remoteConnection.sendall(
                                    struct.pack("!H", len(packet)) + packet
                                )

                                for remote in self.remoteAddrs:
                                    if (
                                        remote.socket == remoteConnection
                                        and remote.connecting
                                    ):
                                        self.logger.info(
                                            "REMOTE: Connection to %s established"
                                            % remote.addr
                                        )
                                        remote.connecting = False
                            except socket.error as e:
                                if e.errno == errno.EAGAIN:
                                    pass
                                else:
                                    self.logger.info(
                                        "REMOTE: Failed to connect to %s: %s"
                                        % (remote.addr, str(e))
                                    )
                                    self.removeConnection(remoteConnection)
                                    continue

                    orig_dgram = datagram
                    tx_dgram = orig_dgram
                    destMac = None

                    valid_handlers = [
                        handler
                        for handler in self.handlers
                        if handler.can_handle_datagram(tx_dgram)
                    ]

                    if len(valid_handlers) > 0:
                        tx_dgram = UDPDatagram(tx_dgram.payload)
                        for hdlr in valid_handlers:
                            hdlr.handle(tx_dgram)
                        continue
                    elif (
                        self.mdnsForceUnicast
                        and orig_dgram.dst_address == constants.MDNS_MCAST_ADDR
                        and orig_dgram.dst_port == constants.MDNS_MCAST_PORT
                    ):
                        tx_dgram = MDNSDatagram(tx_dgram.payload).with_unicast_bit()

                    # Handle SSDP M-SEARCH requests
                    elif (
                        self.ssdpUnicastAddr
                        and orig_dgram.dst_address == constants.SSDP_MCAST_ADDR
                        and orig_dgram.dst_port == constants.SSDP_MCAST_PORT
                    ):
                        tx_dgram = SSDPDatagram(tx_dgram.payload)

                        if tx_dgram.is_query:
                            # Append the source to recentSsdpSearchSrc
                            recentSsdpSearchSrc.append(
                                SSDPQuerier(
                                    addr=tx_dgram.src_address,
                                    port=tx_dgram.src_port,
                                    timestamp=time.time(),
                                )
                            )
                            # Remove entries older than 5 seconds
                            recentSsdpSearchSrc = [
                                entry
                                for entry in recentSsdpSearchSrc
                                if time.time() - entry.timestamp < 5
                            ]
                        self.logger.info(
                            "Recorded SSDP search source: %s:%d"
                            % (tx_dgram.src_address, tx_dgram.src_port)
                        )

                        # Modify the src IP and port
                        srcAddr = self.ssdpUnicastAddr
                        srcPort = constants.SSDP_UNICAST_PORT
                        tx_dgram = tx_dgram.with_different_src(
                            self.ssdpUnicastAddr, constants.SSDP_UNICAST_PORT
                        )

                        self.register_ip_checksum(tx_dgram.ip_checksum)
                    elif (
                        self.ssdpUnicastAddr
                        and tx_dgram.dst_address == self.ssdpUnicastAddr
                        and tx_dgram.dst_port == constants.SSDP_UNICAST_PORT
                    ):
                        # Remove entries older than 5 seconds
                        recentSsdpSearchSrc = [
                            entry
                            for entry in recentSsdpSearchSrc
                            if time.time() - entry.timestamp < 5
                        ]
                        if not recentSsdpSearchSrc:
                            # No recent SSDP searches
                            continue

                        # Relay the SSDP unicast response to all recent sources
                        for entry in recentSsdpSearchSrc:
                            self.logger.info(
                                "Relaying SSDP Unicast response to %s:%d"
                                % (entry.addr, entry.port)
                            )
                            tx_dgram = SSDPDatagram(
                                tx_dgram.payload
                            ).with_different_dst(entry.addr, entry.port)
                            self.register_ip_checksum(tx_dgram.ip_checksum)

                            # Resolve destMac for dstAddr
                            try:
                                if entry.addr in self.ip_mac_map:
                                    # Destination is router's own IP address
                                    destMac = self.ip_mac_map[entry.addr]
                                else:
                                    destMacAddr = PacketRelay.unicastIpToMac(entry.addr)
                                    if destMacAddr:
                                        destMac = binascii.unhexlify(
                                            destMacAddr.replace(":", "")
                                        )
                                    else:
                                        self.logger.info(
                                            "DEBUG: could not resolve mac for %s"
                                            % entry.addr
                                        )
                                        continue
                            except Exception as e:
                                self.logger.info(
                                    "DEBUG: exception while resolving mac of IP %s: %s"
                                    % (entry.addr, str(e))
                                )
                                continue

                            # Determine the appropriate transmitter (interface) to send the packet on
                            tx_found = False
                            for tx in self.transmitters:
                                if self.onNetwork(entry.addr, tx.addr, tx.netmask):
                                    # Found the transmitter corresponding to the network
                                    tx_found = True
                                    break
                            if not tx_found:
                                self.logger.info(
                                    "DEBUG: could not find transmitter for dstAddr %s"
                                    % entry.addr
                                )
                                continue

                            # Transmit the packet
                            try:
                                self.transmitPacket(
                                    tx.socket,
                                    tx.mac,
                                    destMac,
                                    tx_dgram.payload,
                                )
                                self.logger.info(
                                    "[SSDP Unicast] Relayed %s bytes from %s:%s on %s [ttl %s] to %s:%s via %s/%s"
                                    % (
                                        len(tx_dgram.payload),
                                        orig_dgram.src_address,
                                        orig_dgram.src_port,
                                        receivingInterface,
                                        tx_dgram.ttl,
                                        tx_dgram.dst_address,
                                        tx_dgram.dst_port,
                                        tx.interface,
                                        tx.addr,
                                    )
                                )
                            except Exception as e:
                                if hasattr(e, "errno") and e.errno == errno.ENXIO:
                                    try:
                                        (ifname, mac, ip, netmask, broadcast) = (
                                            self.getInterface(tx.interface)
                                        )
                                        s = socket.socket(
                                            socket.AF_PACKET, socket.SOCK_RAW
                                        )
                                        s.bind((ifname, 0))
                                        tx.mac = mac
                                        tx.netmask = netmask
                                        tx.addr = ip
                                        tx.socket = s
                                        self.transmitPacket(
                                            tx.socket,
                                            tx.mac,
                                            destMac,
                                            tx_dgram.payload,
                                        )
                                    except Exception as e:
                                        self.logger.info(
                                            "Error sending packet: %s" % str(e)
                                        )
                                else:
                                    self.logger.info(
                                        "Error sending packet: %s" % str(e)
                                    )
                                continue  # Skip to next entry in recentSsdpSearchSrc

                        # Skip the rest of the loop for this packet
                        continue

                    # Determine if the packet is a query from an interface we should not relay queries from

                    is_mdns_query = (
                        isinstance(tx_dgram, MDNSDatagram) and tx_dgram.is_mdns_query
                    )
                    is_ssdp_query = (
                        isinstance(tx_dgram, SSDPDatagram) and tx_dgram.is_query
                    )

                    if (
                        is_mdns_query or is_ssdp_query
                    ) and receivingInterface in self.noQueryInterfaces:
                        self.logger.info(
                            "Dropping query packet from interface %s"
                            % receivingInterface
                        )
                        continue

                    # Work out the name of the interface we received the packet on.
                    if receivingInterface != "remote":
                        pass  # receivingInterface already determined

                    for tx in self.transmitters:
                        # Re-transmit on all other interfaces than on the interface that we received this packet from...
                        if receivingInterface == tx.interface:
                            continue

                        # Check if the packet is an mDNS advertisement and should not be relayed to this interface
                        if (
                            isinstance(tx_dgram, MDNSDatagram)
                            and tx_dgram.is_mdns_announcement
                            and tx.interface in self.noAdvertiseInterfaces
                        ):
                            self.logger.info(
                                "Skipping mDNS advertisement relay to interface %s"
                                % tx.interface
                            )
                            continue

                        transmit = True
                        for net in self.ifFilter:
                            (network, netmask) = (
                                net.split("/") if "/" in net else (net, "32")
                            )
                            if (
                                self.onNetwork(
                                    tx_dgram.src_address,
                                    network,
                                    self.cidrToNetmask(int(netmask)),
                                )
                                and tx.interface not in self.ifFilter[net]
                            ):
                                self.logger.info(
                                    f"Dropping packet from {tx_dgram.src_address}:{tx_dgram.src_port} related to {tx.interface} due to ifFilters"
                                )
                                transmit = False
                                break
                        if not transmit:
                            continue

                        if (
                            tx_dgram.src_address == self.ssdpUnicastAddr
                            and not self.onNetwork(
                                tx_dgram.src_address, tx.addr, tx.netmask
                            )
                        ):
                            continue

                        if (
                            (
                                orig_dgram.dst_address == tx.relay.addr
                                or orig_dgram.dst_address == tx.broadcast
                            )
                            and orig_dgram.dst_port == tx.relay.port
                            and (
                                self.oneInterface
                                or not self.onNetwork(addr, tx.addr, tx.netmask)
                            )
                        ):
                            if destMac is None:
                                destMac = self.etherAddrs.get(
                                    tx_dgram.dst_address, None
                                )
                                if destMac is None:
                                    raise RuntimeError(
                                        f"Could not translate {tx_dgram.dst_address} to a MAC address"
                                    )

                            srcAddr = tx_dgram.src_address
                            srcPort = tx_dgram.src_port
                            if tx.interface in self.masquerade:
                                data = data[:12] + socket.inet_aton(tx.addr) + data[16:]
                                srcAddr = tx.addr
                            asSrc = (
                                ""
                                if srcAddr == orig_dgram.src_address
                                and srcPort == orig_dgram.src_port
                                else " (as %s:%s)" % (srcAddr, srcPort)
                            )
                            self.logger.info(
                                "%s%s %s byte%s from %s:%s on %s [ttl %s] to %s:%s via %s/%s%s"
                                % (
                                    tx.service and "[%s] " % tx.service or "",
                                    tx.interface in self.masquerade
                                    and "Masqueraded"
                                    or "Relayed",
                                    len(data),
                                    len(data) != 1 and "s" or "",
                                    orig_dgram.src_address,
                                    orig_dgram.src_port,
                                    receivingInterface,
                                    tx_dgram.ttl,
                                    tx_dgram.dst_address,
                                    tx_dgram.dst_port,
                                    tx.interface,
                                    tx.addr,
                                    asSrc,
                                )
                            )

                            try:
                                self.transmitPacket(
                                    tx.socket,
                                    tx.mac,
                                    destMac,
                                    tx_dgram.payload,
                                )
                            except Exception as e:
                                if hasattr(e, "errno") and e.errno == errno.ENXIO:
                                    try:
                                        (ifname, mac, ip, netmask, broadcast) = (
                                            self.getInterface(tx.interface)
                                        )
                                        s = socket.socket(
                                            socket.AF_PACKET, socket.SOCK_RAW
                                        )
                                        s.bind((ifname, 0))
                                        tx.mac = mac
                                        tx.netmask = netmask
                                        tx.addr = ip
                                        tx.socket = s
                                        self.transmitPacket(
                                            tx.socket,
                                            tx.mac,
                                            destMac,
                                            tx_dgram.payload,
                                        )
                                    except Exception as e:
                                        self.logger.info(
                                            "Error sending packet: %s" % str(e)
                                        )
                                else:
                                    self.logger.info(
                                        "Error sending packet: %s" % str(e)
                                    )
                                continue  # Skip to next transmitter

    def getInterface(self, interface: str) -> tuple[str, bytes, str, str, str]:
        ifname = None

        # See if we got an interface name.
        if interface in self.nif.interfaces():
            ifname = interface

        # Maybe we got an network/netmask combination?
        elif re.match(r"\A\d+\.\d+\.\d+\.\d+\Z", interface):
            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    if interface == addrs[self.nif.AF_INET][0]["addr"]:
                        ifname = i
                        break

        # Or perhaps we got an IP address?
        elif re.match(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", interface):
            (network, netmask) = interface.split("/")
            netmask = ".".join(
                [
                    str((0xFFFFFFFF << (32 - int(netmask)) >> i) & 0xFF)
                    for i in [24, 16, 8, 0]
                ]
            )

            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    ip = addrs[self.nif.AF_INET][0]["addr"]
                    if self.onNetwork(ip, network, netmask):
                        ifname = i
                        break

        if not ifname:
            raise IOError("Interface %s does not exist." % interface)

        try:
            # Here we want to make sure that an interface has an
            # IPv4 address - but if we are running at boot time
            # it might be that we don't yet have an address assigned.
            #
            # --wait doesn't make sense in the situation where we
            # look for an IP# or net/mask combination, of course.
            while True:
                addrs = self.nif.ifaddresses(ifname)
                if self.nif.AF_INET in addrs:
                    break
                if not self.wait:
                    print(
                        "Interface %s does not have an IPv4 address assigned." % ifname
                    )
                    sys.exit(1)
                self.logger.info("Waiting for IPv4 address on %s" % ifname)
                time.sleep(1)

            ip = addrs[self.nif.AF_INET][0]["addr"]
            netmask = addrs[self.nif.AF_INET][0]["netmask"]

            ipLong = PacketRelay.ip2long(ip)
            netmaskLong = PacketRelay.ip2long(netmask)
            broadcastLong = ipLong | (~netmaskLong & 0xFFFFFFFF)
            broadcast = PacketRelay.long2ip(broadcastLong)

            # If we've been given a virtual interface like eth0:0 then
            # netifaces might not be able to detect its MAC address so
            # lets at least try the parent interface and see if we can
            # find a MAC address there.
            if self.nif.AF_LINK not in addrs and ":" in ifname:
                addrs = self.nif.ifaddresses(ifname.split(":")[0])

            if self.nif.AF_LINK in addrs:
                mac = addrs[self.nif.AF_LINK][0]["addr"]
            elif self.allowNonEther:
                mac = "00:00:00:00:00:00"
            else:
                print("Unable to detect MAC address for interface %s." % ifname)
                sys.exit(1)

            # These functions all return a value in string format, but our
            # only use for a MAC address later is when we concoct a packet
            # to send, and at that point we need as binary data. Lets do
            # that conversion here.
            return (
                ifname,
                binascii.unhexlify(mac.replace(":", "")),
                ip,
                netmask,
                broadcast,
            )
        except Exception as e:
            print("Error getting information about interface %s." % ifname)
            print("Valid interfaces: %s" % " ".join(self.nif.interfaces()))
            self.logger.info(str(e))
            sys.exit(1)

    @staticmethod
    def isMulticast(ip: str) -> bool:
        """
        Is this IP address a multicast address?
        """
        ipLong = PacketRelay.ip2long(ip)
        return ipLong >= PacketRelay.ip2long(
            constants.MULTICAST_MIN
        ) and ipLong <= PacketRelay.ip2long(constants.MULTICAST_MAX)

    @staticmethod
    def isBroadcast(ip: str) -> bool:
        """
        Is this IP address a broadcast address?
        """
        return ip == constants.BROADCAST

    @staticmethod
    def ip2long(ip: str) -> int:
        """
        Given an IP address (or netmask) turn it into an unsigned long.
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    @staticmethod
    def long2ip(ip: int) -> str:
        """
        Given an unsigned long turn it into an IP address
        """
        return socket.inet_ntoa(struct.pack("!I", ip))

    @staticmethod
    def onNetwork(ip: str, network: str, netmask: str) -> bool:
        """
        Given an IP address and a network/netmask tuple, work out
        if that IP address is on that network.
        """
        ipL = PacketRelay.ip2long(ip)
        networkL = PacketRelay.ip2long(network)
        netmaskL = PacketRelay.ip2long(netmask)
        return (ipL & netmaskL) == (networkL & netmaskL)

    @staticmethod
    def multicastIpToMac(addr: str) -> bytes:
        # Compute the MAC address that we will use to send
        # packets out to. Multicast MACs are derived from
        # the multicast IP address.
        multicastMac = 0x01005E000000
        multicastMac |= PacketRelay.ip2long(addr) & 0x7FFFFF
        return struct.pack("!Q", multicastMac)[2:]

    @staticmethod
    def broadcastIpToMac(addr: str) -> bytes:
        broadcastMac = 0xFFFFFFFFFFFF
        return struct.pack("!Q", broadcastMac)[2:]

    @staticmethod
    def cidrToNetmask(bits: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << (32 - bits))))
