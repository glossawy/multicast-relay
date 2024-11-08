import struct
from multicast_relay import constants
from multicast_relay.datagrams.operations import OperationsMixin
from multicast_relay.datagrams.raw import RawDatagram


class MDNSDatagram(RawDatagram, OperationsMixin["MDNSDatagram"]):
    @property
    def dns_header(self) -> bytes:
        return self._slice_from_ip_header(8, 20)

    def with_unicast_bit(self):
        udp_payload = self.payload[self.ip_header_length + 8 :]

        flags = struct.unpack("!H", udp_payload[2:4])[0]
        if flags & 0x8000 != 0:
            return MDNSDatagram(self.payload)

        # Set the unicast response bit
        flags |= 0x8000
        return self.with_overwritten_bytes(
            # flags are the 3rd and 4th bytes after the header
            self.ip_header_length + 8 + 2,
            struct.pack("!H", flags),
        )

    @property
    def is_mdns_query(self) -> bool:
        # mDNS uses UDP port 5353
        if self.dst_port != constants.MDNS_MCAST_PORT:
            return False  # Not mDNS packet

        flags = struct.unpack("!H", self.dns_header[2:4])[0]
        qr = (flags >> 15) & 0x1  # QR bit is the highest bit

        return qr == 0  # Return True if it's a query

    @property
    def is_mdns_announcement(self) -> bool:
        # mDNS uses UDP port 5353
        if self.dst_port != constants.MDNS_MCAST_PORT:
            return False  # Not mDNS packet

        flags = struct.unpack("!H", self.dns_header[2:4])[0]
        qr = (flags >> 15) & 0x1  # QR bit is the highest bit

        return qr == 1  # Return True if it's an advertisement (response)
