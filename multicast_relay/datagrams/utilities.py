import struct


def overwrite_bytes(payload: bytes, at_byte: int, new_bytes: bytes) -> bytes:
    return payload[:at_byte] + new_bytes + payload[at_byte + len(new_bytes) :]


def calculate_header_payload_lengths(payload: bytes) -> tuple[int, int]:
    byte_buffer = bytes([payload[0]])
    ip_header_len = (struct.unpack("B", byte_buffer)[0] & 0x0F) * 4

    return ip_header_len, len(payload) - ip_header_len


def calculate_ip_checksum(payload: bytes) -> bytes:
    # Zero out current checksum
    ip_header_length, _ = calculate_header_payload_lengths(payload)
    data = overwrite_bytes(payload, at_byte=10, new_bytes=struct.pack("!H", 0))

    # Recompute the IP header checksum
    checksum = 0
    for i in range(0, ip_header_length, 2):
        checksum += struct.unpack("!H", data[i : i + 2])[0]

    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF
    data = data[:10] + struct.pack("!H", checksum) + data[12:]

    return data


def calculate_udp_checksum(payload: bytes) -> bytes:
    ip_header_length, _ = calculate_header_payload_lengths(payload)

    ip_header = payload[:ip_header_length]
    udp_header = payload[ip_header_length : ip_header_length + 8]
    udp_body = payload[ip_header_length + 8 :]

    pseudoIPHeader = ip_header[12:20] + struct.pack(
        "!BBH", 0, ip_header[9], len(udp_header) + len(udp_body)
    )

    udp_packet = pseudoIPHeader + udp_header[:6] + struct.pack("!H", 0) + udp_body
    if len(udp_packet) % 2:
        udp_packet += struct.pack("!B", 0)

    # Recompute the UDP header checksum
    checksum = 0
    for i in range(0, len(udp_packet), 2):
        checksum += struct.unpack("!H", udp_packet[i : i + 2])[0]

    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF
    return udp_header[:6] + struct.pack("!H", checksum)
