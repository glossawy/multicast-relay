def stringify_udp_data(ip_header_length: int, udp_data: bytes) -> str:
    return udp_data[ip_header_length + 8 :].decode("utf-8").upper()
