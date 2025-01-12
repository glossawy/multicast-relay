import netifaces


class Netifaces:
    def __init__(self, ifNameStructLen):
        self.ifNameStructLen = ifNameStructLen

    @property
    def AF_LINK(self) -> int:
        return netifaces.AF_PACKET

    @property
    def AF_INET(self) -> int:
        return netifaces.AF_INET

    def interfaces(self):
        return netifaces.interfaces()

    def ifaddresses(self, interface: str):
        return netifaces.ifaddresses(interface)
