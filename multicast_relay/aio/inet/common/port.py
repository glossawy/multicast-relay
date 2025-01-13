from ctypes import ArgumentError
from typing import NewType, overload
from ._allowed_ports import AllowablePorts

Port = NewType("Port", int)


@overload
def port(portNumber: AllowablePorts) -> Port: ...
@overload
def port(portNumber: int) -> Port: ...


def port(portNumber: AllowablePorts | int) -> Port:
    if portNumber in AllowablePorts:
        return Port(portNumber)
    else:
        raise ArgumentError(
            f'{portNumber} is not within the valid port range')
