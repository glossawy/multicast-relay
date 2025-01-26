
from typing import Protocol, runtime_checkable

@runtime_checkable
class RuntimeCheckable(Protocol):
    _is_runtime_protocol: bool
