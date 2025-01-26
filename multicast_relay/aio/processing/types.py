from collections.abc import AsyncGenerator, AsyncIterable, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, Self, TypeGuard, cast

import anyio

from multicast_relay.aio.inet import Interface


class Produceable[ValueType](Protocol):
    type DeriveableTo[I, O] = tuple[Produceable[I], Produceable[O]]

    @classmethod
    def __unwrap_deriveable[I, O](
        cls: type["Produceable[O]"],
        _self: "Produceable[O]",
        value: "DeriveableTo[I, O]",
    ) -> tuple["Produceable[I]", "Produceable[O]"]:
        return cast(Produceable[I], value), _self

    @classmethod
    def deriveable_from[IV](
        cls, target: "Produceable[IV]"
    ) -> TypeGuard[DeriveableTo[IV, ValueType]]: ...
    @classmethod
    def derive_from[I, O](cls, value: DeriveableTo[I, O]) -> Self: ...

    def into[V](self, check: type["Produceable[V]"]) -> "Produceable[V] | None":
        if (
            issubclass(check, Protocol)
            and getattr(check, "_is_runtime_protocol", False)
            and not isinstance(self, check)
        ):
            # Either it matches the protocol
            return None

        # Or it is the type
        if type(self) is check:
            return cast(Produceable[V], self)

        # Or it can be runtime converted to the type
        if check.deriveable_from(self):
            return check.derive_from(self)
        else:
            return None


class Producer[Produceable_T: Produceable[Any]](Protocol):
    @property
    def interface(self) -> Interface: ...

    def run(self) -> AsyncGenerator[Produceable_T]: ...


type StreamMapper[I: Produceable[Any], O: Produceable[Any]] = Callable[
    [AsyncIterable[I]], AsyncIterable[O]
]
type StreamFilter[I: Produceable[Any]] = StreamMapper[I, I]
type StreamTerminator[I: Produceable[Any], O: Any] = Callable[[I], O]
type PreparedStream[I: Produceable[Any], O: Any] = Callable[
    [AsyncIterable[I]], AsyncIterable[O]
]


class StreamOperator[I: Produceable[Any], O: Produceable[Any]](Protocol):
    def __call__(self, ins: AsyncIterable[I]) -> AsyncIterable[O]: ...

    def then[O2: Produceable[Any]](
        self, step: "StreamOperator[O, O2]"
    ) -> "StreamOperator[I, O2]":
        return CombinedStreamOperator(self, step)

    @property
    def and_then(self) -> "FluentStreamOperator[I, O]":
        return FluentStreamOperator(self)

    def finish[O2](
        self, end: StreamTerminator[O, O2] = lambda i: i
    ) -> PreparedStream[I, O2]:
        async def finished(ait):
            async for v in self(ait):
                yield end(v)

        return finished


@dataclass(frozen=True)
class CombinedStreamOperator[
    I: Produceable[Any],
    O: Produceable[Any],
    O2: Produceable[Any],
](StreamOperator[I, O2]):
    step: StreamOperator[I, O]
    next_step: StreamOperator[O, O2]

    def __call__(self, ins: AsyncIterable[I]) -> AsyncIterable[O2]:
        return self.next_step(self.step(ins))


@dataclass(frozen=True)
class FunctionStreamOperator[I: Produceable[Any], O: Produceable[Any]](
    StreamOperator[I, O]
):
    operation: Callable[[I], Awaitable[O]]

    def __call__(self, ins: AsyncIterable[I]) -> AsyncIterable[O]:
        async def wrapper():
            async for v in ins:
                yield await self.operation(v)

        return wrapper()


@dataclass(frozen=True)
class PredicateStreamOperator[I: Produceable[Any]](StreamOperator[I, I]):
    predicate: Callable[[I], Awaitable[bool]]

    def __call__(self, ins: AsyncIterable[I]) -> AsyncIterable[I]:
        async def wrapper():
            async for v in ins:
                if await self.predicate(v):
                    yield v

        return wrapper()


@dataclass(frozen=True)
class BranchStreamOperator[I: Produceable[Any], A: Any, B: Any](
    StreamOperator[I, A | B]
):
    predicate: Callable[[I], Awaitable[bool]]
    if_true: PreparedStream[I, A]
    if_false: PreparedStream[I, B]

    def __call__(self, ins: AsyncIterable[I]) -> AsyncIterable[A | B]:
        snd_true, rcv_true = anyio.create_memory_object_stream()
        snd_false, rcv_false = anyio.create_memory_object_stream()

        snd_out, rcv_out = anyio.create_memory_object_stream[A | B]()

        async def wrapper():
            async with anyio.create_task_group() as tg:
                tg.start_soon(condition)
                tg.start_soon(branch, self.if_true, rcv_true)
                tg.start_soon(branch, self.if_false, rcv_false)

                async for v in rcv_out:
                    yield await v

        async def branch(branch: PreparedStream[I, A | B], ins: AsyncIterable[I]):
            async for v in branch(ins):
                await snd_out.send(v)

        async def condition():
            async for v in ins:
                if await self.predicate(v):
                    await snd_true.send(v)
                else:
                    await snd_false.send(v)

        return wrapper()


@dataclass(frozen=True)
class FluentStreamOperator[I: Produceable[Any], O: Produceable[Any]]:
    parent_operator: StreamOperator[I, O]

    def map_with[O2: Produceable[Any]](
        self, callable: Callable[[O], Awaitable[O2]]
    ) -> StreamOperator[I, O2]:
        return self.parent_operator.then(FunctionStreamOperator[O, O2](callable))

    def filter_with(
        self, predicate: Callable[[O], Awaitable[bool]]
    ) -> StreamOperator[I, O]:
        return self.parent_operator.then(PredicateStreamOperator(predicate))

    def if_then_else[A, B](
        self,
        predicate: Callable[[O], Awaitable[bool]],
        then: PreparedStream[O, A],
        otherwise: PreparedStream[O, B],
    ) -> PreparedStream[I, A | B]:
        s = BranchStreamOperator(predicate, then, otherwise).finish()

        return lambda ins: s(self.parent_operator(ins))


class Consumer[ProducedType: Produceable[Any]](Protocol):
    @classmethod
    def operators(cls) -> StreamOperator[Produceable[Any], ProducedType]: ...
    async def accept(self, stream: AsyncIterable[ProducedType]) -> None: ...


class Observer[P: Produceable[Any]](Protocol):
    @property
    def interest(self) -> type[P]: ...
    def observe(self, value: P) -> None: ...
