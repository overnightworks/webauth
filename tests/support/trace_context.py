"""A caller's trace context and a failing propagator, each restored when its block ends."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from opentelemetry import context, trace
from opentelemetry.propagate import get_global_textmap, set_global_textmap
from opentelemetry.propagators.textmap import CarrierT, Getter, Setter, TextMapPropagator

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACESTATE = "vendor=opaque"
PROPAGATOR_FAILURE_MESSAGE = "propagator canary failure"
_TRACE_ID = int("4bf92f3577b34da6a3ce929d0e0e4736", 16)
_SPAN_ID = int("00f067aa0ba902b7", 16)


@contextmanager
def inside_a_trace(*, tracestate: str | None = None) -> Iterator[None]:
    """The current context holds the sampled remote span `TRACEPARENT` names, with `tracestate`
    when given."""
    span_context = trace.SpanContext(
        _TRACE_ID,
        _SPAN_ID,
        is_remote=True,
        trace_flags=trace.TraceFlags(trace.TraceFlags.SAMPLED),
        trace_state=trace.TraceState.from_header([tracestate]) if tracestate else None,
    )
    entered = trace.set_span_in_context(trace.NonRecordingSpan(span_context))
    token = context.attach(entered)
    try:
        yield
    finally:
        context.detach(token)


class _RaisingPropagator(TextMapPropagator):
    def inject(
        self,
        carrier: CarrierT,
        context: context.Context | None = None,
        setter: Setter[CarrierT] | None = None,
    ) -> None:
        raise RuntimeError(PROPAGATOR_FAILURE_MESSAGE)

    def extract(
        self,
        carrier: CarrierT,
        context: context.Context | None = None,
        getter: Getter[CarrierT] = ...,  # type: ignore[assignment]
    ) -> context.Context:
        raise NotImplementedError

    @property
    def fields(self) -> set[str]:
        return set()


@contextmanager
def a_raising_global_propagator() -> Iterator[None]:
    """OpenTelemetry's global propagator raises `RuntimeError(PROPAGATOR_FAILURE_MESSAGE)` on
    every injection; the previous one returns when the block ends."""
    previous = get_global_textmap()
    set_global_textmap(_RaisingPropagator())
    try:
        yield
    finally:
        set_global_textmap(previous)
