"""A caller's trace context and the propagators a test installs, restored when the block ends."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from opentelemetry import baggage, context, trace
from opentelemetry.propagate import get_global_textmap, set_global_textmap
from opentelemetry.propagators.textmap import CarrierT, Getter, Setter, TextMapPropagator

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACESTATE = "vendor=opaque"
_TRACE_ID = int("4bf92f3577b34da6a3ce929d0e0e4736", 16)
_SPAN_ID = int("00f067aa0ba902b7", 16)


@contextmanager
def inside_a_trace(
    *, tracestate: str | None = None, baggage_entry: str | None = None
) -> Iterator[None]:
    """The current context holds the sampled remote span `TRACEPARENT` names, with `tracestate`
    when given and a baggage entry when `baggage_entry` is."""
    span_context = trace.SpanContext(
        _TRACE_ID,
        _SPAN_ID,
        is_remote=True,
        trace_flags=trace.TraceFlags(trace.TraceFlags.SAMPLED),
        trace_state=trace.TraceState.from_header([tracestate]) if tracestate else None,
    )
    entered = trace.set_span_in_context(trace.NonRecordingSpan(span_context))
    if baggage_entry is not None:
        entered = baggage.set_baggage("session", baggage_entry, entered)
    token = context.attach(entered)
    try:
        yield
    finally:
        context.detach(token)


class _WritingPropagator(TextMapPropagator):
    def __init__(self, written: Mapping[str, str], then_raise: bool) -> None:
        self._written = written
        self._then_raise = then_raise

    def inject(
        self,
        carrier: CarrierT,
        context: context.Context | None = None,
        setter: Setter[CarrierT] | None = None,
    ) -> None:
        for name, value in self._written.items():
            carrier[name] = value  # type: ignore[index]
        if self._then_raise:
            raise RuntimeError("propagator canary failure")

    def extract(
        self,
        carrier: CarrierT,
        context: context.Context | None = None,
        getter: Getter[CarrierT] = ...,  # type: ignore[assignment]
    ) -> context.Context:
        raise NotImplementedError

    @property
    def fields(self) -> set[str]:
        return set(self._written)


@contextmanager
def global_propagator_writing(
    written: Mapping[str, str], *, then_raise: bool = False
) -> Iterator[None]:
    """OpenTelemetry's global propagator writes `written` into every carrier, then raises when
    `then_raise`; the previous one returns when the block ends."""
    previous = get_global_textmap()
    set_global_textmap(_WritingPropagator(written, then_raise))
    try:
        yield
    finally:
        set_global_textmap(previous)
