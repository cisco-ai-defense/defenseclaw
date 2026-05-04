# OTel Gateway Log Trace-Context Gap

Date: 2026-05-04

## Summary

DefenseClaw's gateway OpenTelemetry log path currently loses native OTel trace context before the log record is emitted.

As a result:

- request-scoped gateway logs are not linked to traces using standard OTel log/trace correlation
- the system falls back to copying the trace identifier into a custom attribute, `defenseclaw.trace_id`
- trace correlation still works operationally, but through a DefenseClaw-specific workaround instead of native OTel context propagation

This is not a total observability break, but it is a real telemetry design bug / architecture gap.

## Why This Matters

For OTel-native correlation, the ideal behavior is:

1. a request enters DefenseClaw
2. the request is associated with a live span / trace context
3. gateway events emitted during that request are exported as OTel logs using the same context
4. the backend can correlate logs and traces natively without depending on a copied string attribute

The current implementation breaks step 3.

That means DefenseClaw is:

- duplicating trace identity into a custom field
- depending on custom attribute-based joins for gateway logs
- not taking full advantage of native OTel log/trace correlation when the trace context already exists

## Current Behavior

### Where the trace ID originates

Request correlation middleware and request helpers already derive and propagate trace identity in request-bound paths:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gateway/correlation_middleware.go`
- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gateway/requestctx.go`

Examples:

- `TraceIDFromContext(ctx)` returns the request trace id when available
- if the explicit context value is empty, the code can fall back to the active span's trace id

### How gateway events are emitted today

Structured gateway events flow through:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gatewaylog/writer.go`

The writer fanout API is:

```go
func (w *Writer) WithFanout(fn func(Event))
```

That means:

- fanout callbacks receive only `gatewaylog.Event`
- they do not receive `context.Context`
- any live trace/span context from the original request is lost before telemetry fanout executes

### How OTel logs are emitted today

Gateway events are projected into OTel logs in:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/telemetry/gateway_events.go`

The log emission path ends with:

```go
p.logger.Emit(context.Background(), rec)
```

This is the key issue.

Because the logger call uses `context.Background()`:

- the OTel logger does not receive the original request context
- the log record is not emitted under the active trace/span context
- native trace correlation is lost at the log emission boundary

### The fallback currently used

To preserve some correlation, the current implementation copies trace identity into:

- `defenseclaw.trace_id`

This means downstream systems can still correlate logs to traces by attribute value, but that is a workaround rather than native OTel correlation.

## Concrete Evidence In Code

### Writer fanout drops context

File:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gatewaylog/writer.go`

Relevant shape:

- `WithFanout(fn func(Event))`
- `Emit(e Event)`

Observation:

- no context parameter is carried through the writer/fanout contract

### Gateway OTel log emission uses background context

File:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/telemetry/gateway_events.go`

Relevant behavior:

- builds an OTel `log.Record`
- emits via `p.logger.Emit(context.Background(), rec)`

Observation:

- the OTel log record is emitted without request/span context

### Request-scoped trace identity already exists upstream

Files:

- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gateway/requestctx.go`
- `/Users/adiagne/Documents/splunk-work/poc/defenseclaw/internal/gateway/correlation_middleware.go`

Observation:

- request-scoped trace identity is already available
- the issue is not that DefenseClaw cannot compute trace correlation
- the issue is that the gateway log emission path loses it before export

## Impact

### 1. Logs are not natively trace-correlated

Backends that expect OTel-native log/trace correlation will not be able to rely solely on the log record's true trace context for gateway events.

Instead, they must use:

- `defenseclaw.trace_id`

This is less idiomatic and less portable.

### 2. Duplicate trace identity representation

The system now has two concepts of trace identity:

- the real OTel trace context
- the copied custom attribute `defenseclaw.trace_id`

This duplication increases ambiguity and maintenance burden.

### 3. More custom logic in downstream consumers

Consumers or aggregators that want to correlate gateway logs to traces need to know about DefenseClaw-specific fields instead of relying on generic OTel semantics.

### 4. Harder normalization across modules

If the goal is to align DefenseClaw, NVM, and the aggregate package around standardized semantics:

- `session_id` and `tool_id` can map cleanly to GenAI semantic-convention fields
- `trace_id` should ideally rely on true OTel trace context

The current gateway-log path makes DefenseClaw the outlier here.

## Why This Should Change

This should change because:

- DefenseClaw already captures request trace identity
- OTel already has a built-in concept of trace correlation
- gateway logs should use native trace context when available
- relying on `defenseclaw.trace_id` is a workaround, not the desired architecture

The current system is functional, but not semantically clean.

## Recommended Future Direction

This should be handled in a follow-up PR, separate from the current naming-normalization work.

### Desired end state

For request-scoped gateway OTel logs:

- the logger emits with the real request/span context
- the backend can correlate logs to traces natively
- `defenseclaw.trace_id` can eventually be removed or at least downgraded from "required correlation field"

### Likely implementation direction

The main design change is to propagate context through the gateway event fanout path.

Today:

- `WithFanout(fn func(Event))`

Likely future shape:

- `WithFanout(fn func(context.Context, Event))`

or an equivalent design that preserves request context through:

1. event emission
2. gateway writer fanout
3. telemetry log projection
4. `logger.Emit(ctx, rec)`

### Important constraint

Not all gateway events are request-scoped.

Examples:

- startup
- background capacity/runtime events
- watcher/background lifecycle events

So even after a fix:

- some gateway logs will still have no trace context
- but request-bound events should

## Severity Assessment

This is:

- not a production-breaking telemetry outage
- not urgent in the same way as dropped events or incorrect metrics
- but still a real observability correctness issue

Recommended severity:

- medium-priority telemetry design bug

Reason:

- correlation still works through `defenseclaw.trace_id`
- but the implementation is not OTel-native and makes downstream normalization harder

## Relationship To Current PR

The current PR/branch focuses on attribute naming normalization:

- `tenant.id`
- `workspace.id`
- `deployment.environment`
- `deployment.mode`
- `discovery.source`
- `gen_ai.conversation.id`
- `gen_ai.tool.call.id`

This trace-context gap is related, but distinct:

- it is not just a field rename
- it is a context-propagation / log-emission plumbing change

That is why it should be handled separately.
