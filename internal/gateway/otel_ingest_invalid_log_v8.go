// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

const invalidInboundLeafLogInterval = time.Minute

// invalidInboundLeafLogWriter is gateway.log (the gateway's stderr); tests
// replace it.
var invalidInboundLeafLogWriter io.Writer = os.Stderr

var invalidInboundLeafLogLimiter = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// logInvalidInboundLeafV8 names the connector, signal and metric, span or
// event name of a native OTLP record dropped as invalid_record, so the
// telemetry.records.dropped counts can be traced to a source (GAP-1495). At
// most one line per source and name per minute.
func logInvalidInboundLeafV8(leaf otlpDecodedLeaf, source string) {
	name := invalidInboundLeafName(leaf)
	key := source + "\x00" + string(leaf.signal) + "\x00" + name
	now := time.Now()
	invalidInboundLeafLogLimiter.Lock()
	if last, ok := invalidInboundLeafLogLimiter.last[key]; ok && now.Sub(last) < invalidInboundLeafLogInterval {
		invalidInboundLeafLogLimiter.Unlock()
		return
	}
	if len(invalidInboundLeafLogLimiter.last) > 256 {
		invalidInboundLeafLogLimiter.last = map[string]time.Time{}
	}
	invalidInboundLeafLogLimiter.last[key] = now
	invalidInboundLeafLogLimiter.Unlock()
	_, _ = fmt.Fprintf(invalidInboundLeafLogWriter,
		"[otel-ingest] dropped an invalid %s record from %s: %s (telemetry.records.dropped class=invalid_record)\n",
		leaf.signal, boundedLogLabel(source), name)
}

func invalidInboundLeafName(leaf otlpDecodedLeaf) string {
	name := ""
	switch {
	case leaf.metric != nil:
		name = "metric " + boundedLogLabel(leaf.metric.GetName())
	case leaf.span != nil:
		name = "span " + boundedLogLabel(leaf.span.GetName())
	case leaf.logRecord != nil:
		if event, state := leaf.leafAttributes.stringValue("event.name"); state == otlpTypedAttributeUnique {
			name = "event " + boundedLogLabel(event)
		} else {
			name = "event " + boundedLogLabel(leaf.logRecord.GetEventName())
		}
	}
	if strings.HasSuffix(name, " ") || name == "" {
		return "unnamed record"
	}
	return name
}

// boundedLogLabel keeps a short printable name for a log line.
func boundedLogLabel(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if builder.Len() >= 96 {
			builder.WriteString("...")
			break
		}
		if unicode.IsPrint(r) && !unicode.IsSpace(r) {
			builder.WriteRune(r)
		} else {
			builder.WriteRune('_')
		}
	}
	return builder.String()
}
