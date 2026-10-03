// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// GAP-2299: an export that gets no HTTP response names the failure code and
// the gateway's proxy path in gateway.log, at most once a minute per code.
func TestLogTransportFailureNamesCodeAndProxyPath(t *testing.T) {
	var out bytes.Buffer
	previous := rejectionLogWriter
	rejectionLogWriter = &out
	t.Cleanup(func() { rejectionLogWriter = previous })

	logTransportFailure("galileo-gap2299", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 5)
	logTransportFailure("galileo-gap2299", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 5)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one throttled line, got %q", out.String())
	}
	for _, want := range []string{
		"galileo-gap2299 traces export failed: connection_failed (5 spans)",
		"HTTPS_PROXY/NO_PROXY",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("line %q lacks %q", lines[0], want)
		}
	}
}

// GAP-1768: a refused export names the HTTP status, a scrubbed reason and
// the refused span names in gateway.log, at most once a minute per status.
func TestLogHTTPRejectionNamesStatusReasonAndSpans(t *testing.T) {
	var out bytes.Buffer
	previous := rejectionLogWriter
	rejectionLogWriter = &out
	t.Cleanup(func() { rejectionLogWriter = previous })

	token := strings.Repeat("a1B2", 12)
	response := func(contentType string, body []byte) *http.Response {
		return &http.Response{
			StatusCode: http.StatusUnprocessableEntity,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(bytes.NewReader(body)),
		}
	}
	request := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{
			{Name: "execute_tool Bash"}, {Name: "tool_batch"}, {Name: "execute_tool Bash"},
		}}},
	}}}
	body := []byte(`{"detail":"span attribute too long at https://api.example.test/v2?key=` + token + "\nkey " + token + `"}`)
	logHTTPRejection("galileo-gap1768", observability.SignalTraces,
		response("application/json", body), 3, distinctSpanNames(request))
	logHTTPRejection("galileo-gap1768", observability.SignalTraces,
		response("application/json", body), 3, nil)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one throttled line, got %q", out.String())
	}
	line := lines[0]
	for _, want := range []string{
		"galileo-gap1768 traces export rejected: HTTP 422",
		"(3 spans: execute_tool Bash, tool_batch)",
		"span attribute too long",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, token) || strings.Contains(line, "key="+token) {
		t.Fatalf("line leaks the token: %q", line)
	}

	status := protowire.AppendTag(nil, 1, protowire.VarintType)
	status = protowire.AppendVarint(status, 3)
	status = protowire.AppendTag(status, 2, protowire.BytesType)
	status = protowire.AppendString(status, "invalid span kind")
	if got := rejectionReason("application/x-protobuf", status); got != "invalid span kind" {
		t.Fatalf("protobuf status reason = %q", got)
	}
}
