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
	"net/url"
	"os"
	"strings"
	"testing"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
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

	logTransportFailure("galileo-gap2299", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 5, "api.example.test:443", true)
	logTransportFailure("galileo-gap2299", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 5, "api.example.test:443", true)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one throttled line, got %q", out.String())
	}
	for _, want := range []string{
		"galileo-gap2299 traces export failed: connection_failed (5 spans)",
		"connects to api.example.test:443 through the proxy",
		"HTTPS_PROXY/NO_PROXY",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("line %q lacks %q", lines[0], want)
		}
	}
}

type proxyReportingDialer struct {
	recordingDialer
	proxied bool
}

func (d *proxyReportingDialer) Proxies(*url.URL) (bool, error) { return d.proxied, nil }

// GAP-2375: with no proxy on the route the line says the gateway connects
// directly to the endpoint and gives no proxy advice; a dialer that proxies
// the endpoint keeps the proxy advice.
func TestLogTransportFailureNamesDirectRouteWithoutProxyAdvice(t *testing.T) {
	var out bytes.Buffer
	previous := rejectionLogWriter
	rejectionLogWriter = &out
	t.Cleanup(func() { rejectionLogWriter = previous })

	endpoint, _ := url.Parse("http://127.0.0.1:19998")
	for _, dialer := range []any{nil, &recordingDialer{}, &proxyReportingDialer{}} {
		config := signalConfig{url: endpoint}
		if dialer != nil {
			config.dialer = dialer.(netguard.V8Dialer)
		}
		if host, proxied := transportRoute(config); host != "127.0.0.1:19998" || proxied {
			t.Fatalf("transportRoute(%T) = %q, %v; want direct to 127.0.0.1:19998", dialer, host, proxied)
		}
	}
	host, proxied := transportRoute(signalConfig{url: endpoint, dialer: &proxyReportingDialer{proxied: true}})
	if !proxied {
		t.Fatal("a dialer that proxies the endpoint must be reported as proxied")
	}

	logTransportFailure("sf3r8-dead", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 16, host, false)
	line := out.String()
	for _, want := range []string{
		"sf3r8-dead traces export failed: connection_failed (16 spans)",
		"connects directly to 127.0.0.1:19998 (no proxy)",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, "HTTPS_PROXY") || strings.Contains(line, "through the proxy") {
		t.Fatalf("direct line gives proxy advice: %q", line)
	}
}

// GAP-2343: one item is singular, and with no test writer the line goes to
// the os.Stderr of the moment (the daemon's time-stamping pipe), not the
// os.Stderr captured at package init.
func TestLogTransportFailureSingularAndCurrentStderr(t *testing.T) {
	previous := rejectionLogWriter
	rejectionLogWriter = nil
	t.Cleanup(func() { rejectionLogWriter = previous })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	logTransportFailure("galileo-gap2343", observability.SignalTraces, delivery.FailureCodeConnectionFailed, 1, "", false)
	logTransportFailure("galileo-gap2343", observability.SignalLogs, delivery.FailureCodeConnectionFailed, 1, "", false)
	os.Stderr = saved
	_ = w.Close()
	got, _ := io.ReadAll(r)
	for _, want := range []string{"traces export failed: connection_failed (1 span);", "logs export failed: connection_failed (1 record);"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("stderr %q lacks %q", got, want)
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
