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
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

const (
	rejectionBodyReadBytes  = 2048
	rejectionReasonMaxRunes = 200
	rejectionMaxNames       = 4
	rejectionLogInterval    = time.Minute
)

// rejectionLogWriter is where rejected-export lines go when set (tests set
// it). Otherwise they go to os.Stderr, read at write time: the daemon swaps
// os.Stderr for the pipe that stamps each gateway.log line with a time after
// this package is initialised (GAP-2343).
var rejectionLogWriter io.Writer

func rejectionLogOutput() io.Writer {
	if rejectionLogWriter != nil {
		return rejectionLogWriter
	}
	return os.Stderr
}

// itemUnit names the exported items: "span"/"spans" for traces,
// "record"/"records" otherwise.
func itemUnit(signal observability.Signal, count int) string {
	unit := "record"
	if signal == observability.SignalTraces {
		unit = "span"
	}
	if count != 1 {
		unit += "s"
	}
	return unit
}

var rejectionLogLimiter = struct {
	sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int
}{last: map[string]time.Time{}, suppressed: map[string]int{}}

var rejectionTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_\-.]{32,}`)

type rejectionCaptureKey struct{}

// rejectedResponse keeps the status and the head of the body of the last
// refused HTTP attempt for an SDK exporter that never returns the response
// (metrics, GAP-1870), so the refusal can be logged like logs and traces.
type rejectedResponse struct {
	mu          sync.Mutex
	status      int
	contentType string
	body        []byte
}

func withRejectionCapture(ctx context.Context) (context.Context, *rejectedResponse) {
	capture := &rejectedResponse{}
	return context.WithValue(ctx, rejectionCaptureKey{}, capture), capture
}

// captureRejection records a non-2xx response when the request context asks
// for it, and puts the bytes it read back in front of the body for the SDK.
func captureRejection(ctx context.Context, response *http.Response) {
	capture, ok := ctx.Value(rejectionCaptureKey{}).(*rejectedResponse)
	if !ok || capture == nil || response == nil || (response.StatusCode >= 200 && response.StatusCode < 300) {
		return
	}
	var head []byte
	if response.Body != nil {
		head, _ = io.ReadAll(io.LimitReader(response.Body, rejectionBodyReadBytes))
		response.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), response.Body), response.Body}
	}
	capture.mu.Lock()
	capture.status, capture.contentType, capture.body = response.StatusCode, response.Header.Get("Content-Type"), head
	capture.mu.Unlock()
}

// response rebuilds the last refused response, or nil when there was none.
func (capture *rejectedResponse) response() *http.Response {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.status == 0 {
		return nil
	}
	return &http.Response{
		StatusCode: capture.status,
		Header:     http.Header{"Content-Type": []string{capture.contentType}},
		Body:       io.NopCloser(bytes.NewReader(capture.body)),
	}
}

// logHTTPRejection writes one gateway.log line when a destination refuses an
// export with a non-retryable HTTP status, so an operator can see the status
// code, a short scrubbed reason from the response body and what was in the
// refused batch (GAP-1768). The failure code alone ("http_rejected") drops
// the status and reason. At most one line per destination, signal and status
// per minute; skipped lines are counted in the next one.
func logHTTPRejection(destination string, signal observability.Signal, response *http.Response, itemCount int, names []string) {
	if response == nil {
		return
	}
	suppressed, ok := rejectionLogAdmit(fmt.Sprintf("%s/%s/%d", destination, signal, response.StatusCode))
	if !ok {
		return
	}

	var body []byte
	if response.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(response.Body, rejectionBodyReadBytes))
	}
	line := fmt.Sprintf("[observability] %s %s export rejected: HTTP %d (%d %s",
		safeLogToken(destination), signal, response.StatusCode, itemCount, itemUnit(signal, itemCount))
	if len(names) > 0 {
		line += ": " + strings.Join(names, ", ")
	}
	line += ")"
	if reason := rejectionReason(response.Header.Get("Content-Type"), body); reason != "" {
		line += ": " + reason
	}
	if suppressed > 0 {
		line += fmt.Sprintf(" [%d similar in the last minute not logged]", suppressed)
	}
	_, _ = fmt.Fprintln(rejectionLogOutput(), line)
}

// rejectionLogAdmit applies the once-a-minute limit for key. It reports
// whether a line may be written and how many were skipped since the last one.
func rejectionLogAdmit(key string) (int, bool) {
	now := time.Now()
	rejectionLogLimiter.Lock()
	defer rejectionLogLimiter.Unlock()
	if last, ok := rejectionLogLimiter.last[key]; ok && now.Sub(last) < rejectionLogInterval {
		rejectionLogLimiter.suppressed[key]++
		return 0, false
	}
	suppressed := rejectionLogLimiter.suppressed[key]
	rejectionLogLimiter.last[key] = now
	rejectionLogLimiter.suppressed[key] = 0
	return suppressed, true
}

// logTransportFailure writes one gateway.log line when an export gets no
// HTTP response at all (DNS, connect, proxy or timeout), so a destination
// that doctor shows as delivery_failed also leaves a trace in gateway.log
// (GAP-2299). The line names the endpoint and the path the gateway took to
// it: through the proxy it was started with, which is often not the proxy of
// the shell where 'destination test' runs, or directly when no proxy covers
// the endpoint, where proxy advice would mislead (GAP-2375). At most one
// line per destination, signal and failure code per minute.
func logTransportFailure(destination string, signal observability.Signal, code delivery.FailureCode, itemCount int, endpoint string, proxied bool) {
	suppressed, ok := rejectionLogAdmit(fmt.Sprintf("%s/%s/%s", destination, signal, code))
	if !ok {
		return
	}
	target := "the endpoint"
	if endpoint != "" {
		target = endpoint
	}
	line := fmt.Sprintf("[observability] %s %s export failed: %s (%d %s); ", safeLogToken(destination), signal,
		code, itemCount, itemUnit(signal, itemCount))
	if proxied {
		line += "the gateway connects to " + target + " through the proxy it was started with " +
			"(HTTPS_PROXY/NO_PROXY), so check that path and restart the gateway from a shell with the " +
			"right proxy settings"
	} else {
		line += "the gateway connects directly to " + target + " (no proxy), so check that the " +
			"collector is running there and reachable from this host"
	}
	if suppressed > 0 {
		line += fmt.Sprintf(" [%d similar in the last minute not logged]", suppressed)
	}
	_, _ = fmt.Fprintln(rejectionLogOutput(), line)
}

// proxyReporter is a dialer that can say whether it reaches a destination
// through a proxy (the gateway's telemetry egress dialer).
type proxyReporter interface {
	Proxies(target *url.URL) (bool, error)
}

// transportRoute returns the endpoint host:port of config and whether its
// dialer sends that endpoint through a proxy. The HTTP transport never uses
// a proxy itself, so a dialer that cannot tell connects directly.
func transportRoute(config signalConfig) (string, bool) {
	if config.url == nil {
		return "", false
	}
	endpoint := config.url.Host
	reporter, ok := config.dialer.(proxyReporter)
	if !ok {
		return endpoint, false
	}
	proxied, err := reporter.Proxies(&url.URL{Scheme: "https", Host: endpoint})
	return endpoint, err == nil && proxied
}

// rejectionReason extracts a short, scrubbed reason from an OTLP error body:
// the google.rpc.Status message for protobuf replies, otherwise the text.
func rejectionReason(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	text := string(body)
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil &&
		(mediaType == "application/x-protobuf" || mediaType == "application/protobuf") {
		text = statusMessage(body)
	}
	return scrubRejectionText(text)
}

// statusMessage reads field 2 (message) of a google.rpc.Status, the OTLP/HTTP
// protobuf error body, without importing the genproto package.
func statusMessage(body []byte) string {
	for len(body) > 0 {
		number, kind, n := protowire.ConsumeTag(body)
		if n < 0 {
			return ""
		}
		body = body[n:]
		if number == 2 && kind == protowire.BytesType {
			value, m := protowire.ConsumeBytes(body)
			if m < 0 {
				return ""
			}
			return string(value)
		}
		m := protowire.ConsumeFieldValue(number, kind, body)
		if m < 0 {
			return ""
		}
		body = body[m:]
	}
	return ""
}

func scrubRejectionText(text string) string {
	var builder strings.Builder
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		builder.WriteRune(r)
	}
	cleaned := strings.Join(strings.Fields(builder.String()), " ")
	cleaned = netguard.ScrubURLsInText(cleaned)
	cleaned = rejectionTokenPattern.ReplaceAllString(cleaned, "<redacted>")
	if runes := []rune(cleaned); len(runes) > rejectionReasonMaxRunes {
		cleaned = string(runes[:rejectionReasonMaxRunes]) + "..."
	}
	return cleaned
}

// distinctSpanNames returns up to rejectionMaxNames distinct span names, each
// scrubbed and bounded, in first-seen order.
func distinctSpanNames(request *collectortracepb.ExportTraceServiceRequest) []string {
	var out []string
	seen := map[string]bool{}
	for _, resource := range request.GetResourceSpans() {
		for _, scope := range resource.GetScopeSpans() {
			for _, span := range scope.GetSpans() {
				name := scrubRejectionText(span.GetName())
				if r := []rune(name); len(r) > 64 {
					name = string(r[:64])
				}
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				out = append(out, name)
				if len(out) == rejectionMaxNames {
					return out
				}
			}
		}
	}
	return out
}

func safeLogToken(value string) string {
	if observability.IsStableToken(value) {
		return value
	}
	return "destination"
}
