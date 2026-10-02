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
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	rejectionBodyReadBytes  = 2048
	rejectionReasonMaxRunes = 200
	rejectionMaxNames       = 4
	rejectionLogInterval    = time.Minute
)

// rejectionLogWriter is where rejected-export lines go. The gateway's stderr
// is gateway.log. Tests replace it.
var rejectionLogWriter io.Writer = os.Stderr

var rejectionLogLimiter = struct {
	sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int
}{last: map[string]time.Time{}, suppressed: map[string]int{}}

var rejectionTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_\-.]{32,}`)

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
	key := fmt.Sprintf("%s/%s/%d", destination, signal, response.StatusCode)
	now := time.Now()
	rejectionLogLimiter.Lock()
	if last, ok := rejectionLogLimiter.last[key]; ok && now.Sub(last) < rejectionLogInterval {
		rejectionLogLimiter.suppressed[key]++
		rejectionLogLimiter.Unlock()
		return
	}
	suppressed := rejectionLogLimiter.suppressed[key]
	rejectionLogLimiter.last[key] = now
	rejectionLogLimiter.suppressed[key] = 0
	rejectionLogLimiter.Unlock()

	var body []byte
	if response.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(response.Body, rejectionBodyReadBytes))
	}
	unit := "records"
	if signal == observability.SignalTraces {
		unit = "spans"
	}
	line := fmt.Sprintf("[observability] %s %s export rejected: HTTP %d (%d %s",
		safeLogToken(destination), signal, response.StatusCode, itemCount, unit)
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
	_, _ = fmt.Fprintln(rejectionLogWriter, line)
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
