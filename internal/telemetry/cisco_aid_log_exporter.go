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

package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/telemetry/otlptransform"
)

// ciscoAIDExportTimeout bounds a single ingest POST (plus its at-most-one
// re-mint retry). Kept short so a stalled backend cannot block the log
// BatchProcessor's export goroutine indefinitely.
const ciscoAIDExportTimeout = 10 * time.Second

// ciscoAIDRemintMinGap rate-limits token re-mints so a persistent 401 (revoked
// enrollment, clock skew) cannot hammer the CMID provider once per export.
const ciscoAIDRemintMinGap = 30 * time.Second

// ciscoAIDLogExporter is a custom sdklog.Exporter that delivers DefenseClaw's
// OTEL log events to the Cisco AI Defense event-ingest API. Unlike the stock
// OTLP exporters it targets a single custom path and wraps the OTLP-JSON body
// in the required {"payload": {...}} envelope, authenticating with a CMID
// bearer token sourced from cloudreg.Provider and re-minted on HTTP 401.
type ciscoAIDLogExporter struct {
	url      string
	client   *http.Client
	provider cloudreg.Provider
	debug    bool

	remintMu   sync.Mutex
	lastRemint time.Time

	stopped atomic.Bool
}

// Compile-time assertion: the custom exporter satisfies sdklog.Exporter.
var _ sdklog.Exporter = (*ciscoAIDLogExporter)(nil)

func newCiscoAIDLogExporter(url string, provider cloudreg.Provider) *ciscoAIDLogExporter {
	return &ciscoAIDLogExporter{
		url:      url,
		client:   &http.Client{Timeout: ciscoAIDExportTimeout},
		provider: provider,
		// Opt-in client-side confirmation of successful sends, matching the
		// repo-wide DEFENSECLAW_DEBUG=1 convention (see gateway/proxy.go,
		// gateway/client.go). Off by default to avoid production log spam.
		debug: os.Getenv("DEFENSECLAW_DEBUG") == "1",
	}
}

// Export transforms the batch of SDK log records into OTLP ResourceLogs, wraps
// them in the AI Defense ingest envelope, and POSTs with a CMID bearer token.
// Errors are returned to the BatchProcessor, which routes them to the global
// OTel error handler (Provider.installOpenTelemetryGlobals) for accounting.
func (e *ciscoAIDLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if e.stopped.Load() || len(records) == 0 {
		return nil
	}
	rls := otlptransform.ResourceLogs(records)
	if len(rls) == 0 {
		return nil
	}
	body, err := marshalLogsPayload(rls)
	if err != nil {
		return err
	}
	return e.post(ctx, body, len(records))
}

// ForceFlush is a no-op: the exporter buffers nothing itself (the
// BatchProcessor owns the queue and drives Export).
func (e *ciscoAIDLogExporter) ForceFlush(context.Context) error {
	return nil
}

// Shutdown marks the exporter stopped; subsequent Export calls are no-ops.
func (e *ciscoAIDLogExporter) Shutdown(context.Context) error {
	e.stopped.Store(true)
	return nil
}

// post sends body with the current token, transparently re-minting once on a
// 401 (mirrors the inspection path in cisco_inspect.go doInspectHTTP). n is the
// number of log records in body, used only for the DEFENSECLAW_DEBUG success line.
func (e *ciscoAIDLogExporter) post(ctx context.Context, body []byte, n int) error {
	// Bound the whole sequence (token mint + initial POST + at-most-one
	// re-mint retry) under a single deadline. client.Timeout is per-Do, so
	// without this a 401 retry could block for up to ~2x ciscoAIDExportTimeout,
	// contradicting the constant's "single bounded window" contract.
	ctx, cancel := context.WithTimeout(ctx, ciscoAIDExportTimeout)
	defer cancel()

	tok, err := e.provider.Token(ctx)
	if err != nil {
		return fmt.Errorf("cisco ai defense telemetry: token: %w", err)
	}

	status, respSnippet, err := e.doPost(ctx, body, tok)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		fresh, ok := e.remint(ctx, tok)
		if !ok {
			return fmt.Errorf("cisco ai defense telemetry: unauthorized and no fresh token available")
		}
		status, respSnippet, err = e.doPost(ctx, body, fresh)
		if err != nil {
			return err
		}
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return fmt.Errorf("cisco ai defense telemetry: ingest HTTP %d: %s", status, respSnippet)
	}
	if e.debug {
		fmt.Fprintf(os.Stderr,
			"[cisco-ai-defense] telemetry: sent %d record(s) -> %s HTTP %d\n",
			n, e.url, status)
	}
	return nil
}

// doPost performs one POST attempt and returns the HTTP status code plus a
// bounded snippet of the response body (used to surface server rejection
// reasons such as a 403). The body is read (bounded) so the connection can be
// reused and the snippet reflects the server's error message.
func (e *ciscoAIDLogExporter) doPost(ctx context.Context, body []byte, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("cisco ai defense telemetry: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cisco ai defense telemetry: POST %s: %w", e.url, err)
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, snippet, nil
}

// remint invalidates the cached token and fetches a fresh one, rate-limited so
// a persistent 401 does not re-mint on every export. Returns the new token and
// true only when it differs from the token that just failed.
func (e *ciscoAIDLogExporter) remint(ctx context.Context, current string) (string, bool) {
	e.remintMu.Lock()
	defer e.remintMu.Unlock()

	if !e.lastRemint.IsZero() && time.Since(e.lastRemint) < ciscoAIDRemintMinGap {
		// Rate-limited: reuse whatever the cache holds, but only retry if
		// it is genuinely different from the token that just 401'd.
		if tok, err := e.provider.Token(ctx); err == nil && tok != "" && tok != current {
			return tok, true
		}
		return "", false
	}

	e.provider.Invalidate()
	e.lastRemint = time.Now()
	tok, err := e.provider.Token(ctx)
	if err != nil || tok == "" || tok == current {
		return "", false
	}
	return tok, true
}
