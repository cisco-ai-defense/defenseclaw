// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestGAP1085NoSinkCarriesTheMatchedValue: a reply that holds a value of a
// legacy local detector, on the raw-forward stream (where GAP-1085 was
// found) and the /llm stream, whole and in 7-byte pieces, in the default and
// strict packs. Every sink carries 0 bytes of the value: the block message
// the client gets (the last event of a blocked reply), the gateway log lines, and
// every byte the gateway wrote to disk: the audit store (audit rows and the
// alerts the TUI reads), the judge-bodies store and a JSONL telemetry
// destination with redaction profile none (the log records an OTLP
// destination is sent, unredacted). A finding record reaches that
// destination in every run, or the run measured nothing.
func TestGAP1085NoSinkCarriesTheMatchedValue(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the audit store fixture needs an unprivileged user")
	}
	values := gap1085Values(t)
	type pathRun func(t *testing.T, rec *httptest.ResponseRecorder, proxy *GuardrailProxy, pack string, pieces []string)
	paths := []struct {
		name string
		run  pathRun
	}{
		{"raw-forward", gap0429RawForward},
		{"llm", func(t *testing.T, rec *httptest.ResponseRecorder, proxy *GuardrailProxy, pack string, pieces []string) {
			prov := &mockProvider{streamChunks: gap0429Chunks(pieces)}
			proxy.resolveProviderFn = func(*ChatRequest) LLMProvider { return prov }
			gap0429LLMProxy(t, rec, proxy, pack)
		}},
	}
	for _, path := range paths {
		for _, pack := range []string{"default", "strict"} {
			for _, v := range values {
				for _, size := range []int{0, 7} {
					name := path.name + "/" + pack + "/" + v.name
					if size > 0 {
						name += "/pieces"
					}
					dir := t.TempDir()
					sinkPath := filepath.Join(dir, "sink", "audit.jsonl")
					sink, err := local.NewJSONL(local.DefaultJSONLConfig(sinkPath))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(filepath.Join(dir, "store"), 0o700); err != nil {
						t.Fatal(err)
					}
					fixture := newSidecarRuntimeFixtureExportingToInDir(t, filepath.Join(dir, "store"), nil, sink)
					fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
					if err != nil {
						t.Fatal(err)
					}
					logger := audit.NewLogger(fixture.store)
					logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
					watch := &gap0429Watch{GuardrailInspector: retestInspector(), secret: v.value}
					rec := httptest.NewRecorder()
					watch.rec = rec
					proxy := newTestProxy(t, &mockProvider{}, watch, "action")
					proxy.logger, proxy.store, proxy.dataDir = logger, fixture.store, filepath.Join(dir, "data")
					stderr := captureStderr(t, func() {
						path.run(t, rec, proxy, pack, gap0429Pieces(gap1085Text(v), size, nil))
					})
					var record bool
					for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !record; time.Sleep(50 * time.Millisecond) {
						all, _ := os.ReadFile(sinkPath)
						record = bytes.Contains(all, []byte("defenseclaw.finding.rule_id"))
					}
					if !record {
						t.Errorf("%s: no finding record reached the telemetry destination: not measured", name)
					}
					_ = sink.Close(context.Background())
					sinks := map[string]string{"log lines": stderr}
					if watch.blocked {
						sinks["block message"] = gap1085LastEvent(rec.Body.String())
					}
					_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
						if err == nil && !d.IsDir() {
							if b, err := os.ReadFile(p); err == nil {
								rel, _ := filepath.Rel(dir, p)
								sinks[rel] = string(b)
							}
						}
						return nil
					})
					for sink, text := range sinks {
						if n := gap1085Leaked(text, v.value); n > 0 {
							t.Errorf("%s: %s carries the matched value (%d value windows)", name, sink, n)
						}
					}
					if !strings.Contains(strings.Join(func() []string {
						keys := make([]string, 0, len(sinks))
						for k := range sinks {
							keys = append(keys, k)
						}
						return keys
					}(), " "), "audit.db") {
						t.Errorf("%s: the audit store wrote nothing to disk: not measured", name)
					}
				}
			}
		}
	}
}

// gap1085LastEvent is the text of the last stream event of out: the block
// message of a blocked stream. The reply text before it is the business of
// the stream hold (GAP-0429), not of this test.
func gap1085LastEvent(out string) string {
	last := ""
	for _, line := range strings.Split(out, "\n") {
		if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data: "); ok && d != "[DONE]" {
			last = line
		}
	}
	return streamedContent(last)
}
