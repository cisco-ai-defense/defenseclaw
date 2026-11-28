// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// otlpRelay records relayed OTLP exports.
type otlpRelay struct {
	*vaultRelay
	otlp []sandboxrelay.OTLPCall
}

func (r *otlpRelay) OTLP(_ context.Context, call sandboxrelay.OTLPCall) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.otlp = append(r.otlp, call)
	return nil
}

// A harness's own telemetry export is masked before it is relayed: the
// managed gateway never receives a capturable value through OTLP either.
func TestSandboxOTLPIsMaskedBeforeRelay(t *testing.T) {
	relay := &otlpRelay{vaultRelay: &vaultRelay{fakeRelay: &fakeRelay{}}}
	f := newSandboxIngressFixture(t, withTestVault(vault.Open(filepath.Join(t.TempDir(), "vault"))), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	key := vaultTestAnthropicKey()
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"prompt: use\n` + key + `"}}]}]}]}`
	rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("otlp: %d %s", rec.Code, rec.Body.String())
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.otlp) != 1 || len(relay.otlp[0].Body) != len(body) || strings.Contains(string(relay.otlp[0].Body), key) {
		t.Fatalf("relayed otlp = %d calls", len(relay.otlp))
	}
	if !strings.Contains(string(relay.otlp[0].Body), "sk-ant-****") {
		t.Fatalf("relayed body = %s", relay.otlp[0].Body)
	}
}

func TestMaskCapturableBodyGzipAndRefusals(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("x " + vaultTestStripeKey()))
	_ = zw.Close()
	out, changed, err := maskCapturableBody(buf.Bytes(), "gzip")
	if err != nil || !changed {
		t.Fatalf("gzip: changed=%v err=%v", changed, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if strings.Contains(string(plain), vaultTestStripeKey()) {
		t.Fatal("gzip body still holds the value")
	}
	if _, _, err := maskCapturableBody([]byte("x"), "zstd"); err == nil {
		t.Fatal("an unreadable encoding was accepted")
	}
}
