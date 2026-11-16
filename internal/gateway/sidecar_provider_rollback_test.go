// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A provider prerequisite is part of setup, before publishing readiness.
// Refusing it must restore the vendor config and provider snapshot so a retry
// reads the account's corrected config rather than a stale blank-key backup.
func TestRunGuardrailProviderRefusalRollsBackAndAllowsCorrectedRetry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ZeptoClaw requires the Unix guardrail proxy")
	}
	root := testenv.PrivateTempDir(t)
	path := filepath.Join(root, "config.json")
	previous := connector.ZeptoClawConfigPathOverride
	connector.ZeptoClawConfigPathOverride = path
	t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = previous })
	const original = `{"providers":{"openai":{"api_base":"https://api.openai.com/v1","api_key":""}},"theme":"dark"}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "zeptoclaw"
	cfg.Guardrail.Mode = "observe"
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth(), router: routerWithDefaultRulePack(t)}
	err := s.runGuardrail(t.Context())
	if err == nil || !strings.Contains(err.Error(), "zero usable providers") {
		t.Fatalf("runGuardrail = %v, want provider prerequisite refusal", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != original {
		t.Fatalf("provider refusal changed vendor config: %q, %v", got, err)
	}
	assertPathMissing(t, filepath.Join(cfg.DataDir, "zeptoclaw_backup.json"))
	if active := connector.LoadActiveConnector(cfg.DataDir); active != "" {
		t.Fatalf("failed setup published active connector %q", active)
	}

	corrected := strings.Replace(original, `"api_key":""`, `"api_key":"synthetic provider fixture"`, 1)
	if err := os.WriteFile(path, []byte(corrected), 0o600); err != nil {
		t.Fatal(err)
	}
	c := connector.NewZeptoClawConnector()
	opts := connector.SetupOpts{DataDir: cfg.DataDir, ProxyAddr: guardrailListenAddr(cfg.Guardrail.Port, cfg.Guardrail.Host), APIAddr: apiListenAddr(cfg)}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if count, err := c.HasUsableProviders(); err != nil || count != 1 {
		t.Fatalf("corrected retry provider count = %d, %v", count, err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != corrected {
		t.Fatalf("teardown did not restore corrected config: %q, %v", got, err)
	}
}
