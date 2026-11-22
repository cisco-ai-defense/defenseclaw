// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-1092: a boot that removes the DefenseClaw hooks of an
// unconfigured connector whose hook script is gone (a rollback's data swap
// dropped it) leaves an audit row.
func TestBootReclaimOfHooksWithoutAHookScriptWritesAnAuditRow(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	hooksFile := filepath.Join(home, ".kiro", "hooks", "defenseclaw.json")
	if err := os.MkdirAll(filepath.Dir(hooksFile), 0o700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dataDir, "hooks", "kiro-hook.sh") + " --hook-surface v3"
	body := `{"version":"v1","hooks":[{"name":"defenseclaw-pre-tool","trigger":"PreToolUse","matcher":".*",` +
		`"action":{"type":"command","command":"` + command + `"},"timeout":30,"enabled":true}]}` + "\n"
	if err := os.WriteFile(hooksFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	s := &Sidecar{cfg: cfg, logger: logger}
	s.reclaimUnguardedConnectorHooks(context.Background(), connector.NewDefaultRegistry())
	if data, err := os.ReadFile(hooksFile); err == nil && strings.Contains(string(data), "defenseclaw-") {
		t.Fatalf("the stale Kiro hooks stayed:\n%s", data)
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Target == "kiro" && strings.Contains(e.Details, "action=reclaim-unguarded result=removed") {
			return
		}
	}
	t.Fatalf("no reclaim-unguarded audit row for kiro among %d events", len(events))
}
