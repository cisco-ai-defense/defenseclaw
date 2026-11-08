// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A connector the administrator took off the roster is neither protected nor
// pending in the account's own status: "not managed (removed from roster)",
// for that account only.
func TestOwnStatusForWindowsAccountShowsAConnectorRemovedFromTheRoster(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousName, previousValidate := ownStatusWindowsAccountName, validateManagedGuardianAuthorization
	t.Cleanup(func() {
		ownStatusWindowsAccountName, validateManagedGuardianAuthorization = previousName, previousValidate
	})
	ownStatusWindowsAccountName = func(string) string { return `WIN11\alice` }
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	const alice, bob = "S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-21-1004336348-1177238915-682003330-1002"
	dataDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(dataDir, "guardian"))
	if err := os.MkdirAll(filepath.Join(dataDir, "guardian"), 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := managed.MarshalRemovedConnectors([]managed.RemovedConnector{
		{Connector: "cursor", SID: alice, RemovedAt: "2026-11-08T18:00:00Z"},
		{Connector: "cursor", SID: bob, RemovedAt: "2026-11-08T18:00:00Z"},
		{Connector: "codex", SID: alice, RemovedAt: "2026-11-08T18:00:00Z"},
	}, "2026-11-08T18:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed.RemovedConnectorsPath(dataDir), record, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)

	var out struct {
		Connectors map[string]struct {
			Protected bool   `json:"protected"`
			State     string `json:"state"`
		} `json:"connectors"`
	}
	body := api.ownStatusForWindowsAccount(context.Background(), alice)
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	for _, name := range []string{"cursor", "codex"} {
		if row := out.Connectors[name]; row.Protected || row.State != managed.NotManagedRemovedFromRoster {
			t.Fatalf("%s = %+v, want %q and not protected", name, row, managed.NotManagedRemovedFromRoster)
		}
	}
	if row := out.Connectors["claudecode"]; !row.Protected {
		t.Fatalf("a configured connector lost its row: %+v", row)
	}
	// Bob sees only his own removed connector, and nothing of alice's.
	body = api.ownStatusForWindowsAccount(context.Background(), bob)
	if strings.Contains(string(body), alice) || strings.Contains(string(body), "codex") {
		t.Fatalf("bob's answer names alice's removed connector: %s", body)
	}
	if !strings.Contains(string(body), managed.NotManagedRemovedFromRoster) {
		t.Fatalf("bob's answer lacks his own removed connector: %s", body)
	}
	// A record the trust check refuses says nothing.
	validateManagedGuardianAuthorization = func(string, string) error { return os.ErrPermission }
	if strings.Contains(string(api.ownStatusForWindowsAccount(context.Background(), alice)), managed.NotManagedRemovedFromRoster) {
		t.Fatal("an untrusted record was rendered")
	}
}
