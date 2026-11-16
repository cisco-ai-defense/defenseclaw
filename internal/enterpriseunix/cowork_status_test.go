// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestDescribeCoworkReportsCoverageAndEachAccountsLastEvent(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.Geteuid = func() int { return 0 }
	at := time.Date(2026, 11, 3, 13, 16, 5, 0, time.UTC)
	var queried string
	old := coworkLastEvents
	coworkLastEvents = func(_ context.Context, path string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		queried = path
		return []enterprisestatus.CoworkAccountEvent{{UserID: "501", UserName: "alice", At: at}}, false, nil
	}
	t.Cleanup(func() { coworkLastEvents = old })
	uidAlice, uidBob := 501, 502
	targets := []enterprisehooks.ManifestTarget{
		{User: "alice", UID: &uidAlice, Connector: "codex"},
		{User: "bob", UID: &uidBob, Connector: "codex"},
	}
	cfg := &config.Config{}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"claudecode": {ManagedHooksOnly: config.ManagedHooksOnlyPreserve}}
	block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll}}
	record := &Deployment{MachinePolicyConnectors: []string{"claudecode", "codex"}}

	raw := DefaultConfig(h.env.Layout)

	result := enterprisestatus.New(ActionStatus, managed.ProfileStandalone, "darwin", "1.0.8")
	l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionStatus},
		gatewayHealthBody: []byte(`{"connectors":[{"name":"claudecode","surfaces":{"cowork":{"requests":4,"last_activity_at":"2026-11-03T13:16:05Z"}}}]}`)}
	l.describeCowork(cfg, raw, block, record, targets)
	cowork := result.Cowork
	if cowork == nil || !cowork.Configured || cowork.ManagedHooksOnly != "preserve" || cowork.Requests != 4 || !cowork.AccountsKnown ||
		len(cowork.Accounts) != 2 || cowork.Accounts[0] != (enterprisestatus.CoworkAccount{Account: "alice", LastEventAt: "2026-11-03T13:16:05Z"}) ||
		cowork.Accounts[1] != (enterprisestatus.CoworkAccount{Account: "bob"}) {
		t.Fatalf("cowork = %+v", cowork)
	}
	if want := h.env.P(filepath.Join(h.env.Layout.DataDir, "audit.db")); queried != want {
		t.Fatalf("audit store queried at %q, want %q", queried, want)
	}

	// Not root: no account names.
	h.env.Geteuid = func() int { return 501 }
	result = enterprisestatus.New(ActionStatus, managed.ProfileStandalone, "darwin", "1.0.8")
	l.result = result
	l.describeCowork(cfg, raw, block, record, targets)
	if result.Cowork == nil || result.Cowork.AccountsKnown || len(result.Cowork.Accounts) != 0 {
		t.Fatalf("unprivileged cowork = %+v", result.Cowork)
	}

	// Without the claudecode machine policy Cowork is not covered.
	h.env.Geteuid = func() int { return 0 }
	result = enterprisestatus.New(ActionVerify, managed.ProfileStandalone, "linux", "1.0.8")
	l.result, l.opts.Action = result, ActionVerify
	l.describeCowork(cfg, raw, block, &Deployment{MachinePolicyConnectors: []string{"codex"}}, targets)
	if result.Cowork == nil || result.Cowork.Configured || result.Cowork.Reason != enterprisestatus.CoworkReasonMachinePolicyUnset {
		t.Fatalf("no machine policy cowork = %+v", result.Cowork)
	}

	// unverified_versions: refuse refuses the Claude Desktop surface.
	refuse := *cfg
	refuse.Enterprise.Enrollment.UnverifiedVersions = config.EnterpriseUnverifiedRefuse
	result = enterprisestatus.New(ActionStatus, managed.ProfileStandalone, "darwin", "1.0.8")
	l.result, l.opts.Action = result, ActionStatus
	l.describeCowork(&refuse, raw, block, record, targets)
	if result.Cowork == nil || result.Cowork.Configured || result.Cowork.Reason != enterprisestatus.CoworkReasonDesktopRefused {
		t.Fatalf("refuse cowork = %+v", result.Cowork)
	}

	// Only status and verify of the standalone profile get the block.
	result = enterprisestatus.New(ActionEnsure, managed.ProfileStandalone, "linux", "1.0.8")
	l.result, l.opts.Action = result, ActionEnsure
	l.describeCowork(cfg, raw, block, record, targets)
	if result.Cowork != nil {
		t.Fatalf("ensure got a cowork block: %+v", result.Cowork)
	}
}

// The per-account line reads the audit store the gateway writes, resolved
// from the installed config the way the gateway start resolves it, on the
// Linux and the macOS layout: nothing here replaces the lookup or the path.
// The lifecycle's built-in config sets data_dir, and the runtime decode alone
// then names <config folder>/audit.db (/etc/defenseclaw/audit.db), which does
// not exist, so every account was "unknown" (cowork-1-0-8 GAP-0025).
func TestDescribeCoworkReadsTheGatewayAuditStoreOfTheManagedLayout(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			layout := h.env.Layout
			for _, tc := range []struct {
				name, extra, store string
			}{
				{"layout default", "", filepath.Join(layout.DataDir, "audit.db")},
				{"observability.local.path", "observability:\n  local:\n    path: " + filepath.Join(layout.DataDir, "stores", "events.db") + "\n",
					filepath.Join(layout.DataDir, "stores", "events.db")},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := append(DefaultConfig(layout), tc.extra...)
					writeHostFile(t, h, layout.ConfigPath, string(raw))
					cfg, err := h.env.InstalledConfig()
					if err != nil {
						t.Fatal(err)
					}
					storePath := h.env.P(tc.store)
					if err := os.MkdirAll(filepath.Dir(storePath), 0o700); err != nil {
						t.Fatal(err)
					}
					store, err := audit.NewStore(storePath)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = store.Close() })
					if err := store.Init(); err != nil {
						t.Fatal(err)
					}
					at := time.Date(2026, 11, 4, 1, 6, 30, 0, time.UTC)
					if err := store.LogEvent(audit.Event{Action: "connector-hook", Connector: "claudecode", Timestamp: at,
						Structured: map[string]any{"user.id": "1001", "defenseclaw.user.name": "dccw-u1", "event": "PreToolUse", "surface": "cowork"}}); err != nil {
						t.Fatal(err)
					}
					uid1, uid2 := 1001, 1002
					targets := []enterprisehooks.ManifestTarget{
						{User: "dccw-u1", UID: &uid1, Connector: "codex"},
						{User: "dccw-u2", UID: &uid2, Connector: "codex"},
					}
					block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll}}
					result := enterprisestatus.New(ActionStatus, managed.ProfileStandalone, goos, "1.0.8")
					l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionStatus}}
					l.describeCowork(cfg, raw, block, &Deployment{MachinePolicyConnectors: []string{"claudecode"}}, targets)
					cowork := result.Cowork
					if cowork == nil || !cowork.AccountsKnown || len(cowork.Accounts) != 2 ||
						cowork.Accounts[0] != (enterprisestatus.CoworkAccount{Account: "dccw-u1", LastEventAt: "2026-11-04T01:06:30Z"}) ||
						cowork.Accounts[1] != (enterprisestatus.CoworkAccount{Account: "dccw-u2"}) {
						t.Fatalf("cowork = %+v", cowork)
					}
				})
			}
		})
	}
}
