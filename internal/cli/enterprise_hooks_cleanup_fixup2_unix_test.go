//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

type fixup2CodexCase struct {
	fixture               *standaloneFixture
	resolver              standaloneTestResolver
	entry                 enterpriseHookUserCleanup
	oldHome, currentHome  string
	currentConfig, seed   string
	workerRemoveResponses []enterpriseHookWorkerTargetResult
}

func setupFixup2CodexCase(t *testing.T, seed string, move bool) *fixup2CodexCase {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome := f.home(t, "sample-codex-old", 0o700)
	currentHome := f.home(t, "sample-codex-current", 0o700)
	t.Setenv("HOME", oldHome)
	t.Setenv("CODEX_HOME", "")
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	if seed != "" {
		if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(oldConfig, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if _, err := os.Stat(oldConfig); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap precondition failed: %v", err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install Codex: %v", err)
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	if move {
		if err := os.RemoveAll(oldHome); err != nil {
			t.Fatal(err)
		}
	}
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	c := &fixup2CodexCase{fixture: f, resolver: resolver, oldHome: oldHome, currentHome: currentHome,
		currentConfig: filepath.Join(currentHome, ".codex", "config.toml"), seed: seed,
		entry: enterpriseHookUserCleanup{Connector: "codex", User: "sample-user", UID: uid,
			UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")},
	}
	useEnterpriseHookWorkerHelper(t, "real")
	previousRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := runEnterpriseHookWorker(ctx, account, request)
		if err == nil {
			c.workerRemoveResponses = append(c.workerRemoveResponses, response.Targets...)
		}
		return response, err
	}
	return c
}

func TestStandaloneCleanupMovedCodexBootstrapAndTrustedProjects(t *testing.T) {
	for _, tc := range []struct{ name, seed string }{
		{name: "bootstrap stub"},
		{name: "uppercase project", seed: "[projects.\"/srv/work/DefenseClaw\"]\ntrust_level = \"trusted\"\n"},
		{name: "lowercase project", seed: "[projects.\"/home/sample-user/code/defenseclaw\"]\ntrust_level = \"trusted\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := setupFixup2CodexCase(t, tc.seed, true)
			for attempt := 1; attempt <= 2; attempt++ {
				outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("attempt %d = %v, %v", attempt, outcome, err)
				}
			}
			data, err := os.ReadFile(c.currentConfig)
			if err != nil {
				t.Fatal(err)
			}
			if tc.seed == "" {
				for _, line := range []string{"# Created by DefenseClaw installer", "# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],", "# and the top-level notify entries."} {
					if !bytes.Contains(data, []byte(line)) {
						t.Fatalf("bootstrap header was lost: %q", data)
					}
				}
			} else if !bytes.Contains(data, []byte(tc.seed)) {
				t.Fatalf("trusted project changed: %q", data)
			}
			for _, result := range c.workerRemoveResponses {
				if !result.OK || !result.PathsReported || result.Remaining != "" {
					t.Fatalf("Codex Remove did not report clean: %+v", result)
				}
			}
			if len(c.workerRemoveResponses) != 2 {
				t.Fatalf("Remove responses = %d, want two", len(c.workerRemoveResponses))
			}
			if tc.seed == "" {
				now := time.Now()
				if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, now); err != nil {
					t.Fatal(err)
				}
				c.fixture.writeManifest(t)
				manifest, err := enterprisehooks.LoadManifest(c.fixture.manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &bytes.Buffer{}, manifest,
					enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, c.resolver, now); err != nil {
					t.Fatal(err)
				}
				cmd := &cobra.Command{}
				cmd.SetContext(context.Background())
				report := enterpriseHooksRemoveAllReport{}
				runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
				if report.Removed != 0 || len(report.Failed) != 0 || len(report.Pending) != 0 {
					t.Fatalf("remove-all listed a completed Codex row: %+v", report)
				}
			}
		})
	}
}

func writeFixup2StrayReceipt(t *testing.T, home, name, connectorName, kind string) string {
	t.Helper()
	dir := filepath.Join(home, ".defenseclaw", "connector_backups", connectorName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".json")
	content := []byte("{not json")
	switch kind {
	case "version zero":
		content = []byte("{}")
	case "wrong location":
		content = []byte(`{"version":1,"connector":"other","logical_name":"config","path":"/tmp/sample-config"}`)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStandaloneCleanupSameHomeRemovesDespiteStrayReceipt(t *testing.T) {
	for _, name := range []string{"opencode", "codex"} {
		for _, kind := range []string{"invalid json", "version zero", "wrong location"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				var entry enterpriseHookUserCleanup
				var resolver standaloneTestResolver
				var artifact string
				if name == "opencode" {
					c := setupRehomedOpenCodeCase(t, false, false)
					c.resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: c.entry.UID, GID: os.Getgid(), Home: c.oldHome}
					entry, resolver, artifact = c.entry, c.resolver, c.oldPlugin
				} else {
					c := setupFixup2CodexCase(t, "model = \"gpt-5\"\n", false)
					c.resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: c.entry.UID, GID: os.Getgid(), Home: c.oldHome}
					entry, resolver, artifact = c.entry, c.resolver, filepath.Join(c.oldHome, ".codex", "config.toml")
				}
				stray := writeFixup2StrayReceipt(t, entry.UserHome, "notes", name, kind)
				outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("same-home removal with %s = %v, %v", stray, outcome, err)
				}
				if name == "opencode" {
					if _, err := os.Lstat(artifact); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("plugin remains: %v", err)
					}
				} else {
					data, err := os.ReadFile(artifact)
					if err != nil || strings.Contains(string(data), ".defenseclaw/") || strings.Contains(string(data), "x-defenseclaw-") {
						t.Fatalf("Codex entries remain: %v, %q", err, data)
					}
				}
			})
		}
	}
}

func TestStandaloneCleanupRehomedStrayReceiptKeepsRow(t *testing.T) {
	for _, tc := range []struct {
		name, kind, location string
		move                 bool
	}{
		{name: "copied current invalid", kind: "invalid json", location: "current"},
		{name: "copied current version zero", kind: "version zero", location: "current"},
		{name: "copied current wrong location", kind: "wrong location", location: "current"},
		{name: "moved current invalid", kind: "invalid json", location: "current", move: true},
		{name: "moved current version zero", kind: "version zero", location: "current", move: true},
		{name: "moved current wrong location", kind: "wrong location", location: "current", move: true},
		{name: "copied old wrong location", kind: "wrong location", location: "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := setupRehomedOpenCodeCase(t, false, tc.move)
			home := c.currentHome
			if tc.location == "old" {
				home = c.oldHome
			}
			stray := writeFixup2StrayReceipt(t, home, "notes", "opencode", tc.kind)
			if tc.location == "current" {
				previousRunner := enterpriseHookWorkerRunner
				t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
				calls := 0
				enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
					calls++
					return previousRunner(ctx, account, request)
				}
				defer func() {
					if calls != 3 { // one worker on each attempt, then remove-all
						t.Errorf("unverified reports triggered a retry: %d worker runs", calls)
					}
				}()
			}
			for attempt := 1; attempt <= 2; attempt++ {
				outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
				if outcome != enterpriseHookUserCleanupFailed || err == nil || !strings.Contains(err.Error(), stray) {
					t.Fatalf("attempt %d = %v, %v; want unverified receipt %s", attempt, outcome, err, stray)
				}
			}
			if _, err := os.Lstat(c.newPlugin); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("current plugin remains after two worker removals: %v", err)
			}
			if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			if report.Removed != 0 || len(report.Failed) != 1 || !strings.Contains(report.Failed[0], stray) ||
				skip[c.entry.UID] != enterpriseHookPurgeSkipFailed {
				t.Fatalf("remove-all lost unverified receipt: report %+v, skip %+v", report, skip)
			}
		})
	}
}

func TestTypedRehomeLongUnverifiedReceiptKeepsRemedy(t *testing.T) {
	oldHome, currentHome := longRehomeReportTestPath("old"), longRehomeReportTestPath("new")
	receipt := filepath.Join(currentHome, ".defenseclaw", "connector_backups", "opencode", "notes.json")
	report := enterpriseHookWorkerTargetResult{Unverified: enterpriseHookWorkerUnverifiedReason(
		fmt.Errorf("load managed backup %s: %s", receipt, strings.Repeat("invalid receipt ", 100)))}
	if err := validateEnterpriseHookWorkerRemoveReport(report); err != nil {
		t.Fatalf("worker reason is invalid: %v", err)
	}
	path, problem := enterpriseHookCleanupReportProblem(report, currentHome)
	changed := &enterpriseHookTargetHomeChangedError{name: "sample-user", home: oldHome, directoryHome: currentHome}
	err := newEnterpriseHookCleanupUnverifiedError(changed,
		enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user"}, currentHome,
		filepath.Join(currentHome, ".defenseclaw"), path, problem, report)
	for _, tc := range []struct {
		name string
		max  int
		text string
	}{
		{"ledger and guardian", enterpriseHookUserCleanupErrorMax, enterpriseHookUserCleanupFailureText(err)},
		{"remove-all", 768, enterpriseHookRehomedReportReason(err)},
	} {
		if len(tc.text) > tc.max || !utf8.ValidString(tc.text) ||
			!strings.Contains(tc.text, "notes.json") ||
			!strings.Contains(tc.text, "delete the stale copied receipt under") ||
			!strings.Contains(tc.text, "rerun") {
			t.Fatalf("%s lost the receipt or remedy (%d bytes): %q", tc.name, len(tc.text), tc.text)
		}
	}
}
