// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubEnumerateRunningAgents(t *testing.T, processes []inventory.AgentProcess, processErr error, sids map[string]string) {
	t.Helper()
	previousProcesses, previousLookup := enterpriseWindowsEnumerateAgentProcesses, enterpriseWindowsEnumerateAccountSID
	t.Cleanup(func() {
		enterpriseWindowsEnumerateAgentProcesses, enterpriseWindowsEnumerateAccountSID = previousProcesses, previousLookup
	})
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) { return processes, processErr }
	enterpriseWindowsEnumerateAccountSID = func(account string) string { return sids[account] }
	resetEnumerateKnownSIDs(t)
}

func resetEnumerateKnownSIDs(t *testing.T) {
	t.Helper()
	known := &enterpriseWindowsEnumerateKnownSIDs
	known.Lock()
	known.byAccount = map[string]string{}
	known.Unlock()
	t.Cleanup(func() {
		known.Lock()
		known.byAccount = map[string]string{}
		known.Unlock()
	})
}

// GAP-0226: the enumerator is told which agent sessions run, by account SID
// and connector, so a running agent no row enrolls is reported.
func TestEnterpriseWindowsEnumerateRunningAgentsBySID(t *testing.T) {
	const alice, bob = "S-1-12-1-3570884736-1162376387-1447295907-1452683434", "S-1-5-21-1-2-3-1001"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 10, Connector: "Codex", User: `AzureAD\EntraAlice`},
		{PID: 11, Connector: "codex", User: `azuread\entraalice`},
		{PID: 12, Connector: "claudecode", User: `DCLAB\bob`},
		{PID: 13, Connector: "codex", User: `DCLAB\gone`},
		{PID: 14, Connector: "codex", User: ""},
	}, nil, map[string]string{`AzureAD\EntraAlice`: alice, `DCLAB\bob`: bob})
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex", "claudecode"})
	if len(got) != 2 || got[alice]["codex"] != "codex (pid 10)" || got[bob]["claudecode"] != "claudecode (pid 12)" {
		t.Fatalf("running agents = %+v", got)
	}
	if len(unknown) != 2 || unknown[0].User != `DCLAB\gone` || unknown[0].Connector != "codex" || unknown[0].SID != "" ||
		unknown[0].Code != enterprisehooks.UnprotectedCodeAgentUnprotected || !strings.Contains(unknown[0].Reason, "codex (pid 13)") ||
		!strings.Contains(unknown[0].Reason, "could not be resolved") {
		t.Fatalf("owner-unknown agents = %+v", unknown)
	}
	if unknown[1].User != "(unknown account)" || unknown[1].Connector != "codex" ||
		unknown[1].Code != enterprisehooks.UnprotectedCodeAgentUnprotected || !strings.Contains(unknown[1].Reason, "codex (pid 14)") {
		t.Fatalf("empty-account agent was dropped: %+v", unknown)
	}

	stderr := new(bytes.Buffer)
	stubEnumerateRunningAgents(t, nil, errors.New("snapshot denied"), nil)
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(stderr, []string{"codex"}); got != nil || unknown != nil || !strings.Contains(stderr.String(), "running agent sessions are unreadable") {
		t.Fatalf("unreadable sessions: %+v %+v, log %q", got, unknown, stderr.String())
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentWithoutOwner(t *testing.T) {
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 14, Connector: "codex"},
		{PID: 15, Connector: "opencode"},
	}, nil, nil)
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 0 || len(unknown) != 1 || unknown[0].User != "(unknown account)" ||
		unknown[0].Connector != "codex" || unknown[0].Code != enterprisehooks.UnprotectedCodeAgentUnprotected ||
		!strings.Contains(unknown[0].Reason, "codex (pid 14)") {
		t.Fatalf("running agents with no account name or SID: %+v %+v", got, unknown)
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentUsesSnapshotSIDWithoutAccountName(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 14, Connector: "codex", OwnerSID: sid}}, nil, nil)
	var calls atomic.Int32
	enterpriseWindowsEnumerateAccountSID = func(string) string {
		calls.Add(1)
		return ""
	}
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 1 || got[sid]["codex"] != "codex (pid 14)" || len(unknown) != 0 || calls.Load() != 0 {
		t.Fatalf("snapshot SID was not used directly: %+v %+v, lookups %d", got, unknown, calls.Load())
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentUsesSnapshotSIDWhenNameLookupStalls(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 14, Connector: "codex", User: "DOMAIN\\user", OwnerSID: sid}}, nil, nil)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int32
	enterpriseWindowsEnumerateAccountSID = func(string) string {
		calls.Add(1)
		<-release
		return ""
	}
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 1 || got[sid]["codex"] != "codex (pid 14)" || len(unknown) != 0 || calls.Load() != 0 {
		t.Fatalf("snapshot SID waited for a name lookup: %+v %+v, lookups %d", got, unknown, calls.Load())
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentUnknownOwnerSurvivesRecord(t *testing.T) {
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 14, Connector: "codex"}}, nil, nil)
	_, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	data, err := enterprisehooks.MarshalUnprotectedAgents(unknown)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || parsed[0].User != "(unknown account)" || parsed[0].Connector != "codex" ||
		!strings.Contains(parsed[0].Message(), "codex") || !strings.Contains(parsed[0].Message(), "not protected") ||
		!strings.Contains(parsed[0].Message(), "cannot tell whether a row enrolls it") {
		t.Fatalf("owner-unknown record or message = %+v", parsed)
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentsDeduplicatesUnknownOwner(t *testing.T) {
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 14, Connector: "codex"},
		{PID: 15, Connector: "codex"},
	}, nil, nil)
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 0 || len(unknown) != 1 || unknown[0].User != "(unknown account)" {
		t.Fatalf("duplicate owner-unknown entries: %+v %+v", got, unknown)
	}
}

// A failed or timed-out SID lookup must not drop a running agent from the
// unprotected record: the account keeps the SID an earlier cycle resolved,
// and an account never resolved is reported with its owner unknown, for an
// enabled connector only.
func TestEnterpriseWindowsEnumerateRunningAgentLookupFailureFailsClosed(t *testing.T) {
	const alice = "S-1-12-1-3570884736-1162376387-1447295907-1452683434"
	processes := []inventory.AgentProcess{{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`}}
	stubEnumerateRunningAgents(t, processes, nil, map[string]string{`AzureAD\EntraAlice`: alice})
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 0 {
		t.Fatalf("first cycle: %+v %+v", got, unknown)
	}
	// The domain controller stops answering: the cached SID keeps the row.
	enterpriseWindowsEnumerateAccountSID = func(string) string { return "" }
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 0 {
		t.Fatalf("failed lookup dropped the running agent: %+v %+v", got, unknown)
	}

	// Never resolved: owner unknown, unprotected; a disabled connector's
	// agent is not reported.
	resetEnumerateKnownSIDs(t)
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`},
			{PID: 11, Connector: "codex", User: `azuread\entraalice`},
			{PID: 12, Connector: "opencode", User: `AzureAD\EntraAlice`},
		}, nil
	}
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 0 || len(unknown) != 1 || unknown[0].User != `AzureAD\EntraAlice` || unknown[0].Connector != "codex" ||
		!strings.Contains(unknown[0].Message(), "codex for user AzureAD\\EntraAlice is not protected") {
		t.Fatalf("never-resolved account: %+v %+v", got, unknown)
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentLookupIsBounded(t *testing.T) {
	previousTimeout := enterpriseWindowsEnumerateRunningLookupTimeout
	t.Cleanup(func() { enterpriseWindowsEnumerateRunningLookupTimeout = previousTimeout })
	enterpriseWindowsEnumerateRunningLookupTimeout = 20 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 1, Connector: "codex", User: `DCLAB\slow`}}, nil, nil)
	enterpriseWindowsEnumerateAccountSID = func(string) string {
		<-release
		return "S-1-5-21-1-2-3-1009"
	}
	started := time.Now()
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); len(got) != 0 || len(unknown) != 1 {
		t.Fatalf("a lookup that does not answer must name no SID and report the owner unknown: %+v %+v", got, unknown)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("lookup took %s, want the bounded timeout", elapsed)
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentBudgetExhaustedForLaterAccount(t *testing.T) {
	previousBudget, previousTimeout := enterpriseWindowsEnumerateRunningLookupBudget, enterpriseWindowsEnumerateRunningLookupTimeout
	t.Cleanup(func() {
		enterpriseWindowsEnumerateRunningLookupBudget, enterpriseWindowsEnumerateRunningLookupTimeout = previousBudget, previousTimeout
	})
	enterpriseWindowsEnumerateRunningLookupBudget = 20 * time.Millisecond
	enterpriseWindowsEnumerateRunningLookupTimeout = 20 * time.Millisecond
	const knownSID = "S-1-5-21-1-2-3-1009"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 1, Connector: "codex", User: `DCLAB\slow`},
		{PID: 2, Connector: "codex", User: `DCLAB\later`},
	}, nil, nil)
	known := &enterpriseWindowsEnumerateKnownSIDs
	known.Lock()
	known.byAccount[`dclab\later`] = knownSID
	known.Unlock()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	enterpriseWindowsEnumerateAccountSID = func(string) string {
		<-release
		return ""
	}
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if got[knownSID]["codex"] != "codex (pid 2)" || len(unknown) != 1 || unknown[0].User != `DCLAB\slow` {
		t.Fatalf("budget exhausted with a cached later account: rows %+v, unknown %+v", got, unknown)
	}
	resetEnumerateKnownSIDs(t)
	got, unknown = enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 0 || len(unknown) != 2 || unknown[1].User != `DCLAB\later` {
		t.Fatalf("budget exhausted without a cached later account: rows %+v, unknown %+v", got, unknown)
	}
}

// The standalone cycle hands the running sessions to the enumerator; the
// Secure Client profile does not.
func TestEnterpriseWindowsEnumerateCyclePassesRunningAgents(t *testing.T) {
	const alice = "S-1-12-1-3570884736-1162376387-1447295907-1452683434"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`}}, nil, map[string]string{`AzureAD\EntraAlice`: alice})
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{})
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousCacheLoader := enterpriseWindowsEnumerateGroupCacheLoader
	previousCacheWriter := enterpriseWindowsEnumerateGroupCacheWriter
	previousRecordWriter := enterpriseWindowsEnumerateUnprotectedWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateGroupCacheLoader = previousCacheLoader
		enterpriseWindowsEnumerateGroupCacheWriter = previousCacheWriter
		enterpriseWindowsEnumerateUnprotectedWriter = previousRecordWriter
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	enterpriseWindowsEnumerateGroupCacheLoader = func(string) (*enterprisehooks.WindowsEnrollmentGroupCache, error) {
		return enterprisehooks.NewWindowsEnrollmentGroupCache(), nil
	}
	enterpriseWindowsEnumerateGroupCacheWriter = func(string, *enterprisehooks.WindowsEnrollmentGroupCache) (bool, error) { return false, nil }
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	var published []enterprisehooks.UnprotectedAgent
	enterpriseWindowsEnumerateUnprotectedWriter = func(_ string, agents []enterprisehooks.UnprotectedAgent) (bool, error) {
		published = agents
		return true, nil
	}
	var seen enterprisehooks.EnumerateOptions
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		seen = opts
		if label := opts.RunningAgents[alice]["codex"]; label != "" && opts.ReportUnprotected != nil {
			opts.ReportUnprotected(enterprisehooks.UnprotectedAgent{User: "EntraAlice", SID: alice, Connector: "codex", Reason: label + " runs for this account"})
		}
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifest); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if seen.RunningAgents[alice]["codex"] != "codex (pid 10)" {
		t.Fatalf("running agents not passed: %+v", seen.RunningAgents)
	}
	if len(published) != 1 || published[0].Connector != "codex" || !strings.Contains(published[0].Reason, "codex (pid 10)") {
		t.Fatalf("published = %+v", published)
	}

	// No cycle ever resolved this account. The owner-unknown entry must
	// reach the published record, survive its wire format, and make status
	// and verify security-incomplete without a SID.
	resetEnumerateKnownSIDs(t)
	// The cycle only reports an agent of an enabled connector.
	cfg.Guardrail.Connector = "codex"
	enterpriseWindowsEnumerateAccountSID = func(string) string { return "" }
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`},
			{PID: 11, Connector: "codex", User: `azuread\entraalice`},
		}, nil
	}
	published = nil
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifest); err != nil {
		t.Fatalf("owner-unknown cycle: %v", err)
	}
	if len(published) != 1 || published[0].SID != "" || published[0].Connector != "codex" {
		t.Fatalf("published owner-unknown entries = %+v, want one with no SID", published)
	}
	data, err := enterprisehooks.MarshalUnprotectedAgents(published)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil || len(parsed) != 1 || parsed[0].SID != "" || !strings.Contains(parsed[0].Message(), "could not be resolved") {
		t.Fatalf("read owner-unknown record = %+v, %v", parsed, err)
	}
	previousReader := windowsEnterpriseUnprotectedAgentsReader
	t.Cleanup(func() { windowsEnterpriseUnprotectedAgentsReader = previousReader })
	windowsEnterpriseUnprotectedAgentsReader = func() ([]enterprisehooks.UnprotectedAgent, error) { return parsed, nil }
	for _, action := range []string{"status", "verify"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.2")
		result.SecurityComplete = true
		applyWindowsEnterpriseUnprotectedAgents(result)
		if result.SecurityComplete || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0].Message, "could not be resolved") {
			t.Fatalf("%s owner-unknown status = %+v", action, result)
		}
	}
}
