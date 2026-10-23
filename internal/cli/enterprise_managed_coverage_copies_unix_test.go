//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func privateInstallFacts(t *testing.T, install enterprisehooks.PrivateAgentInstall) map[string]any {
	t.Helper()
	data, err := json.Marshal(install)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]any{}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

// The root parent keeps a worker's copy in a machine prefix, as it keeps
// one in the home, and turns any other claim into an incomplete scan with
// a known reason, once per connector (GAP-0891).
func TestEnumerateDiscoverPrivateInstallsAcceptsMachinePrefixCopies(t *testing.T) {
	home := t.TempDir()
	prior := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = prior })
	machine := "/usr/local/lib/node_modules/@anthropic-ai/claude-code"
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		var claims []enterprisehooks.PrivateAgentInstall
		for _, raw := range []string{
			`{"connector":"claudecode","version":"2.0.77","path":"` + machine + `"}`,
			`{"connector":"claudecode","path":"` + machine + `-other","untrusted":true}`,
			`{"connector":"claudecode","version":"2.0.77","path":"/etc/shadow"}`,
			`{"connector":"claudecode","version":"2.0.77","path":"` + home + `/x/../../elsewhere"}`,
			`{"connector":"claudecode","incomplete":true,"skipped":"version_manager_limit"}`,
			`{"connector":"codex","incomplete":true,"skipped":"$(id)"}`,
		} {
			var claim enterprisehooks.PrivateAgentInstall
			if err := json.Unmarshal([]byte(raw), &claim); err != nil {
				t.Fatal(err)
			}
			claims = append(claims, claim)
		}
		return enterpriseHookWorkerResponse{PrivateInstalls: claims}, nil
	}
	account := unixidentity.Account{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	found, err := enterpriseHooksEnumerateDiscoverAll(context.Background(), account, []string{"claudecode", "codex"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, install := range found.PrivateInstalls {
		facts := privateInstallFacts(t, install)
		skipped, _ := facts["skipped"].(string)
		got = append(got, strings.Join([]string{install.Connector, install.Version, install.Path,
			map[bool]string{true: "incomplete"}[install.Incomplete], map[bool]string{true: "untrusted"}[facts["untrusted"] == true], skipped}, "|"))
	}
	want := []string{
		"claudecode|2.0.77|" + machine + "|||",
		"claudecode||" + machine + "-other||untrusted|",
		"claudecode|||incomplete||" + enterprisehooks.PrivateInstallSkippedOutsideRoots,
		"codex|||incomplete||",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("worker claims kept:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A retained discovery record says why the last complete scan is shown, in
// --json and in the text view (GAP-0889).
func TestEnterpriseDiscoveryShowsTheRetainedScanExplanation(t *testing.T) {
	previous := enterpriseDiscoveryReadRecord
	t.Cleanup(func() { enterpriseDiscoveryReadRecord = previous })
	stubEnterpriseDiscoveryRuntime(t, nil, errors.New("stub"))
	enterpriseDiscoveryReadRecord = func(path string) (inventory.UserScanRecord, error) {
		var record inventory.UserScanRecord
		data, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(data, &record)
		}
		return record, err
	}
	dir := t.TempDir()
	scanned := time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC)
	record := inventory.UserScanRecord{Version: inventory.UserScanRecordVersion, UID: 1204, User: "t8b2minv", UpdatedAt: scanned,
		Report: inventory.AIDiscoveryReport{
			Summary: inventory.AIDiscoverySummary{Result: "partial", DetectorErrors: map[string]string{"user_scan": enterpriseHookAIDiscoveryRetainedNote}},
			Signals: []inventory.AISignal{{Name: "Claude Code", Category: "agent_cli", SupportedConnector: "claudecode", State: "active", LastSeen: scanned}},
		}}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(dir, "1204.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var asJSON bytes.Buffer
	if err := writeEnterpriseDiscovery(&asJSON, dir, "1204", true); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accounts []map[string]json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(asJSON.Bytes(), &doc); err != nil || len(doc.Accounts) != 1 {
		t.Fatalf("json view: %v\n%s", err, asJSON.String())
	}
	var detectors map[string]string
	_ = json.Unmarshal(doc.Accounts[0]["detector_errors"], &detectors)
	if detectors["user_scan"] != enterpriseHookAIDiscoveryRetainedNote || !strings.Contains(string(doc.Accounts[0]["result"]), "partial") {
		t.Fatalf("retained account in JSON = %s", asJSON.String())
	}
	for _, user := range []string{"", "t8b2minv"} {
		var text bytes.Buffer
		if err := writeEnterpriseDiscovery(&text, dir, user, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text.String(), "result partial") || !strings.Contains(text.String(), "user_scan: "+enterpriseHookAIDiscoveryRetainedNote) {
			t.Fatalf("text view for %q:\n%s", user, text.String())
		}
	}
}
