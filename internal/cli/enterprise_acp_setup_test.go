// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// A managed user runs the setup the enrollment reports, on a host with no
// Python CLI: it writes the guarded editor entry into the user settings file
// (JSONC, other entries and the leading comment kept) and a contract lock the
// guard accepts, and a second entry of the same editor re-pins the first
// lock, whose settings digest it changed (GAP-0254).
// A program of that name in the current folder is refused in words, not as
// "not found" (GAP-0734).
func TestResolveACPExecutableNamesTheCurrentFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH lookup of the current folder differs on Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dcfakeagent"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	if _, err := resolveACPExecutable("dcfakeagent", "Fake Agent"); err == nil || !strings.Contains(err.Error(), "current folder") {
		t.Fatalf("err = %v, want the current-folder refusal", err)
	}
}

func TestEnterpriseACPUserSetupWritesAnEntryAndALockTheGuardAccepts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows editor settings path is covered by the live managed run")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dataDir := filepath.Join(home, ".defenseclaw")
	settings := filepath.Join(home, ".config", "zed", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "// Zed settings\n{\n  // theme\n  \"theme\": \"One Dark\",\n  \"agent_servers\": {\"Other\": {\"command\": \"other\",},},\n}\n"
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if guard, err = filepath.EvalSymlinks(guard); err != nil {
		t.Fatal(err)
	}
	stubEnterpriseACPGuardCustody(t)
	serviceDir := t.TempDir()
	enroll := func(agent string) string {
		t.Helper()
		credential, err := acp.EnsureEnterpriseCredential(serviceDir, "uid:1001", "zed", agent, "locked")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := acp.PublishEnterpriseUserToken(dataDir, "zed", agent, credential.Token); err != nil {
			t.Fatal(err)
		}
		command := map[string]string{"kiro": "kiro-cli", "hermes": "hermes"}[agent]
		binary := filepath.Join(t.TempDir(), command)
		if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return binary
	}
	setup := func(agent, binary string) (enterpriseACPUserSetupResult, error) {
		return setupEnterpriseACPUserFiles(enterpriseACPUserSetup{
			client: "zed", agent: agent, profile: "locked", mode: acp.ModeAction, dataDir: dataDir, guard: guard,
			agentBinary: binary, gatewayURL: "http://127.0.0.1:18970/api/v1/acp/evaluate",
		})
	}

	if _, err := setup("kiro", filepath.Join(t.TempDir(), "openhands")); err == nil ||
		!strings.Contains(err.Error(), "is not the Kiro executable") {
		// A user enrolled for one agent ran another under it (GAP-0398).
		t.Fatalf("setup accepted another program as the enrolled agent: %v", err)
	}
	if _, err := setup("kiro", "kiro-cli"); err == nil {
		t.Fatal("setup without an enrolled token succeeded")
	} else if body, _ := os.ReadFile(settings); string(body) != original {
		t.Fatalf("a refused setup changed the settings file: %s", body)
	}
	kiroBinary := enroll("kiro")
	result, err := setup("kiro", kiroBinary)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "// Zed settings\n") {
		t.Fatalf("the leading comment was lost:\n%s", body)
	}
	var document struct {
		Theme   string                    `json:"theme"`
		Servers map[string]map[string]any `json:"agent_servers"`
	}
	if err := json.Unmarshal(enterprisepolicy.StripJSONC(body), &document); err != nil {
		t.Fatalf("the rewritten settings are not valid: %v\n%s", err, body)
	}
	entry := document.Servers["DefenseClaw · Kiro"]
	args, _ := json.Marshal(entry["args"])
	if document.Theme != "One Dark" || document.Servers["Other"]["command"] != "other" ||
		entry["command"] != guard || entry["type"] != "custom" ||
		!strings.Contains(string(args), `"--contract-lock","`+result.contractLock+`"`) ||
		!strings.Contains(string(args), `"--token-file","`+result.tokenFile+`"`) {
		t.Fatalf("settings do not carry the guarded entry next to the existing ones:\n%s", body)
	}
	validate := func(agent, binary, lock string) {
		t.Helper()
		resolved, err := filepath.EvalSymlinks(binary)
		if err != nil {
			t.Fatal(err)
		}
		if err := acp.ValidateRuntimeContract(lock, "zed", agent, "locked", acp.ModeAction, resolved); err != nil {
			t.Fatalf("the guard refuses the %s lock: %v", agent, err)
		}
	}
	validate("kiro", kiroBinary, result.contractLock)

	hermesBinary := enroll("hermes")
	type setupOutcome struct {
		result enterpriseACPUserSetupResult
		err    error
	}
	done := make(chan setupOutcome, 1)
	if err := withACPUserSetupLock(settings, func() error {
		started := make(chan struct{})
		go func() {
			close(started)
			result, setupErr := setup("hermes", hermesBinary)
			done <- setupOutcome{result, setupErr}
		}()
		<-started
		select {
		case outcome := <-done:
			return fmt.Errorf("concurrent setup finished before the editor transaction was released: %v", outcome.err)
		case <-time.After(250 * time.Millisecond):
			return nil
		}
	}); err != nil {
		t.Fatal(err)
	}
	outcome := <-done
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	hermes := outcome.result
	validate("hermes", hermesBinary, hermes.contractLock)
	validate("kiro", kiroBinary, result.contractLock)
}

// stubEnterpriseACPGuardCustody accepts the test binary as the guard: it is
// not in an administrator-owned directory.
func stubEnterpriseACPGuardCustody(t *testing.T) {
	t.Helper()
	old := enterpriseACPGuardCustody
	enterpriseACPGuardCustody = func(string) error { return nil }
	t.Cleanup(func() { enterpriseACPGuardCustody = old })
}

// A managed setup pins only the administrator-owned guard: a copy in the home
// is refused and nothing is written (GAP-0426).
func TestEnterpriseACPUserSetupRefusesAGuardTheUserOwns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows custody check is covered by the live managed run")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dataDir := filepath.Join(home, ".defenseclaw")
	credential, err := acp.EnsureEnterpriseCredential(t.TempDir(), "uid:1001", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acp.PublishEnterpriseUserToken(dataDir, "zed", "kiro", credential.Token); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "my-acp-guard")
	agent := filepath.Join(home, "kiro-cli")
	for _, path := range []string{guard, agent} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, err = setupEnterpriseACPUserFiles(enterpriseACPUserSetup{
		client: "zed", agent: "kiro", profile: "locked", mode: acp.ModeObserve, dataDir: dataDir, guard: guard,
		agentBinary: agent, gatewayURL: "http://127.0.0.1:18970/api/v1/acp/evaluate",
	})
	if err == nil || !strings.Contains(err.Error(), "not the administrator-owned DefenseClaw ACP guard") {
		t.Fatalf("a guard in the home was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".config", "zed", "settings.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a refused setup wrote the editor settings: %v", statErr)
	}
}
