// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// A managed user runs the setup the enrollment reports, on a host with no
// Python CLI: it writes the guarded editor entry into the user settings file
// (JSONC, other entries and the leading comment kept) and a contract lock the
// guard accepts, and a second entry of the same editor re-pins the first
// lock, whose settings digest it changed (GAP-0254).
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
		binary := filepath.Join(t.TempDir(), agent+"-cli")
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
	hermes, err := setup("hermes", hermesBinary)
	if err != nil {
		t.Fatal(err)
	}
	validate("hermes", hermesBinary, hermes.contractLock)
	validate("kiro", kiroBinary, result.contractLock)
}
