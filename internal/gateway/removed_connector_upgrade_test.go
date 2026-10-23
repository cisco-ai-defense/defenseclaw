// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// until 1.1: what an OpenHands setup of 1.0.x left in a data directory.
type retiredOpenHandsHost struct {
	home, dataDir, script, hooksPath, patchedHooks string
}

const (
	retiredOpenHandsOperatorHooks = `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`
	// The head of the hook script 1.0.0 through 1.0.3 rendered.
	retiredOpenHandsScript = "#!/bin/bash\n# defenseclaw-managed-hook v6\n# DefenseClaw OpenHands hook — forwards OpenHands lifecycle hook payloads\n" +
		"# to the DefenseClaw gateway.\nexec \"$HOME/.defenseclaw/bin/defenseclaw-hook\" openhands \"$@\"\n"
)

func stageRetiredOpenHands(t *testing.T) retiredOpenHandsHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands was never set up on Windows")
	}
	h := retiredOpenHandsHost{home: testenv.PrivateTempDir(t)}
	restore, err := connector.BindUserHomeDir(h.home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	h.dataDir = filepath.Join(h.home, ".defenseclaw")
	h.script = filepath.Join(h.dataDir, "hooks", "openhands-hook.sh")
	h.hooksPath = filepath.Join(h.home, ".openhands", "hooks.json")
	writeRetiredFile(t, h.script, retiredOpenHandsScript)
	h.patchedHooks = `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]},` +
		`{"matcher":"*","hooks":[{"type":"command","command":"` + h.script + `","timeout":60}]}]}`
	writeRetiredSetupRecord(t, h.dataDir, "openhands", "config", h.hooksPath, []byte(retiredOpenHandsOperatorHooks), h.patchedHooks)
	// The hook contract lock as 1.0.3 wrote it.
	digest := sha256.Sum256([]byte(retiredOpenHandsScript))
	writeRetiredFile(t, filepath.Join(h.dataDir, "hook_contract_lock.json"), `{"version":2,"updated_at":"2026-10-01T00:00:00Z","connectors":{"openhands":{`+
		`"connector":"openhands","contract_id":"openhands-hooks-v1","compatibility_status":"supported","hook_script_version":"v6",`+
		`"hook_script_digests":{"openhands-hook.sh":"sha256:`+hex.EncodeToString(digest[:])+`"},`+
		`"defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"}}}`+"\n")
	if got := connector.LoadHookContractLockEntry(h.dataDir, "openhands"); got.HookScriptDigests["openhands-hook.sh"] == "" {
		t.Fatalf("staged 1.0.3 lock entry did not load: %+v", got)
	}
	if _, err := connector.EnsureHookAPIToken(h.dataDir, "openhands"); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h retiredOpenHandsHost) requireTornDown(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(h.hooksPath)
	if err != nil || string(data) != h.patchedHooks {
		t.Fatalf("OpenHands hooks after the upgrade = %s, %v; want them as setup left them: %s", data, err, h.patchedHooks)
	}
	if body, err := os.ReadFile(h.script); err != nil || !strings.Contains(string(body), "disabled tombstone") ||
		!strings.Contains(string(body), "exit 2") || !strings.Contains(string(body), "OpenHands support was removed in DefenseClaw 1.0.4") {
		t.Fatalf("hook script after the upgrade = %q, %v; want the stub that blocks every call", body, err)
	}
	if got := connector.LoadHookContractLockEntry(h.dataDir, "openhands"); got.Connector != "openhands" {
		t.Fatalf("the openhands lock entry was cleared: %+v", got)
	}
	// The hook token stays: a copy of the old hook reads it (G-deadcode loop
	// round 2, removed_connector_copied_hook_unix_test.go).
	if token, err := connector.LoadHookAPIToken(h.dataDir, "openhands"); err != nil || token == "" {
		t.Fatalf("openhands token = %q, %v; want it kept", token, err)
	}
	if _, err := os.Lstat(filepath.Join(h.dataDir, "connector_backups", "openhands", "config.json")); err != nil {
		t.Fatalf("the hooks.json backup record was removed: %v", err)
	}
	if leftovers, _ := connector.RemovedConnectorLeftovers("openhands", connector.SetupOpts{DataDir: h.dataDir}); len(leftovers) == 0 ||
		leftovers[0].Path != h.hooksPath {
		t.Fatalf("leftovers = %+v, want hooks.json first", leftovers)
	}
}

// until 1.1: the first gateway start after an upgrade from a release that
// set up OpenHands turns the hook script into the stub that blocks every call
// and keeps the hook token; hooks.json, the backups and the lock stay, and are
// listed for the user to remove by hand.
func TestUpgradeTearsDownTheRemovedOpenHandsConnector(t *testing.T) {
	h := stageRetiredOpenHands(t)
	if err := connector.SaveActiveConnector(h.dataDir, "openhands"); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: h.dataDir}
	if err := teardownPreviousConnector(connector.NewDefaultRegistry(), "codex", opts, context.Background()); err != nil {
		t.Fatalf("teardown of the removed connector: %v", err)
	}
	h.requireTornDown(t)
}

// until 1.1: the whole upgrade from published 1.0.2 with OpenHands set up
// next to five surviving connectors (GAP-0290): its config.yaml loads in the
// new runtime with OpenHands dropped, and the boot path a guardrail-enabled
// gateway runs tears OpenHands down while every surviving connector stays.
func TestUpgradeFrom102LoadsTheConfigAndCleansUpOpenHands(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	h := stageRetiredOpenHands(t)
	t.Setenv("DEFENSECLAW_HOME", h.dataDir)
	raw, err := os.ReadFile(filepath.Join("..", "cli", "testdata", "retired-connector-upgrade", "1.0.2.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(h.dataDir, "config.yaml")
	source := []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "@HOME@", filepath.ToSlash(h.dataDir)))
	writeRetiredFile(t, configPath, string(source))
	cfg, err := config.LoadRuntimeV8FromBytes(configPath, source)
	if err != nil {
		t.Fatalf("the 1.0.2 config does not load: %v", err)
	}
	names := cfg.ActiveConnectors()
	want := []string{"claudecode", "codex", "copilot", "hermes", "opencode"}
	got := append([]string(nil), names...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active connectors = %v, want %v", got, want)
	}
	if !cfg.Guardrail.Enabled {
		t.Fatal("the upgrade turned the guardrail off")
	}
	previous := append(append([]string(nil), want...), "openhands")
	if err := connector.SaveActiveConnectors(h.dataDir, previous); err != nil {
		t.Fatal(err)
	}

	s := multiBootSidecar(t)
	s.cfg = cfg
	lockState, err := connector.CaptureHookContractLockSnapshot(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	candidates, unavailable := s.removedConnectorRollbackCandidates(
		connector.NewDefaultRegistry(), connector.LoadActiveConnectors(h.dataDir), names,
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key", lockState,
	)
	if len(unavailable) != 0 {
		t.Fatalf("removed connectors kept for retry: %v", unavailable)
	}
	if _, failed := teardownRemovedConnectorCandidates(candidates, context.Background()); len(failed) != 0 {
		t.Fatalf("removed connector teardown failed: %v", failed)
	}
	h.requireTornDown(t)
}
