// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the teardown-only OpenHands and OmniGent connectors (removed.go).
// Delete with that file.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemovedConnectorsUnavailable(t *testing.T) {
	registry := NewDefaultRegistry()
	for _, name := range []string{"openhands", "omnigent"} {
		if IsKnownBuiltinConnector(name) {
			t.Errorf("%s is still a built-in connector", name)
		}
		if _, found := registry.Get(name); found {
			t.Errorf("%s is still in the default registry", name)
		}
		if !IsRemovedConnector(name) || !IsRemovedConnector(strings.ToUpper(name)) {
			t.Errorf("IsRemovedConnector(%q) = false", name)
		}
	}
	for _, name := range []string{"codex", "claudecode", "", "openhands-x"} {
		if IsRemovedConnector(name) {
			t.Errorf("IsRemovedConnector(%q) = true", name)
		}
	}
}

// The removed IDs resolve only to a teardown-only connector that never sets
// up, authenticates or routes anything.
func TestRemovedConnectorsAreTeardownOnly(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"openhands", "openhands"}, {"Open-Hands", "openhands"}, {"OMNIGENT", "omnigent"},
	} {
		conn, ok := RetiredConnector(tc.name)
		if !ok || conn.Name() != tc.want {
			t.Fatalf("RetiredConnector(%q) = %v, %v; want %s", tc.name, conn, ok, tc.want)
		}
		if err := conn.Setup(context.Background(), SetupOpts{DataDir: t.TempDir()}); err == nil ||
			!strings.Contains(err.Error(), "removed in DefenseClaw 1.0.4") {
			t.Fatalf("%s Setup = %v, want the removal refusal", tc.want, err)
		}
		if conn.Authenticate(nil) {
			t.Fatalf("%s authenticated hook traffic", tc.want)
		}
		if _, err := conn.Route(nil, nil); err == nil {
			t.Fatalf("%s routed hook traffic", tc.want)
		}
		if err := conn.Teardown(context.Background(), SetupOpts{}); err == nil {
			t.Fatalf("%s Teardown with no data directory = nil", tc.want)
		}
	}
}

// --- fixture: a host an older release set up ---

const (
	// removedOpenHands103Script is the head of the hook script 0.8.10 through
	// 1.0.3 rendered: the marker is its second line.
	removedOpenHands103Script = "#!/bin/bash\n# defenseclaw-managed-hook v6\n# DefenseClaw OpenHands hook - forwards OpenHands lifecycle hook payloads\n" +
		"exec \"$HOME/.defenseclaw/bin/defenseclaw-hook\" hook --connector openhands \"$@\"\n"
	removedOmnigent103Module = "# defenseclaw-managed-policy v1\n\"\"\"OmniGent custom policy bridge installed by DefenseClaw.\"\"\"\n\n" +
		"def defenseclaw_policy(event):\n    return {\"result\": \"ALLOW\"}\n"
	removedOpenHandsOperatorHooks = `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`
	removedOmnigentOperatorConfig = "policy_modules:\n  - corp_policy\n"
)

// removedHost is a home and data directory where an older release set up a
// removed connector next to a surviving one (Codex).
type removedHost struct {
	home, dataDir string
	opts          SetupOpts
	// agentConfig is the agent config setup patched; pth the OmniGent
	// import path file.
	agentConfig, pth string
}

func writeRemovedFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func newRemovedHost(t *testing.T) *removedHost {
	t.Helper()
	// Not t.TempDir: the shell tests run commands under the home, and a
	// blank or quote from a test's name would change how they read.
	home, err := os.MkdirTemp("", "removed-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	t.Setenv("OMNIGENT_CONFIG", "")
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The surviving connector.
	if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	codexScript := filepath.Join(dataDir, "hooks", "codex-hook.sh")
	writeRemovedFile(t, filepath.Join(home, ".codex", "config.toml"), "[hooks]\ncommand = \""+codexScript+"\"\n", 0o600)
	writeRemovedFile(t, codexScript, "#!/bin/sh\n# defenseclaw-managed-hook v1\n", 0o700)
	writeRemovedFile(t, filepath.Join(dataDir, "hooks", ".hookcfg.codex"), "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n", 0o600)
	return &removedHost{home: home, dataDir: dataDir, opts: SetupOpts{DataDir: dataDir}}
}

func (h *removedHost) script(c removedOnlyConnector) string { return c.scriptPath(h.dataDir) }

// recordSetup does what an older setup did for one file: back up what it
// found (none when before is ""), then write body.
func (h *removedHost) recordSetup(t *testing.T, connectorName, logical, path, before, body string) {
	t.Helper()
	if before != "" {
		writeRemovedFile(t, path, before, 0o600)
	}
	if err := captureManagedFileBackup(h.dataDir, connectorName, logical, path); err != nil {
		t.Fatal(err)
	}
	writeRemovedFile(t, path, body, 0o600)
	if err := updateManagedFileBackupPostHash(h.dataDir, connectorName, logical, path); err != nil {
		t.Fatal(err)
	}
}

// stage leaves what a 1.0.3 setup of c left: the agent config, its backup
// records, the script, the tokens, the runtime record and the shared hook
// state, and a hook contract lock that holds c and Codex.
func (h *removedHost) stage(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	hooks := filepath.Join(h.dataDir, "hooks")
	switch c.name {
	case removedOpenHandsID:
		h.agentConfig = filepath.Join(h.home, ".openhands", "hooks.json")
		h.recordSetup(t, c.name, "config", h.agentConfig, removedOpenHandsOperatorHooks,
			`{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]},`+
				`{"matcher":"*","hooks":[{"type":"command","command":"`+h.script(c)+`","timeout":60}]}]}`)
		writeRemovedFile(t, h.script(c), removedOpenHands103Script, 0o700)
		writeRemovedFile(t, filepath.Join(hooks, hookConfigSidecarName+".openhands"), "DEFENSECLAW_CONNECTOR=openhands\nDEFENSECLAW_FAIL_MODE=closed\n", 0o600)
	case removedOmnigentID:
		h.agentConfig = filepath.Join(h.home, ".omnigent", "config.yaml")
		h.pth = filepath.Join(h.home, "venv", "site-packages", "defenseclaw_omnigent.pth")
		h.recordSetup(t, c.name, "config", h.agentConfig, removedOmnigentOperatorConfig,
			removedOmnigentOperatorConfig+"  - "+removedOmnigentModuleName+"\npolicies:\n  "+removedOmnigentPolicyKey+":\n    handler: "+removedOmnigentModuleName+".defenseclaw_policy\n")
		h.recordSetup(t, c.name, "pth", h.pth, "", hooks+"\n")
		h.recordSetup(t, c.name, "module", h.script(c), "", removedOmnigent103Module)
	}
	writeRemovedFile(t, filepath.Join(hooks, hookConfigSidecarName), "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n", 0o600)
	writeRemovedFile(t, filepath.Join(h.dataDir, hookContractLockFile), `{"version":2,"updated_at":"2026-10-01T00:00:00Z","connectors":{`+
		`"codex":{"connector":"codex","contract_id":"codex-hooks-v1","hook_script_digests":{"codex-hook.sh":"sha256:00"},"defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"},`+
		`"`+c.name+`":{"connector":"`+c.name+`","contract_id":"`+c.name+`-hooks-v1","hook_script_digests":{"`+c.script+`":"sha256:00"},`+
		`"locations":{"hook_config_paths":["`+filepath.ToSlash(h.agentConfig)+`"]},"defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"}}}`+"\n", 0o600)
	if got := LoadHookContractLockEntry(h.dataDir, c.name); got.Connector != c.name {
		t.Fatalf("staged %s lock entry did not load: %+v", c.name, got)
	}
	if _, err := EnsureHookAPIToken(h.dataDir, c.name); err != nil {
		t.Fatal(err)
	}
	writeRemovedFile(t, c.otlpTokenPath(h.dataDir), "otlp-token\n", 0o600)
}

// snapshot reads every file, link and folder under the home, except skip.
func (h *removedHost) snapshot(t *testing.T, skip ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(h.home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		for _, skipped := range skip {
			if path == skipped {
				return nil
			}
		}
		if filepath.Base(path) == filepath.Base(hookAPITokenPublishLockPath(h.dataDir)) {
			// The lock the token writers share; revoking a token takes it.
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			out[path] = "symlink:" + target
		case entry.IsDir():
			out[path] = "<dir>"
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireRemovedSame(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	for path, body := range want {
		if got[path] != body {
			t.Fatalf("%s changed %s:\n got %q\nwant %q", what, path, got[path], body)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Fatalf("%s created %s", what, path)
		}
	}
}

func (h *removedHost) tokens(c removedOnlyConnector) []string { return c.tokenPaths(h.dataDir) }

func (h *removedHost) requireStub(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	data, err := os.ReadFile(h.script(c))
	if err != nil || string(data) != c.tombstone {
		t.Fatalf("%s = %q, %v; want the stub that blocks every call", h.script(c), data, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(h.script(c))
		if err != nil || info.Mode().Perm() != c.mode {
			t.Fatalf("%s mode = %v, %v; want %v", h.script(c), info.Mode(), err, c.mode)
		}
	}
}

func (h *removedHost) requireRevoked(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	for _, token := range h.tokens(c) {
		if _, err := os.Lstat(token); !os.IsNotExist(err) {
			t.Fatalf("token %s survived the teardown: %v", token, err)
		}
	}
	// The OpenHands hook token stays (keepHookToken); OmniGent's goes.
	if token, err := LoadHookAPIToken(h.dataDir, c.name); err != nil || (token == "") == (c.name == removedOpenHandsID) {
		t.Fatalf("%s hook token after the teardown = %q, %v; want kept only for OpenHands", c.name, token, err)
	}
	if token, err := LoadHookAPIToken(h.dataDir, "codex"); err != nil || token == "" {
		t.Fatalf("the surviving connector's token = %q, %v", token, err)
	}
}

func removedConnectorsUnderTest() []removedOnlyConnector {
	return []removedOnlyConnector{removedOpenHands, removedOmnigent}
}

// Review fixes (G-deadcode loop round 1, simplified teardown): the teardown
// put back, removed or deleted agent configs, import paths, policy modules,
// runtime records (.hookcfg, even one that was not DefenseClaw's), backups
// and records. It now changes only the script, the tokens, and a private
// saved copy of a marked OpenHands hook; every other file, link and folder
// stays byte for byte in both modes and on a second run.
func TestRemovedTeardownChangesOnlyTheScriptTokensAndSavedHook(t *testing.T) {
	runtimeRecords := map[string]func(t *testing.T, path string){
		"DefenseClaw's runtime record": func(*testing.T, string) {},
		"a user file":                  func(t *testing.T, path string) { writeRemovedFile(t, path, "my settings\n", 0o600) },
		"a directory": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			writeRemovedFile(t, filepath.Join(path, "keep"), "mine\n", 0o600)
		},
		"a symlink": func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(filepath.Dir(path)), "..", "mine.txt")
			writeRemovedFile(t, target, "mine\n", 0o600)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("symlink: %v", err)
			}
		},
	}
	for _, c := range removedConnectorsUnderTest() {
		for _, managed := range []bool{false, true} {
			for name, plant := range runtimeRecords {
				if c.name == removedOmnigentID && name != "DefenseClaw's runtime record" {
					continue
				}
				t.Run(c.name+"/managed="+map[bool]string{false: "no", true: "yes"}[managed]+"/"+name, func(t *testing.T) {
					h := newRemovedHost(t)
					h.stage(t, c)
					if c.name == removedOpenHandsID {
						plant(t, filepath.Join(h.dataDir, "hooks", hookConfigSidecarName+".openhands"))
					}
					h.opts.ManagedEnterprise = managed
					skip := append([]string{h.script(c)}, h.tokens(c)...)
					if c.name == removedOpenHandsID {
						skip = append(skip, c.editedCopyPath(h.dataDir, []byte(removedOpenHands103Script)))
					}
					before := h.snapshot(t, skip...)
					conn, _ := RetiredConnector(c.name)
					for run := 1; run <= 2; run++ {
						if err := conn.Teardown(context.Background(), h.opts); err != nil {
							t.Fatalf("Teardown run %d: %v", run, err)
						}
						requireRemovedSame(t, "teardown", h.snapshot(t, skip...), before)
						h.requireStub(t, c)
						h.requireRevoked(t, c)
						if c.name == removedOpenHandsID {
							h.requireEditedSaved(t, c, removedOpenHands103Script)
						}
					}
					if err := conn.VerifyClean(h.opts); err != nil {
						t.Fatalf("VerifyClean after the teardown: %v", err)
					}
				})
			}
		}
	}
}

// Review fixes (G-deadcode loop round 1): clearing a removed connector's hook
// contract lock entry, as every boot, Setup and uninstall path does after its
// teardown, rewrote the shared lock and .hookcfg with the per-user writer,
// also on a managed host, and removed .hookcfg.openhands unchecked. For a
// removed connector it is now a no-op in both modes; a surviving connector's
// entry is still cleared.
func TestRemovedConnectorLockEntryIsNeverCleared(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			before := h.snapshot(t)
			for _, managed := range []bool{false, true} {
				for _, spelling := range []string{c.name, strings.ToUpper(c.name), " " + c.label + " "} {
					if err := ClearHookContractLockEntryForMode(h.dataDir, spelling, managed); err != nil {
						t.Fatalf("clear %q managed=%v: %v", spelling, managed, err)
					}
					requireRemovedSame(t, "clearing "+spelling+"'s lock entry", h.snapshot(t), before)
				}
			}
			if err := ClearHookContractLockEntry(h.dataDir, "open-hands"); err != nil {
				t.Fatal(err)
			}
			requireRemovedSame(t, "clearing open-hands' lock entry", h.snapshot(t), before)
			if err := ClearHookContractLockEntry(h.dataDir, "codex"); err != nil {
				t.Fatalf("clear codex: %v", err)
			}
			if got := LoadHookContractLockEntry(h.dataDir, "codex"); got.Connector != "" {
				t.Fatalf("the codex entry survived its clear: %+v", got)
			}
			if got := LoadHookContractLockEntry(h.dataDir, c.name); got.Connector != c.name {
				t.Fatalf("clearing codex dropped the %s entry: %+v", c.name, got)
			}
		})
	}
}

// A known token-path refusal is found before the stub changes anything. A
// publication that fails leaves the old script whole for a retry, with its
// tokens; nothing is ever written into it. VerifyClean fails until cleanup
// finishes.
func TestRemovedTeardownFailuresRemainRetryable(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name+"/a token cannot be revoked", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			otlp := c.otlpTokenPath(h.dataDir)
			if err := os.Remove(otlp); err != nil {
				t.Fatal(err)
			}
			writeRemovedFile(t, filepath.Join(otlp, "blocker"), "x", 0o600)
			before := h.snapshot(t)
			conn, _ := RetiredConnector(c.name)
			err := conn.Teardown(context.Background(), h.opts)
			if err == nil || !strings.Contains(err.Error(), otlp) || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("Teardown = %v, want the token failure naming %s", err, otlp)
			}
			requireRemovedSame(t, "a teardown refused at preflight", h.snapshot(t), before)
			if err := conn.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean passed with a token left")
			}
			if err := os.RemoveAll(otlp); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("retry: %v", err)
			}
			h.requireStub(t, c)
			h.requireRevoked(t, c)
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after the retry: %v", err)
			}
		})
		t.Run(c.name+"/the stub cannot be written", func(t *testing.T) {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory modes do not stop writes here")
			}
			h := newRemovedHost(t)
			h.stage(t, c)
			hooks := filepath.Join(h.dataDir, "hooks")
			skip := []string{}
			if c.name == removedOpenHandsID {
				skip = append(skip, c.editedCopyPath(h.dataDir, []byte(removedOpenHands103Script)))
			}
			before := h.snapshot(t, skip...)
			if err := os.Chmod(h.script(c), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(hooks, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "its tokens were kept") {
				t.Fatalf("Teardown = %v, want the stub failure", err)
			}
			if err := os.Chmod(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.script(c), c.mode); err != nil {
				t.Fatal(err)
			}
			requireRemovedSame(t, "a teardown that could not write the stub", h.snapshot(t, skip...), before)
			if err := conn.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean passed with the old hook in place")
			}
		})
		// The stub's copy cannot be renamed over the script: the old
		// script is left whole, the same file with its bytes, and the
		// tokens stay until the next start, which renames the stub and
		// revokes them. Nothing is ever written into the old script.
		t.Run(c.name+"/the stub's copy cannot be renamed", func(t *testing.T) {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory modes do not stop writes here")
			}
			h := newRemovedHost(t)
			h.stage(t, c)
			beforeBody, readErr := os.ReadFile(h.script(c))
			if readErr != nil {
				t.Fatal(readErr)
			}
			hooks := filepath.Join(h.dataDir, "hooks")
			var skip []string
			if c.name == removedOpenHandsID {
				skip = append(skip, c.editedCopyPath(h.dataDir, []byte(removedOpenHands103Script)))
			}
			first := removedFileIdentity(t, h.script(c))
			before := h.snapshot(t, skip...)
			if err := os.Chmod(hooks, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "publish the stub that blocks every call over") ||
				!strings.Contains(err.Error(), "its tokens were kept") {
				t.Fatalf("Teardown = %v, want the publication failure and the tokens kept", err)
			}
			if err := os.Chmod(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			requireRemovedNamesWhole(t, first, string(beforeBody), []string{h.script(c)})
			h.requireTokensKept(t, c)
			if err := conn.VerifyClean(h.opts); err == nil {
				t.Fatal("VerifyClean passed with the old script at the path")
			}
			requireRemovedSame(t, "a teardown whose publication failed", h.snapshot(t, skip...), before)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatalf("retry: %v", err)
			}
			h.requireStub(t, c)
			h.requireRevoked(t, c)
		})
	}
}

func TestRemovedTeardownRecoversInterruptedStubPublication(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, replacePath := range []bool{false, true} {
			name := "retry"
			if replacePath {
				name = "foreign_path"
			}
			t.Run(c.name+"/"+name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				path := h.script(c)
				conn, _ := RetiredConnector(c.name)
				var crashState atomicTransformPhaseState
				restore := setAtomicTransformPhaseHookForTest(path, func(phase atomicTransformPhase, state atomicTransformPhaseState) error {
					if phase == atomicTransformPhaseDetached {
						crashState = state
						return errAtomicTransformSimulatedCrash
					}
					return nil
				})
				err := conn.Teardown(context.Background(), h.opts)
				restore()
				if !errors.Is(err, errAtomicTransformSimulatedCrash) {
					t.Fatalf("interrupted Teardown = %v, want simulated crash", err)
				}
				if crashState.IntentPath == "" {
					t.Fatal("the detached publication has no recovery intent")
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("detached module path = %v, want absent", err)
				}
				if _, err := os.Lstat(crashState.IntentPath); err != nil {
					t.Fatalf("recovery intent: %v", err)
				}
				leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
				if !removedListsPath(leftovers, crashState.IntentPath) {
					t.Fatalf("leftovers do not name the interrupted publication receipt: %+v", leftovers)
				}
				backups := filepath.Join(h.dataDir, "connector_backups", c.name)
				listedBackups := false
				for _, item := range leftovers {
					if item.Path == backups {
						listedBackups = true
						if !strings.Contains(item.Step, "do not delete") || !strings.Contains(item.Step, "teardown") {
							t.Fatalf("pending publication backup guidance permits deletion: %+v", item)
						}
					}
				}
				if !listedBackups {
					t.Fatalf("leftovers do not preserve the backup folder %s: %+v", backups, leftovers)
				}
				if err := conn.VerifyClean(h.opts); err == nil || !strings.Contains(err.Error(), "interrupted") {
					t.Fatalf("VerifyClean with pending publication = %v, want interrupted-publication refusal", err)
				}
				if replacePath {
					writeRemovedFile(t, path, "operator module\n", 0o600)
					if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "recover") {
						t.Fatalf("Teardown with a foreign replacement = %v, want recovery refusal", err)
					}
					if got, err := os.ReadFile(path); err != nil || string(got) != "operator module\n" {
						t.Fatalf("foreign replacement = %q, %v", got, err)
					}
					for _, token := range h.tokens(c) {
						if _, err := os.Lstat(token); err != nil {
							t.Fatalf("token revoked during refused recovery: %s: %v", token, err)
						}
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("retry after detached publication: %v", err)
				}
				h.requireStub(t, c)
				h.requireRevoked(t, c)
				if err := conn.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean after retry: %v", err)
				}
				if _, err := os.Lstat(crashState.IntentPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery intent survived retry: %v", err)
				}
			})
		}
	}
}

func removedTokenPath(t *testing.T, dataDir, connectorName string) string {
	t.Helper()
	path, err := HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The script is replaced when its DefenseClaw marker proves an older release
// wrote it: the hook or module as rendered or edited, and every older stub,
// including the ones that exited 0. Anything else at the path is never
// changed: no marker, a marker below the head, a link (and its target), a
// folder, a file too large to be DefenseClaw's.
func TestRemovedTeardownReplacesOnlyScriptsDefenseClawWrote(t *testing.T) {
	type variant struct {
		name    string
		plant   func(t *testing.T, path string)
		replace bool
		// saved is the edit the teardown saves before it replaces it
		// (keepEdited, G-deadcode loop round 3).
		saved string
	}
	write := func(body string) func(*testing.T, string) {
		return func(t *testing.T, path string) { writeRemovedFile(t, path, body, 0o700) }
	}
	// setup writes the module as the 1.0.3 setup did, with its backup
	// record, then body over it ("" for none).
	setup := func(body string) func(*testing.T, string) {
		return func(t *testing.T, path string) {
			dataDir := filepath.Dir(filepath.Dir(path))
			if err := captureManagedFileBackup(dataDir, removedOmnigentID, "module", path); err != nil {
				t.Fatal(err)
			}
			writeRemovedFile(t, path, removedOmnigent103Module, 0o600)
			if err := updateManagedFileBackupPostHash(dataDir, removedOmnigentID, "module", path); err != nil {
				t.Fatal(err)
			}
			if body != "" {
				writeRemovedFile(t, path, body, 0o600)
			}
		}
	}
	common := func(marker string) []variant {
		return []variant{
			{name: "no marker", plant: write("#!/bin/sh\necho my own hook\n")},
			{name: "the marker below the head", plant: write("#!/bin/sh\n#\n#\n#\n" + marker + "1\n")},
			{name: "too large", plant: write(marker + "1\n" + strings.Repeat("#\n", removedScriptReadLimit))},
			{name: "a folder", plant: func(t *testing.T, path string) { writeRemovedFile(t, filepath.Join(path, "keep"), "x", 0o600) }},
			{name: "a symlink to a marked file", plant: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(path), "..", "..", "elsewhere.sh")
				writeRemovedFile(t, target, marker+"6\n", 0o700)
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink: %v", err)
				}
			}},
		}
	}
	cases := map[string][]variant{
		removedOpenHandsID: append([]variant{
			{name: "the 1.0.3 hook", plant: write(removedOpenHands103Script), replace: true, saved: removedOpenHands103Script},
			{name: "the hook edited, marker kept", plant: write(removedOpenHands103Script + "echo edited\n"), replace: true, saved: removedOpenHands103Script + "echo edited\n"},
			{name: "the hook with CRLF lines", plant: write(strings.ReplaceAll(removedOpenHands103Script, "\n", "\r\n")), replace: true, saved: strings.ReplaceAll(removedOpenHands103Script, "\n", "\r\n")},
			{name: "the 1.0.x stub that exits 0", plant: write(disabledHookTombstone(removedOpenHandsID)), replace: true, saved: disabledHookTombstone(removedOpenHandsID)},
			{name: "an earlier 1.0.4 stub that exits 0", plant: write(disabledHookTombstone("OpenHands")), replace: true, saved: disabledHookTombstone("OpenHands")},
			{name: "an earlier 1.0.4 stub without -p", plant: write(strings.Replace(removedOpenHandsTombstone, "#!/bin/sh -p\n", "#!/bin/sh\n", 1)), replace: true, saved: strings.Replace(removedOpenHandsTombstone, "#!/bin/sh -p\n", "#!/bin/sh\n", 1)},
		}, common("# defenseclaw-managed-hook v")...),
		removedOmnigentID: append([]variant{
			{name: "the 1.0.3 module", plant: setup(""), replace: true},
			{name: "the module edited, marker kept", plant: setup(removedOmnigent103Module + "# edited\n"), replace: true, saved: removedOmnigent103Module + "# edited\n"},
			{name: "the module without its record", plant: write(removedOmnigent103Module), replace: true, saved: removedOmnigent103Module},
			{name: "a user's own policy module", plant: write("def defenseclaw_policy(event):\n    return {\"result\": \"ALLOW\"}\n")},
		}, common("# defenseclaw-managed-policy v")...),
	}
	for _, c := range removedConnectorsUnderTest() {
		for _, v := range cases[c.name] {
			t.Run(c.name+"/"+v.name, func(t *testing.T) {
				h := newRemovedHost(t)
				v.plant(t, h.script(c))
				var before map[string]string
				if v.replace {
					before = h.snapshot(t, h.script(c))
				} else {
					before = h.snapshot(t)
				}
				conn, _ := RetiredConnector(c.name)
				if !v.replace {
					// Left as it is, and the teardown says so with the step
					// that finishes it (see removed_r3_test.go).
					if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "To finish: ") {
						t.Fatalf("Teardown = %v, want the manual step", err)
					}
					requireRemovedSame(t, "teardown of a script DefenseClaw did not write", h.snapshot(t), before)
					leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
					if !removedListsPath(leftovers, h.script(c)) {
						t.Fatalf("leftovers %+v do not name %s", leftovers, h.script(c))
					}
					if err := conn.VerifyClean(h.opts); err == nil {
						t.Fatal("VerifyClean passed with a script DefenseClaw did not write at the path")
					}
					return
				}
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("Teardown: %v", err)
				}
				skip := []string{h.script(c)}
				if v.saved != "" {
					h.requireEditedSaved(t, c, v.saved)
					saved := c.editedCopyPath(h.dataDir, []byte(v.saved))
					skip = append(skip, saved)
					for dir := filepath.Dir(saved); len(dir) > len(h.dataDir); dir = filepath.Dir(dir) {
						if _, ok := before[dir]; !ok {
							skip = append(skip, dir)
						}
					}
				}
				requireRemovedSame(t, "teardown", h.snapshot(t, skip...), before)
				h.requireStub(t, c)
				if err := conn.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean: %v", err)
				}
			})
		}
	}
}

func removedListsPath(leftovers []RemovedLeftover, path string) bool {
	for _, item := range leftovers {
		if item.Path == path {
			return true
		}
	}
	return false
}

// The OpenHands stub blocks every call: run directly, through a link, by sh -c
// as OpenHands runs hooks, or by a shell, with exit 2 and the deny decision
// that says support was removed and how to remove the hook. It reads no
// startup file and imports no shell function: ENV, BASH_ENV and an exported
// function that would allow the call change nothing.
func TestRemovedOpenHandsStubBlocksWithoutStartupFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands ran its hook script only on Linux and macOS; on Windows its hook is the native launcher")
	}
	h := newRemovedHost(t)
	h.stage(t, removedOpenHands)
	conn, _ := RetiredConnector(removedOpenHandsID)
	if err := conn.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	script := h.script(removedOpenHands)
	link := filepath.Join(h.home, "bin", "relay")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(script, link); err != nil {
		t.Fatal(err)
	}
	allow := filepath.Join(h.home, "allow.sh")
	writeRemovedFile(t, allow, "echo '{\"decision\":\"allow\"}'; exit 0\n", 0o600)
	hostile := []string{"ENV=" + allow, "BASH_ENV=" + allow, "BASH_FUNC_echo%%=() { exit 0; }"}
	// Direct runs: the stub's own #!/bin/sh -p is what reads the env.
	direct := []string{script, link, "exec " + script, "/bin/sh -c " + script}
	if bash, err := exec.LookPath("bash"); err == nil {
		// Where /bin/sh is bash (RHEL, macOS), -p is what keeps BASH_ENV
		// and exported functions out: run the stub's body under bash -p.
		asBash := filepath.Join(h.home, "stub-as-bash")
		writeRemovedFile(t, asBash, strings.Replace(removedOpenHandsTombstone, "#!/bin/sh -p\n", "#!"+bash+" -p\n", 1), 0o700)
		direct = append(direct, asBash)
	}
	// A shell named in the hook command reads its own startup files before
	// the script; that is the hook's choice, so these run with a clean env.
	var named []string
	for _, shell := range []string{"sh", "bash", "dash", "busybox"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		if shell == "busybox" {
			named = append(named, path+" sh "+script)
			continue
		}
		named = append(named, path+" "+script)
	}
	type run struct {
		command string
		env     []string
	}
	var runs []run
	for _, command := range direct {
		runs = append(runs, run{command, nil}, run{command, hostile})
	}
	for _, command := range named {
		runs = append(runs, run{command, nil})
	}
	for _, r := range runs {
		command, env := r.command, r.env
		{
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Dir = h.home
			cmd.Env = append([]string{"HOME=" + h.home, "PATH=/usr/bin:/bin", "LC_ALL=C"}, env...)
			cmd.Stdin = strings.NewReader(`{"event":"pre_tool_use","tool_name":"bash","tool_input":{"command":"rm -rf ~"}}` + "\n")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			status := 0
			var exit *exec.ExitError
			if err := cmd.Run(); errors.As(err, &exit) {
				status = exit.ExitCode()
			} else if err != nil {
				t.Fatalf("run %q: %v", command, err)
			}
			var reply struct{ Decision, Reason string }
			if status != 2 || json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &reply) != nil || reply.Decision != "deny" ||
				!strings.Contains(reply.Reason, "OpenHands support was removed in DefenseClaw 1.0.4") ||
				!strings.Contains(reply.Reason, "remove every hook that runs "+removedOpenHandsHookScript) {
				t.Fatalf("%q (env %v): exit %d, stdout %q, stderr %q; want exit 2 and the deny decision", command, env, status, stdout.String(), stderr.String())
			}
		}
	}
}

// The OmniGent stub is a policy module with no import that denies every
// request with the removal reason, under the handler OmniGent's config names.
func TestRemovedOmnigentStubDeniesEveryRequest(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	h := newRemovedHost(t)
	h.stage(t, removedOmnigent)
	conn, _ := RetiredConnector(removedOmnigentID)
	if err := conn.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	program := "import json, sys; sys.path.insert(0, sys.argv[1]); import " + removedOmnigentModuleName + " as m; " +
		"print(json.dumps({'result': m.defenseclaw_policy({'phase': 'pre_tool'}), 'handler': m.POLICY_REGISTRY[0]['handler']}))"
	out, err := exec.Command(python, "-I", "-S", "-c", program, filepath.Join(h.dataDir, "hooks")).CombinedOutput()
	if err != nil {
		t.Fatalf("import the stub: %v: %s", err, out)
	}
	var got struct {
		Result  map[string]string
		Handler string
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &got); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if got.Result["result"] != "DENY" || !strings.Contains(got.Result["reason"], "OmniGent support was removed in DefenseClaw 1.0.4") ||
		got.Handler != removedOmnigentModuleName+".defenseclaw_policy" {
		t.Fatalf("stub gave %+v, want DENY with the removal reason under %s.defenseclaw_policy", got, removedOmnigentModuleName)
	}
	if strings.Contains(removedOmnigentTombstone, "import ") {
		t.Fatal("the OmniGent stub imports something")
	}
}

// Status, doctor, teardown and every uninstall form list what the teardown
// leaves, with the step to remove each; an agent config that does not name
// DefenseClaw and a host without the connector list nothing.
func TestRemovedConnectorLeftoversListWhatIsLeft(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name, func(t *testing.T) {
			h := newRemovedHost(t)
			if leftovers, ok := RemovedConnectorLeftovers(c.name, h.opts); !ok || len(leftovers) != 0 {
				t.Fatalf("a host without %s lists %+v, %v", c.name, leftovers, ok)
			}
			h.stage(t, c)
			beforeTeardown, _ := RemovedConnectorLeftovers(c.name, h.opts)
			if !removedListsPath(beforeTeardown, removedTokenPath(t, h.dataDir, c.name)) {
				t.Fatalf("before the teardown, leftovers %+v do not name the token", beforeTeardown)
			}
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
			want := map[string]string{
				h.agentConfig: c.configStep,
				h.script(c):   "delete it once nothing above runs it",
				filepath.Join(h.dataDir, "connector_backups", c.name): "copy back what you need",
			}
			if c.name == removedOpenHandsID {
				want[filepath.Join(h.dataDir, "hooks", hookConfigSidecarName+".openhands")] = "delete it"
				want[c.editedCopyPath(h.dataDir, []byte(removedOpenHands103Script))] = "copy back what you need"
				// The hook token stays (keepHookToken), with when it may go.
				want[removedTokenPath(t, h.dataDir, c.name)] = c.keptTokenStep()
			} else {
				want[h.pth] = "delete this file once no OmniGent config.yaml names " + removedOmnigentModuleName
			}
			for path, step := range want {
				found := false
				for _, item := range leftovers {
					if item.Path == path && strings.Contains(item.Step, step) && item.What != "" {
						found = true
					}
				}
				if !found {
					t.Errorf("leftovers %+v have no %s with step %q", leftovers, path, step)
				}
			}
			if len(leftovers) != len(want) {
				t.Errorf("leftovers = %+v, want exactly %d items", leftovers, len(want))
			}
			text := FormatRemovedLeftovers(c.name, leftovers)
			if !strings.HasPrefix(text, c.label+" support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:\n") ||
				!strings.Contains(text, "  - "+h.agentConfig+": ") {
				t.Errorf("formatted leftovers = %q", text)
			}
			// An agent config that no longer names DefenseClaw is not listed.
			clean := removedOpenHandsOperatorHooks
			if c.name == removedOmnigentID {
				clean = removedOmnigentOperatorConfig
			}
			writeRemovedFile(t, h.agentConfig, clean, 0o600)
			if leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts); removedListsPath(leftovers, h.agentConfig) {
				t.Errorf("a cleaned %s is still listed: %+v", h.agentConfig, leftovers)
			}
		})
	}
	if leftovers, ok := RemovedConnectorLeftovers("codex", SetupOpts{}); ok || leftovers != nil {
		t.Fatalf("codex leftovers = %+v, %v", leftovers, ok)
	}
	if FormatRemovedLeftovers(removedOpenHandsID, nil) != "" {
		t.Fatal("no leftovers formatted to text")
	}
}

// The explicit config home native maintenance passes, and for OmniGent the
// files OMNIGENT_CONFIG and OMNIGENT_CONFIG_HOME select, are checked too.
func TestRemovedConnectorLeftoversReadEveryConfigTheAgentMayRead(t *testing.T) {
	h := newRemovedHost(t)
	configHome := filepath.Join(h.home, "elsewhere", ".omnigent")
	explicit := filepath.Join(h.home, "explicit.yaml")
	envHome := filepath.Join(h.home, "env-home")
	named := "policy_modules: [" + removedOmnigentModuleName + "]\n"
	for _, path := range []string{filepath.Join(configHome, "config.yaml"), explicit, filepath.Join(envHome, "config.yaml")} {
		writeRemovedFile(t, path, named, 0o600)
	}
	t.Setenv("OMNIGENT_CONFIG", explicit)
	t.Setenv("OMNIGENT_CONFIG_HOME", envHome)
	opts := h.opts
	opts.ConfigHome = configHome
	leftovers, _ := RemovedConnectorLeftovers(removedOmnigentID, opts)
	for _, path := range []string{filepath.Join(configHome, "config.yaml"), explicit, filepath.Join(envHome, "config.yaml")} {
		if !removedListsPath(leftovers, path) {
			t.Errorf("leftovers %+v do not name %s", leftovers, path)
		}
	}
	hooks := filepath.Join(h.home, "ws", ".openhands", "hooks.json")
	writeRemovedFile(t, hooks, `{"pre_tool_use":[{"hooks":[{"command":"C:\\Users\\u\\defenseclaw-hook.exe hook --connector openhands"}]}]}`, 0o600)
	opts.ConfigHome = filepath.Dir(hooks)
	leftovers, _ = RemovedConnectorLeftovers(removedOpenHandsID, opts)
	if !removedListsPath(leftovers, hooks) {
		t.Errorf("leftovers %+v do not name the Windows launcher hook in %s", leftovers, hooks)
	}
}

// Review fix (G-deadcode loop round 2): a copy of the old OpenHands hook
// under another name in the hooks folder reads the same hook token, and an
// old OpenHands hook that finds no token lets every call run in fail mode
// open before it contacts the gateway. So the OpenHands teardown keeps that
// token whatever is left at the script path (the stub, or nothing), on every
// run, and VerifyClean passes with it; its OTLP token goes, and copies are
// not changed. The leftovers say when the token may go. OmniGent, whose
// module blocks when it finds no token, still loses both tokens.
func TestRemovedOpenHandsTeardownKeepsTheHookTokenForCopiesOfTheHook(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, deleted := range []bool{false, true} {
			name := c.name + "/a copy beside the script"
			if deleted {
				name = c.name + "/the script deleted, a copy left"
			}
			t.Run(name, func(t *testing.T) {
				// Only OpenHands keeps its hook token.
				keep := c.name == removedOpenHandsID
				h := newRemovedHost(t)
				h.stage(t, c)
				before, err := LoadHookAPIToken(h.dataDir, c.name)
				if err != nil || before == "" {
					t.Fatalf("staged token = %q, %v", before, err)
				}
				old, err := os.ReadFile(h.script(c))
				if err != nil {
					t.Fatal(err)
				}
				copied := filepath.Join(h.dataDir, "hooks", "mine-"+c.script)
				writeRemovedFile(t, copied, string(old), c.mode)
				if deleted {
					if err := os.Remove(h.script(c)); err != nil {
						t.Fatal(err)
					}
				}
				conn, _ := RetiredConnector(c.name)
				for run := 1; run <= 2; run++ {
					if err := conn.Teardown(context.Background(), h.opts); err != nil {
						t.Fatalf("run %d: %v", run, err)
					}
					if err := conn.VerifyClean(h.opts); err != nil {
						t.Fatalf("run %d: VerifyClean = %v", run, err)
					}
					got, err := LoadHookAPIToken(h.dataDir, c.name)
					switch {
					case err != nil:
						t.Fatalf("run %d: %v", run, err)
					case keep && got != before:
						t.Fatalf("run %d: the %s hook token = %q, want the one its copied hook reads kept", run, c.name, got)
					case !keep && got != "":
						t.Fatalf("run %d: the %s hook token survived", run, c.name)
					}
					if _, err := os.Lstat(c.otlpTokenPath(h.dataDir)); !os.IsNotExist(err) {
						t.Fatalf("run %d: the OTLP token survived: %v", run, err)
					}
					if body, err := os.ReadFile(copied); err != nil || !bytes.Equal(body, old) {
						t.Fatalf("run %d: the copy %s was changed: %q, %v", run, copied, body, err)
					}
				}
				leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
				token := removedTokenPath(t, h.dataDir, c.name)
				listed := false
				for _, item := range leftovers {
					if item.Path == token {
						listed = true
						if item.What != c.keptTokenWhat() || item.Step != c.keptTokenStep() {
							t.Fatalf("the kept token is listed as %+v", item)
						}
					}
				}
				if listed != keep {
					t.Fatalf("leftovers %+v list the hook token %v, want %v", leftovers, listed, keep)
				}
			})
		}
	}
}
