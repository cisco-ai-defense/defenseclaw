// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 1.0.4 review (loop round 2): one inspect-* script serves every connector of
// a data directory and nothing authenticates which one an invocation runs
// for. Its fail mode is the strictest recorded mode: an inherited
// DEFENSECLAW_CONNECTOR naming an open peer, two closed records with no
// selector, or a legacy open kept from an upgrade never open it while a
// connector is recorded closed. Every parser path is checked: jq, the python3
// fallback, and neither (flat records only).
func TestSharedHookFailModeIsTheStrictestRecordedMode(t *testing.T) {
	helper, err := filepath.Abs(filepath.Join("hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	python, pyErr := exec.LookPath("python3")
	_, jqErr := exec.LookPath("jq")
	// Records as 1.0.4 writes them: an open counts only with its config
	// source (G3-upg); the unsourced cases below check that rule.
	flat := func(name, mode string) string {
		return "DEFENSECLAW_CONNECTOR=" + name + "\nDEFENSECLAW_FAIL_MODE=" + mode + "\nFAIL_MODE_SOURCE=config\n"
	}
	unsourced := func(name, mode string) string {
		return "DEFENSECLAW_CONNECTOR=" + name + "\nDEFENSECLAW_FAIL_MODE=" + mode + "\n"
	}
	mixedJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed","claudecode":"open"},"fail_mode_sources":{"codex":"config","claudecode":"config"}}`
	closedLegacyOpenJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed","claudecode":"closed"},"fail_mode_sources":{"codex":"config","claudecode":"config"},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	openJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"open","claudecode":"open"},"fail_mode_sources":{"codex":"config","claudecode":"config"},"legacy_fail_mode":"closed","legacy_fail_mode_source":"config"}`
	legacyOpenJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	malformedMap := func(value string) string {
		return `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":` + value + `,"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	}
	type state map[string]string
	for _, tc := range []struct {
		name     string
		files    state
		selector string
		// want per parser: jq, python3, none (flat records only).
		want [3]string
	}{
		{"mixed/selector-open-peer", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"mixed/no-selector", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"mixed/json-only-selector-open-peer", state{".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"mixed/flat-only-selector-open-peer", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-two-closed-records", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "closed"), ".hookcfg": closedLegacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-flat-legacy-open-one-closed", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.legacy": flat("", "open"),
			".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed"},"legacy_fail_mode":"open"}`},
			"", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-selector-unrecorded", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg": closedLegacyOpenJSON},
			"cursor", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-json-closed-entry-no-flat", state{".hookcfg": closedLegacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"json-closed-entry-flat-open", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "open"}},
		{"malformed-flat-mode", state{".hookcfg.codex": flat("codex", "OPEN "), ".hookcfg.claudecode": flat("claudecode", "open")},
			"", [3]string{"closed", "closed", "closed"}},
		{"malformed-json", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "{not json"},
			"claudecode", [3]string{"closed", "closed", "open"}},
		{"json-fail-modes-not-a-map", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":["open"]}`},
			"claudecode", [3]string{"closed", "closed", "open"}},
		// The modes the shared hooks keep: a selected connector's own open
		// record when every record is open, and the legacy mode for a call
		// no single connector owns (an install no connector refresh has
		// rewritten yet, or several open records), as before 1.0.4.
		{"all-open/no-selector", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"all-open/no-selector-legacy-open", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg.legacy": flat("", "open"), ".hookcfg": strings.Replace(openJSON, `"legacy_fail_mode":"closed"`, `"legacy_fail_mode":"open"`, 1)},
			"", [3]string{"open", "open", "open"}},
		// Loop round 3: the JSON legacy open alone (no flat legacy record,
		// which every writer since 0.8.10 writes with it) opens nothing.
		{"all-open/no-selector-json-legacy-open-only", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": strings.Replace(openJSON, `"legacy_fail_mode":"closed"`, `"legacy_fail_mode":"open"`, 1)},
			"", [3]string{"closed", "closed", "closed"}},
		{"single-open-record", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`},
			"codex", [3]string{"open", "open", "open"}},
		{"all-open/selector-recorded", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"codex", [3]string{"open", "open", "open"}},
		{"all-open/selector-unrecorded", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"cursor", [3]string{"closed", "closed", "closed"}},
		{"single-closed", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"closed"}}`},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-only-open-json-only", state{".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-only-open-flat", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"open", "open", "open"}},
		{"legacy-only-open-selector", state{".hookcfg": legacyOpenJSON},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-closed-json-open", state{".hookcfg.legacy": flat("", "closed"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-open-json-legacy-missing", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1"}`},
			"", [3]string{"closed", "closed", "open"}},
		{"legacy-flat-open-json-empty-map", state{".hookcfg.legacy": flat("", "open"),
			".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`},
			"", [3]string{"open", "open", "open"}},
		// A legacy record must name no connector, as a connector record must
		// name its own.
		{"legacy-flat-without-connector-line", state{".hookcfg.legacy": "DEFENSECLAW_FAIL_MODE=open\n", ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-naming-a-connector", state{".hookcfg.legacy": flat("codex", "open"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"nothing", state{}, "", [3]string{"closed", "closed", "closed"}},
		// An open no config chose (an earlier release resolved it, or it was
		// lowered for a vendor): closed on every parser path (G3-upg).
		{"unsourced/single-open-record", state{".hookcfg.codex": unsourced("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"}}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"unsourced/json-open-flat-sourced", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"}}`},
			"codex", [3]string{"closed", "closed", "open"}},
		{"unsourced/legacy-only-open", state{".hookcfg.legacy": unsourced("", "open"), ".hookcfg": `{"version":2,"legacy_fail_mode":"open"}`},
			"", [3]string{"closed", "closed", "closed"}},
		// Loop round 3: a v2 JSON whose fail_modes is present but not an
		// object never reaches the legacy mode, with or without the flat
		// legacy record. Only the no-parser path, which cannot read the
		// JSON, follows the flat legacy record.
		{"fail-modes-missing-no-flat", state{".hookcfg": legacyOpenJSON}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null-no-flat", state{".hookcfg": malformedMap("null")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("null")}, "", [3]string{"closed", "closed", "open"}},
		{"fail-modes-false", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("false")}, "", [3]string{"closed", "closed", "open"}},
		{"fail-modes-empty-list", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("[]")}, "", [3]string{"closed", "closed", "open"}},
		{"fail-modes-zero", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("0")}, "", [3]string{"closed", "closed", "open"}},
		{"fail-modes-empty-string", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap(`""`)}, "", [3]string{"closed", "closed", "open"}},
		{"fail-modes-null-selector", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": malformedMap("null")},
			"claudecode", [3]string{"closed", "closed", "open"}},
		{"fail-modes-null-single-flat-record", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("null")},
			"", [3]string{"closed", "closed", "open"}},
	} {
		for i, parser := range []string{"jq", "python3", "none"} {
			t.Run(tc.name+"/"+parser, func(t *testing.T) {
				root := t.TempDir()
				hookDir := filepath.Join(root, "hooks")
				binDir := filepath.Join(root, "bin")
				for _, dir := range []string{hookDir, binDir} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for name, body := range tc.files {
					if err := os.WriteFile(filepath.Join(hookDir, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				path := os.Getenv("PATH")
				switch parser {
				case "jq":
					if jqErr != nil {
						t.Skip("jq is not installed")
					}
				case "python3":
					if pyErr != nil {
						t.Skip("python3 is not installed")
					}
					if err := os.Symlink(python, filepath.Join(binDir, "python3")); err != nil {
						t.Fatal(err)
					}
					if uname, err := exec.LookPath("uname"); err == nil {
						if err := os.Symlink(uname, filepath.Join(binDir, "uname")); err != nil {
							t.Fatal(err)
						}
					}
					path = binDir
				case "none":
					path = binDir
				}
				bash, err := exec.LookPath("bash")
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bash, "-c", `. "$1"; defenseclaw_shared_runtime_fail_mode "$2" "$3"`, "probe", helper, hookDir, tc.selector)
				cmd.Env = append(sanitizedTestEnv(), "PATH="+path, "HOME="+root)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("helper failed: %v\n%s", err, out)
				}
				if got := strings.TrimSpace(string(out)); got != tc.want[i] {
					t.Fatalf("fail mode %q, want %q", got, tc.want[i])
				}
			})
		}
	}
}

// The same rule end to end, through the real setup writers and the real
// inspect-* scripts: with DEFENSECLAW_HOME missing, every per-user hook
// blocks even when an old sidecar records open.
func TestSharedInspectHooksNeverTakeAPeersOpenMode(t *testing.T) {
	type install struct {
		conn Connector
		mode string
	}
	for _, tc := range []struct {
		name string
		// legacy is the sidecar an older release left (written before the
		// connector writers): "" none, "scalar" the 0.8.x KEY=value file,
		// "v2" the 1.0.x unscoped writer.
		legacy    string
		installs  []install
		selectors []string
		wantAllow bool
	}{
		{"codex-closed-claude-open", "", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "claudecode", "codex", "cursor"}, false},
		{"upgrade-0.8-open-two-closed", "scalar", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "closed"}},
			[]string{"", "claudecode", "codex"}, false},
		{"upgrade-1.0-open-two-closed", "v2", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "closed"}},
			[]string{"", "claudecode", "codex"}, false},
		{"upgrade-1.0-open-one-closed-one-open", "v2", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "claudecode"}, false},
		// Legacy open records remain inert, whether scoped or unscoped.
		{"both-open", "", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"claudecode", "codex"}, false},
		{"both-open-unattributed", "", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "cursor"}, false},
		{"upgrade-1.0-open-both-open-unattributed", "v2", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{""}, false},
		{"legacy-open-not-refreshed", "v2", nil, []string{""}, false},
		// Loop round 3: the same install with fail_modes made null is
		// malformed and blocks.
		{"legacy-open-not-refreshed-null-map", "v2-null-map", nil, []string{""}, false},
	} {
		for _, invoke := range hookArgvInspectCases() {
			if len(invoke.stdin) > 4096 {
				continue
			}
			for _, selector := range tc.selectors {
				t.Run(tc.name+"/"+invoke.script+"/selector="+selector, func(t *testing.T) {
					dataDir := t.TempDir()
					hookDir := filepath.Join(dataDir, "hooks")
					if err := os.MkdirAll(hookDir, 0o700); err != nil {
						t.Fatal(err)
					}
					switch tc.legacy {
					case "scalar":
						if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg"), []byte("DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:1\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "v2", "v2-null-map":
						if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "", "open", false); err != nil {
							t.Fatal(err)
						}
					}
					writers := tc.installs
					if len(writers) == 0 {
						// Render the scripts without adding a connector record.
						writers = []install{{NewCodexConnector(), "open"}}
					}
					for _, in := range writers {
						opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: in.mode}
						if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, in.conn); err != nil {
							t.Fatal(err)
						}
					}
					if len(tc.installs) == 0 {
						if err := clearHookConfigSidecarEntry(hookDir, "codex"); err != nil {
							t.Fatal(err)
						}
					}
					if tc.legacy == "v2-null-map" {
						path := filepath.Join(hookDir, ".hookcfg")
						body, err := os.ReadFile(path)
						if err != nil || strings.Contains(string(body), `"fail_modes"`) {
							t.Fatalf("unexpected sidecar (%v):\n%s", err, body)
						}
						body = []byte(strings.Replace(string(body), `"legacy_fail_mode"`, `"fail_modes": null, "legacy_fail_mode"`, 1))
						if err := os.WriteFile(path, body, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if tc.legacy != "" {
						body, err := os.ReadFile(filepath.Join(hookDir, ".hookcfg"))
						if err != nil || !strings.Contains(string(body), `"legacy_fail_mode": "open"`) {
							t.Fatalf("the upgrade did not keep the legacy open mode (%v):\n%s", err, body)
						}
					}
					cmd := exec.Command("bash", filepath.Join(hookDir, invoke.script))
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+dataDir, "DEFENSECLAW_HOME="+filepath.Join(dataDir, "missing"))
					if selector != "" {
						cmd.Env = append(cmd.Env, "DEFENSECLAW_CONNECTOR="+selector)
					}
					cmd.Env = append(cmd.Env, invoke.env...)
					output, err := cmd.CombinedOutput()
					if allowed := err == nil; allowed != tc.wantAllow {
						t.Fatalf("allowed=%v want %v (err=%v)\n%s", allowed, tc.wantAllow, err, output)
					}
					if !tc.wantAllow && !strings.Contains(string(output), "hook home unavailable") {
						t.Fatalf("the block did not come from the unavailable-home exit:\n%s", output)
					}
				})
			}
		}
	}
}
