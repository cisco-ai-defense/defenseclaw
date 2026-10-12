// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeliveryFailureDiagnostics(t *testing.T) {
	for _, connector := range []string{"codex", "claudecode", "cursor"} {
		for _, scenario := range []string{"outage", "malformed", "auth", "missing-token", "managed-missing-token", "oversized", "policy-deny"} {
			for _, mode := range []string{"open", "closed"} {
				for _, strict := range []bool{false, true} {
					name := connector + "/" + scenario + "/" + mode
					if strict {
						name += "/strict"
					}
					t.Run(name, func(t *testing.T) {
						rt := ok(`{"action":"block","reason":"policy-denied","hook_output":{"continue":false,"permission":"deny"}}`)
						switch scenario {
						case "outage":
							rt = &stubRT{err: errors.New("offline")}
						case "malformed":
							rt = ok("private-response-marker")
						case "auth":
							rt = &stubRT{status: 401, body: "private-response-marker"}
						}
						var home string
						r := run(t, connector, rt, func(opts *Options) {
							home = opts.Home
							opts.FailMode = mode
							opts.StrictAvailability = strict
							opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"private-payload-marker"}}`)
							if strings.Contains(scenario, "missing-token") {
								if err := os.Remove(filepath.Join(opts.HookDir, ".token")); err != nil {
									t.Fatal(err)
								}
								opts.Token = ""
								opts.ManagedEnterprise = scenario == "managed-missing-token"
							}
							if scenario == "oversized" {
								opts.MaxBody = 1
							}
						})
						failure, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
						if scenario == "policy-deny" {
							if !os.IsNotExist(err) || strings.Contains(r.stderr, "inspection bypassed") {
								t.Fatalf("policy denial mislabeled: log=%s stderr=%s", failure, r.stderr)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						var record map[string]string
						if err := json.Unmarshal(failure, &record); err != nil {
							t.Fatalf("expected one failure record: %v: %s", err, failure)
						}
						blocked := mode == "closed" || scenario == "managed-missing-token" || (strict && (scenario == "outage" || scenario == "missing-token"))
						want := "fail_open"
						if blocked {
							want = "fail_closed"
						}
						if record["connector"] != connector || record["fail_mode"] != mode || record["outcome"] != want || strings.Contains(r.stderr, "WARNING hook fail-open") == blocked {
							t.Fatalf("wrong diagnostic: record=%+v stderr=%s", record, r.stderr)
						}
						for _, secret := range []string{"private-payload-marker", "private-response-marker", "tkn"} {
							if strings.Contains(string(failure)+r.stderr, secret) {
								t.Fatalf("diagnostic leaked %q", secret)
							}
						}
					})
				}
			}
		}
	}
}

func TestFailOpenWarningSurvivesLogWriteFailure(t *testing.T) {
	r := run(t, "codex", &stubRT{err: errors.New("offline\nforged")}, func(opts *Options) {
		// A regular file prevents the diagnostic directory from being created.
		if err := os.WriteFile(filepath.Join(opts.Home, "logs"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if r.code != 0 || !strings.Contains(r.stderr, "WARNING hook fail-open") {
		t.Fatalf("logging changed delivery or lost warning: code=%d stderr=%q", r.code, r.stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if !strings.HasPrefix(line, "defenseclaw:") {
			t.Fatalf("transport error forged diagnostic line: %q", line)
		}
	}
}

func TestFailOpenDiagnosticEscapesReason(t *testing.T) {
	var stderr bytes.Buffer
	opts := withDefaults(Options{Home: t.TempDir(), Stderr: &stderr})
	logHookFailure(opts, spec{connector: "codex", hookName: "codex-hook"}, "offline\nforged", "transport", "open", false)
	if strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("forged warning line: %q", stderr.String())
	}
	failure, err := os.ReadFile(filepath.Join(opts.Home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]string
	if err := json.Unmarshal(failure, &record); err != nil || record["reason"] != "offline\nforged" || record["outcome"] != "fail_open" {
		t.Fatalf("invalid escaped record: %v: %s", err, failure)
	}
}
