// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
							opts.FailureLogHome = userLogHome(opts.Home)
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
						// An answered call (HTTP 401) is no outage: it closes in
						// fail mode open too.
						blocked := mode == "closed" || scenario == "malformed" || scenario == "auth" || scenario == "managed-missing-token" || scenario == "oversized" ||
							(strict && (scenario == "outage" || scenario == "missing-token"))
						want := "fail_open"
						if blocked {
							want = "fail_closed"
						}
						// A managed standalone hook runs closed whatever the
						// connector or environment asks for.
						wantMode := mode
						if scenario == "malformed" || scenario == "auth" || scenario == "managed-missing-token" || scenario == "oversized" {
							wantMode = "closed"
						}
						if record["connector"] != connector || record["fail_mode"] != wantMode || record["outcome"] != want || strings.Contains(r.stderr, "WARNING hook fail-open") == blocked {
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

func TestManagedNativeOutageLogsInCallingUsersHome(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			userHome := t.TempDir()
			var runtimeHome string
			r := run(t, "codex", &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)}, func(opts *Options) {
				runtimeHome = opts.Home
				opts.ManagedEnterprise = true
				opts.ManagedStandalone = true
				opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
				opts.ExplainUnenrolledAccount = true
				opts.FailMode = mode
				opts.FailureLogHome = func() string { return userHome }
			})
			data, err := os.ReadFile(filepath.Join(userHome, "logs", "hook-failures.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(data, []byte{'\n'}) != 1 {
				t.Fatalf("want one outage row, got %q", data)
			}
			var row map[string]string
			if err := json.Unmarshal(bytes.TrimSpace(data), &row); err != nil {
				t.Fatal(err)
			}
			wantOutcome := "fail_closed"
			if mode == "open" {
				wantOutcome = "fail_open"
			}
			if row["fail_mode"] != mode || row["outcome"] != wantOutcome || row["category"] != "transport" {
				t.Fatalf("unexpected outage row: %v", row)
			}
			if _, err := os.Stat(filepath.Join(runtimeHome, "logs", "hook-failures.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("runtime home received user log: %v", err)
			}
			if blocked(r) != (mode == "closed") {
				t.Fatalf("outage decision in mode %s: %+v", mode, r)
			}
		})
	}
}

func TestManagedNativeAnsweredServerErrorLogsAsResponse(t *testing.T) {
	for _, connector := range []string{"codex", "claudecode"} {
		for _, status := range []int{500, 503} {
			for _, truncated := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/truncated=%t", connector, status, truncated), func(t *testing.T) {
					var home string
					rt := &stubRT{status: status, body: `{"error":"unavailable"}`}
					if truncated {
						rt.onRequest = func(*stubRT, *http.Request) (*http.Response, error) {
							return &http.Response{StatusCode: status, Header: make(http.Header),
								Body: &erroringBody{data: `{"error":"unavailable"}`, err: io.ErrUnexpectedEOF}}, nil
						}
					}
					r := run(t, connector, rt, func(opts *Options) {
						opts.ManagedEnterprise = true
						opts.FailMode = "open"
						home = filepath.Join(t.TempDir(), ".defenseclaw")
						if err := os.MkdirAll(home, 0o700); err != nil {
							t.Fatal(err)
						}
						opts.FailureLogHome = func() string { return home }
					})
					if !blocked(r) || r.rt.requests != 1 {
						t.Fatalf("answered HTTP %d: blocked=%v requests=%d stdout=%q stderr=%q", status, blocked(r), r.rt.requests, r.stdout, r.stderr)
					}
					data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
					if err != nil {
						t.Fatal(err)
					}
					var record map[string]string
					if err := json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
						t.Fatalf("decode failure log %q: %v", data, err)
					}
					if record["category"] != "response" || record["fail_mode"] != "closed" || record["outcome"] != "fail_closed" {
						t.Fatalf("answered HTTP %d logged as %+v", status, record)
					}
				})
			}
		}
	}
}

// A managed hook whose account resolves no diagnostic directory (HOME unset,
// a failed account lookup) writes no row, and never one into the
// administrator-owned enforcement home it runs with.
func TestManagedFailureLogNeverFallsBackToTheEnforcementHome(t *testing.T) {
	for name, resolver := range map[string]func() string{"no resolver": nil, "unresolved account": func() string { return "" }} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(name+" "+mode, func(t *testing.T) {
				var runtimeHome string
				r := run(t, "codex", &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)}, func(opts *Options) {
					runtimeHome = opts.Home
					opts.ManagedEnterprise = true
					opts.ManagedStandalone = true
					opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
					opts.ExplainUnenrolledAccount = true
					opts.FailMode = mode
					opts.FailureLogHome = resolver
				})
				if blocked(r) != (mode == "closed") {
					t.Fatalf("outage decision in mode %s changed: %+v", mode, r)
				}
				if _, err := os.Stat(filepath.Join(runtimeHome, "logs", "hook-failures.jsonl")); !os.IsNotExist(err) {
					t.Fatalf("the enforcement home received a managed row: %v", err)
				}
			})
		}
	}
}

// A managed hook never creates the invoking user's DefenseClaw folder to log
// a failure: the folder it would make is user-owned with the profile's
// inherited access control, and on Windows it is the protected folder whose
// absence the next call must still report (rel-1-0-4 GAP-0593, GAP-0561).
// The decision is unchanged and no row is written.
func TestManagedFailureLogNeverCreatesTheDiagnosticDirectory(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			userHome := filepath.Join(t.TempDir(), ".defenseclaw")
			r := run(t, "codex", &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)}, func(opts *Options) {
				opts.ManagedEnterprise = true
				opts.ManagedStandalone = true
				opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
				opts.ExplainUnenrolledAccount = true
				opts.FailMode = mode
				opts.FailureLogHome = func() string { return userHome }
			})
			if blocked(r) != (mode == "closed") {
				t.Fatalf("outage decision in mode %s changed: %+v", mode, r)
			}
			if _, err := os.Lstat(userHome); !os.IsNotExist(err) {
				t.Fatalf("the managed hook created the diagnostic directory: %v", err)
			}
		})
	}
}

func TestManagedCodexBindingErrorUsesShellWording(t *testing.T) {
	var logHome string
	r := run(t, "codex", ok(`{"action":"allow"}`), func(opts *Options) {
		logHome = t.TempDir()
		opts.FailureLogHome = func() string { return logHome }
		opts.ManagedEnterprise = true
		opts.ManagedStandalone = true
		opts.ExplainUnenrolledAccount = true
		opts.FailMode = "open"
		opts.Stdin = strings.NewReader(`{"hook_event_name":"PostToolUse"}`)
	})
	if !blocked(r) || r.rt.requests != 0 || !strings.Contains(r.stdout, "codex hook binding error") ||
		!strings.Contains(r.stderr, "defenseclaw: codex hook binding error:") ||
		strings.Contains(r.stdout, "gateway returned an answer") {
		t.Fatalf("binding denial: %+v", r)
	}
	data, err := os.ReadFile(filepath.Join(logHome, "logs", "hook-failures.jsonl"))
	if err != nil || bytes.Count(data, []byte{'\n'}) != 1 {
		t.Fatalf("binding log %q: %v", data, err)
	}
}

// A managed Codex Stop hook with a binding error (malformed stdin or a
// mismatched hook_event_name) keeps the neutral Stop rule: blocking Stop
// keeps Codex running and repeats the failing hook. The diagnostic keeps
// the binding-error wording and the row is logged once.
func TestManagedCodexStopBindingErrorKeepsTheNeutralStopRule(t *testing.T) {
	for name, payload := range map[string]string{
		"malformed":  `{`,
		"mismatched": `{"hook_event_name":"PreToolUse"}`,
	} {
		t.Run(name, func(t *testing.T) {
			logHome := t.TempDir()
			r := run(t, "codex", ok(`{"action":"block"}`), func(opts *Options) {
				opts.FailureLogHome = func() string { return logHome }
				opts.ManagedEnterprise = true
				opts.ManagedStandalone = true
				opts.ExplainUnenrolledAccount = true
				opts.FailMode = "closed"
				opts.Event = "Stop"
				opts.Stdin = strings.NewReader(payload)
			})
			if blocked(r) || r.rt.requests != 0 || !strings.Contains(r.stderr, "codex hook binding error") {
				t.Fatalf("Stop binding error was not answered with the neutral allow: %+v", r)
			}
			data, err := os.ReadFile(filepath.Join(logHome, "logs", "hook-failures.jsonl"))
			if err != nil || bytes.Count(data, []byte{'\n'}) != 1 {
				t.Fatalf("binding log %q: %v", data, err)
			}
			var row map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(data), &row); err != nil {
				t.Fatal(err)
			}
			if row["category"] != "response" || !strings.Contains(fmt.Sprint(row["reason"]), "codex hook binding error") {
				t.Fatalf("unexpected binding row: %v", row)
			}
		})
	}
}
