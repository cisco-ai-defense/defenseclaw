// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// cleanOutageCase is one guarded call of a connector while the session
// exchange fails.
type cleanOutageCase struct {
	name        string
	goos        string
	err         error
	cleanMirror bool
	process     string
	event       string
	unapproved  bool
	failsOpen   bool
	// wantGuardBlock: the guard itself denies (hook time) or the check
	// denies.
	wantGuardBlock bool
}

func cleanOutageCases() []cleanOutageCase {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	untrusted := fmt.Errorf("hook socket: %w", hookexec.ErrManagedHookSocketDirectoryUntrusted)
	return []cleanOutageCase{
		{name: "linux stopped gateway with a clean entry under open", goos: "linux", err: notRunning, cleanMirror: true, process: "p-1", failsOpen: true},
		{name: "darwin stopped gateway with a clean entry under open", goos: "darwin", err: notRunning, cleanMirror: true, process: "p-1", failsOpen: true},
		{name: "stopped gateway with a clean entry under closed, strict or the default", goos: "linux", err: notRunning, cleanMirror: true, process: "p-1", failsOpen: false},
		{name: "windows stays closed", goos: "windows", err: notRunning, cleanMirror: true, process: "p-1", failsOpen: true, wantGuardBlock: true},
		{name: "no clean entry", goos: "linux", err: notRunning, process: "p-1", failsOpen: true, wantGuardBlock: true},
		{name: "no agent process identity", goos: "linux", err: notRunning, cleanMirror: true, failsOpen: true, wantGuardBlock: true},
		{name: "session start during the outage", goos: "linux", err: notRunning, cleanMirror: true, process: "p-1", event: "sessionStart", failsOpen: true, wantGuardBlock: true},
		{name: "the scan finds an unapproved hook", goos: "linux", err: notRunning, cleanMirror: true, process: "p-1", unapproved: true, failsOpen: true, wantGuardBlock: true},
		{name: "a gateway that is not proven stopped", goos: "linux", err: errors.New("no answer"), cleanMirror: true, process: "p-1", failsOpen: true, wantGuardBlock: true},
		{name: "an untrusted socket directory", goos: "darwin", err: untrusted, cleanMirror: true, process: "p-1", failsOpen: true, wantGuardBlock: true},
	}
}

// GAP-0352: under a stopped gateway a guarded connector's call is left to
// the managed outage fail mode only when the gateway's clean-session entry
// vouches for the agent process (Linux and macOS); every other case keeps
// the guard's refusal.
func TestForeignGuardCleanSessionOutageHookTime(t *testing.T) {
	for _, id := range []string{"copilot", "cursor", "devin", "opencode"} {
		for _, tc := range cleanOutageCases() {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				fixture := newCleanOutageFixture(t, id, tc)
				event := tc.event
				if event == "" {
					event = outageGuardCallFor(id).event
				}
				if id == "opencode" && tc.event == "sessionStart" {
					event = "session.start"
				}
				payload := cleanOutagePayload(t, fixture, event)
				opts := hookexec.Options{Connector: id, Event: event, ManagedEnterprise: true, FailMode: "open",
					Home: filepath.Join(fixture.home, "managed-data"), Stdin: bytes.NewReader(payload), Stderr: &bytes.Buffer{}}
				applyEnterpriseForeignHookGuard(&opts)
				if id == "opencode" && event != "tool.execute.before" {
					return // the plugin's lifecycle events are not guarded at hook time
				}
				blocked := opts.ManagedRuntimeFailure != ""
				if blocked != tc.wantGuardBlock {
					t.Fatalf("guard blocked %v (%q), want %v", blocked, opts.ManagedRuntimeFailure, tc.wantGuardBlock)
				}
			})
		}
	}
}

// The --foreign-hook-check path (OpenCode, Amp and the Hermes hook) has no
// hook request after it, so it applies the managed outage fail mode itself:
// open allows with a warning, anything else denies with the not-running
// reason.
func TestForeignGuardCleanSessionOutageCheck(t *testing.T) {
	for _, id := range []string{"opencode", "hermes", "amp"} {
		for _, tc := range cleanOutageCases() {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				fixture := newCleanOutageFixture(t, id, tc)
				event := tc.event
				if event == "" {
					event = outageGuardCallFor(id).event
				}
				if tc.event == "sessionStart" {
					event = map[string]string{"opencode": "session.start", "hermes": "on_session_start", "amp": "defenseclaw.plugin.loaded"}[id]
				}
				var out bytes.Buffer
				if code := runForeignHookCheck(id, bytes.NewReader(cleanOutagePayload(t, fixture, event)), &out); code != 0 {
					t.Fatalf("exit %d", code)
				}
				var result foreignHookCheckResult
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatalf("%v: %q", err, out.String())
				}
				wantDeny := tc.wantGuardBlock || !tc.failsOpen
				// Windows Amp keeps its session record locally (no exchange, so
				// no outage), and Windows Hermes is not guarded.
				unguarded := (id == "amp" || id == "hermes") && tc.goos == "windows"
				if unguarded {
					wantDeny = false
				}
				if result.Deny != wantDeny {
					t.Fatalf("check deny %v (%+v), want %v", result.Deny, result, wantDeny)
				}
				if !result.Deny && id == "hermes" && !unguarded &&
					!strings.HasPrefix(out.String(), `{"deny":false,"warnings":["the DefenseClaw gateway is not running`) {
					t.Fatalf("the Hermes shell hook matches the outage warning first: %q", out.String())
				}
				if !result.Deny {
					if !tc.cleanMirror && !unguarded {
						t.Fatal("an allow needs the clean entry")
					}
					if !unguarded {
						if len(result.Warnings) == 0 || !strings.Contains(strings.Join(result.Warnings, " "), "gateway is not running") {
							t.Fatalf("an outage allow must warn: %+v", result)
						}
					}
				}
				if result.Deny && !tc.failsOpen && !tc.wantGuardBlock && !strings.Contains(result.Reason, "enterprise_managed_gateway_not_running") {
					t.Fatalf("a closed outage must name the stopped gateway: %+v", result)
				}
			})
		}
	}
}

func newCleanOutageFixture(t *testing.T, id string, tc cleanOutageCase) *foreignGuardFixture {
	t.Helper()
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	// The scan reads the agent environment: XDG_CONFIG_HOME (set on the
	// GitHub Ubuntu runners) moves the OpenCode and Amp user folders away
	// from the fixture home, and Windows Hermes reads LOCALAPPDATA, so pin
	// both to the fixture home.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HERMES_HOME", filepath.Join(fixture.home, ".hermes"))
	policies := map[string]config.ResolvedConnectorPolicy{}
	policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(id)
	policy.ForeignHooks = config.ForeignHooksRemove
	policies[id] = policy
	summary := enterprisepolicy.BuildPublicPolicy(enterprisepolicy.Options{GOOS: tc.goos, HookBinary: foreignGuardHookBinary, Policies: policies}, []string{id})
	fixture.summary = &summary
	fixture.process = tc.process
	fixture.cleanMirror = tc.cleanMirror
	previousGOOS := hookForeignGuardGOOS
	hookForeignGuardGOOS = tc.goos
	t.Cleanup(func() { hookForeignGuardGOOS = previousGOOS })
	hookForeignGuardOutageFailsOpen = func(string, string) bool { return tc.failsOpen }
	err := tc.err
	hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, err
	}
	if tc.unapproved {
		fixture.write(t, filepath.Join(fixture.home, ".cursor", "hooks.json"), `{"version":1,"hooks":{"preToolUse":[{"command":"/tmp/x.sh"}]}}`)
		fixture.write(t, filepath.Join(fixture.home, ".copilot", "hooks", "x.json"), `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"/tmp/x.sh"}]}}`)
		fixture.write(t, filepath.Join(fixture.home, ".config", "opencode", "plugins", "x.mjs"), "export default {}")
		fixture.write(t, filepath.Join(fixture.home, ".hermes", "config.yaml"), "hooks:\n  pre_tool_call:\n    - command: /tmp/x.sh\n")
		fixture.write(t, filepath.Join(fixture.home, ".config", "amp", "plugins", "x.ts"), "export default {}")
		fixture.write(t, filepath.Join(fixture.project, ".devin", "config.json"), `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"./rewrite-command.sh"}]}]}}`)
	}
	return fixture
}

func cleanOutagePayload(t *testing.T, fixture *foreignGuardFixture, event string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(fixture.project, "src"),
		"session_id": "s-1", "sessionId": "s-1", "conversation_id": "s-1", "tool_name": "Bash", "tool": "bash"})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// The guardian removes the account's clean-session entries after it takes
// the account's lock and before the first ledger record; if they cannot be
// removed the hook file and the ledger stay as they were.
func TestForeignHookRemovalDropsCleanEntriesBeforeTheFirstRecord(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	useForeignHookGuardian(t, nil)
	useInProcessCleanupAsSelf(t)
	trace := traceForeignHookRemovals(t)
	root := managed.ForeignHookCleanDir(cfg.DataDir)
	entry := filepath.Join(root, "1001", "p-entry.json")
	if err := os.MkdirAll(filepath.Dir(entry), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := enterpriseForeignHookDropCleanMirrors
	t.Cleanup(func() { enterpriseForeignHookDropCleanMirrors = previous })
	enterpriseForeignHookDropCleanMirrors = func(dir, identity string) error {
		trace.add("drop")
		return previous(dir, identity)
	}
	home := t.TempDir()
	foreignHookTestCursorHook(t, home)
	result, err := cleanEnterpriseForeignHooksFenced(foreignHookTestTarget(home), foreignHookTestInProcessRequest("cursor", home), time.Now())
	if err != nil || len(result.Removed) != 1 {
		t.Fatalf("cleanup %+v: %v", result, err)
	}
	if got := trace.String(); !strings.HasPrefix(got, "lock,drop,ledger,") {
		t.Fatalf("the entries must go after the lock and before the first record: %s", got)
	}
	if _, err := os.Lstat(filepath.Dir(entry)); !os.IsNotExist(err) {
		t.Fatalf("the account's entries must be gone: %v", err)
	}
}

// An exchange the guardian's drain cut may write an entry after the first
// removal of the account's entries: the commit removes them again before it
// lets go of the lock.
func TestForeignHookRemovalDropsCleanEntriesAgainAtTheCommit(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	useForeignHookGuardian(t, nil)
	useInProcessCleanupAsSelf(t)
	root := managed.ForeignHookCleanDir(cfg.DataDir)
	late := filepath.Join(root, "1001", "p-late.json")
	previous := enterpriseForeignHookDropCleanMirrors
	t.Cleanup(func() { enterpriseForeignHookDropCleanMirrors = previous })
	drops := 0
	enterpriseForeignHookDropCleanMirrors = func(dir, identity string) error {
		drops++
		err := previous(dir, identity)
		if drops == 1 {
			if mkErr := os.MkdirAll(filepath.Dir(late), 0o711); mkErr != nil {
				t.Fatal(mkErr)
			}
			if wErr := os.WriteFile(late, []byte("{}"), 0o644); wErr != nil {
				t.Fatal(wErr)
			}
		}
		return err
	}
	home := t.TempDir()
	foreignHookTestCursorHook(t, home)
	if result, err := cleanEnterpriseForeignHooksFenced(foreignHookTestTarget(home), foreignHookTestInProcessRequest("cursor", home), time.Now()); err != nil || len(result.Removed) != 1 {
		t.Fatalf("cleanup %+v: %v", result, err)
	}
	if drops != 2 {
		t.Fatalf("the entries are removed before the first record and at the commit, got %d removals", drops)
	}
	if _, err := os.Lstat(late); !os.IsNotExist(err) {
		t.Fatalf("an entry written after the first removal must be gone: %v", err)
	}
}

func TestForeignHookRemovalRefusedWhenCleanEntriesCannotBeRemoved(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	useInProcessCleanupAsSelf(t)
	previous := enterpriseForeignHookDropCleanMirrors
	t.Cleanup(func() { enterpriseForeignHookDropCleanMirrors = previous })
	enterpriseForeignHookDropCleanMirrors = func(string, string) error { return errors.New("read-only file system") }
	before, _ := os.ReadFile(g.ledger)
	home := t.TempDir()
	path := foreignHookTestCursorHook(t, home)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := cleanEnterpriseForeignHooksFenced(foreignHookTestTarget(home), foreignHookTestInProcessRequest("cursor", home), time.Now())
	if err == nil || len(result.Removed) != 0 {
		t.Fatalf("the removal must be refused: %+v, %v", result, err)
	}
	if now, err := os.ReadFile(path); err != nil || !bytes.Equal(now, original) {
		t.Fatalf("the hook file must not change: %v", err)
	}
	if after, _ := os.ReadFile(g.ledger); !bytes.Equal(before, after) {
		t.Fatal("the ledger must not change")
	}
	if !accountRemovalLockFree(t, "1001", time.Second) {
		t.Fatal("a refused removal must let go of the account's lock")
	}
}
