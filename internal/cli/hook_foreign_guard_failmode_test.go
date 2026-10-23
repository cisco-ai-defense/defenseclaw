// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// guardOutageConnectors are the guarded connectors whose foreign-hook check
// exchanges the session with the gateway: Copilot and OpenCode on every OS,
// Hermes on Linux and macOS.
func guardOutageConnectors() map[string]string {
	connectors := map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	return connectors
}

func runGuardEvent(t *testing.T, fixture *foreignGuardFixture, connector, event, session string) hookexec.Options {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(fixture.project, "src"),
		"session_id": session, "sessionId": session})
	if err != nil {
		t.Fatal(err)
	}
	opts := hookexec.Options{Connector: connector, Event: event, ManagedEnterprise: true, Stdin: bytes.NewReader(payload), Stderr: io.Discard}
	applyEnterpriseForeignHookGuard(&opts)
	return opts
}

// When the gateway cannot answer the session exchange (it is stopped,
// restarting or not answering) and the fail mode is not open for the
// outage (unset, closed, strict), a guarded connector's call is blocked with
// the outage's reason, and an unapproved hook the scan finds blocks with its
// own reason. Open is covered by the protected-record tests below.
func TestForeignHookGuardBlocksAGatewayOutageUnlessOpen(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	for connector, event := range guardOutageConnectors() {
		// The guard takes no fail mode: the exchange error alone decides.
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		got := runGuardEvent(t, fixture, connector, event, "s-1")
		if got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
			t.Fatalf("%s: a stopped gateway must block with the not-running reason: %q", connector, got.ManagedRuntimeFailure)
		}
	}
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("copilot")
	fixture.process = "agent-process"
	hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, notRunning
	}
	foreign := filepath.Join(fixture.project, ".github", "hooks", "x.json")
	fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
	found := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1")
	if !strings.HasPrefix(found.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(found.ManagedRuntimeFailure, foreign) {
		t.Fatalf("an unapproved hook must block with its own reason: %q", found.ManagedRuntimeFailure)
	}
}

// Only an outage that follows the administrator's open (a standalone hook
// outside Secure Client, not strict, not a held port) is marked, with the
// service uid from the runtime descriptor; the marked error still names the
// outage.
func TestForeignHookSessionExchangeErrorMarksOnlyAnOpenOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	open := hookexec.Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true, FailMode: "open", ManagedServiceUID: 990}
	var marked *foreignHookSessionOutageOpen
	if err := foreignHookSessionExchangeError(open, notRunning); !errors.As(err, &marked) || marked.serviceUID != 990 || !hookexec.ManagedGatewayNotRunning(err) {
		t.Fatalf("open outage: %v", err)
	}
	for name, opts := range map[string]hookexec.Options{
		"closed": func() hookexec.Options { o := open; o.FailMode = "closed"; return o }(),
		"strict": func() hookexec.Options { o := open; o.StrictAvailability = true; return o }(),
	} {
		if err := foreignHookSessionExchangeError(opts, notRunning); errors.As(err, &marked) || err != notRunning {
			t.Fatalf("%s outage must keep its error: %v", name, err)
		}
	}
	if err := foreignHookSessionExchangeError(open, errors.New("invalid session gateway decision")); errors.As(err, &marked) {
		t.Fatalf("a non-outage error must not be marked: %v", err)
	}
}

// protectedRecordFixture points the guard at a temporary protected session
// record root for account 4242, with a key the test account made; trust
// fails for the paths in untrusted (the production check refuses a record,
// a key or a folder the user can change).
type protectedRecordFixture struct {
	root      string
	untrusted map[string]bool
	consulted int
}

const protectedRecordIdentity = "4242"

func newProtectedRecordFixture(t *testing.T) *protectedRecordFixture {
	t.Helper()
	records := &protectedRecordFixture{root: filepath.Join(t.TempDir(), "sessions"), untrusted: map[string]bool{}}
	if err := os.Mkdir(records.root, 0o711); err != nil {
		t.Fatal(err)
	}
	restoreOwner := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	records.newKey(t)
	previousRecord, previousTrust, previousIdentity := hookForeignGuardSessionRecord, hookForeignGuardSessionRecordTrust, hookForeignGuardIdentity
	hookForeignGuardSessionRecord = func(serviceUID int) (string, enterprisepolicy.PublishedSessionTrust, bool) {
		records.consulted++
		return records.root, enterprisepolicy.PublishedSessionTrust{ServiceUID: serviceUID}, true
	}
	hookForeignGuardSessionRecordTrust = func(path string, _ enterprisepolicy.PublishedSessionTrust) error {
		if records.untrusted[path] {
			return fmt.Errorf("%s is writable by the user", path)
		}
		return nil
	}
	hookForeignGuardIdentity = func() (string, bool) { return protectedRecordIdentity, true }
	t.Cleanup(func() {
		hookForeignGuardSessionRecord, hookForeignGuardSessionRecordTrust, hookForeignGuardIdentity = previousRecord, previousTrust, previousIdentity
		restoreOwner()
	})
	return records
}

// newKey makes a new record key, as the lifecycle and the guardian do: every
// earlier allow proves nothing.
func (r *protectedRecordFixture) newKey(t *testing.T) {
	t.Helper()
	if err := enterprisepolicy.RotatePublishedSessionKey(r.root, protectedRecordIdentity, enterpriseForeignHookSessionKeyTrust()); err != nil {
		t.Fatal(err)
	}
}

// key is the path of the current record key.
func (r *protectedRecordFixture) key(t *testing.T) string {
	t.Helper()
	key, err := enterprisepolicy.ReadPublishedSessionKey(r.root, protectedRecordIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return key.ID()
}

// write stores the gateway's answer for one key part (kind "p" or "s"), as
// the gateway does: an allow with the current key. It returns the record's
// path.
func (r *protectedRecordFixture) write(t *testing.T, connector, kind, id string, blocked bool, reason string) string {
	t.Helper()
	key := enterprisepolicy.SessionKey{Connector: connector, Process: id}
	if kind == "s" {
		key = enterprisepolicy.SessionKey{Connector: connector, Session: id}
	}
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(r.root, protectedRecordIdentity, key,
		enterprisepolicy.GuardDecision{Deny: blocked, Reason: reason}, time.Now()); err != nil {
		t.Fatal(err)
	}
	path, ok := enterprisepolicy.PublishedSessionRecordPath(r.root, protectedRecordIdentity, connector, kind, id)
	if !ok {
		t.Fatalf("no record path for %s %s %s", connector, kind, id)
	}
	return path
}

// allow stores the gateway's allow for an agent process and its session.
func (r *protectedRecordFixture) allow(t *testing.T, connector, process, session string) string {
	t.Helper()
	r.write(t, connector, "s", session, false, "")
	return r.write(t, connector, "p", process, false, "")
}

// GAP-0352: under the administrator's open, a gateway outage lets a guarded
// connector's call go on only when the gateway's protected session records
// prove the agent process and its session not blocked, under the current
// key. A missing, untrusted, corrupt, foreign or dead record blocks with
// the outage's reason; a blocking record denies with the gateway's reason;
// nothing under the account's home is read; an unapproved hook the scan
// finds blocks with its own reason; and an outage that does not follow open
// (unset, closed, strict) never reads the record.
func TestForeignHookGuardOpenOutageFollowsTheProtectedSessionRecord(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	openOutage := func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, &foreignHookSessionOutageOpen{err: notRunning, serviceUID: 990}
	}
	const process = "agent-process"
	for connector, event := range guardOutageConnectors() {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = process
		records := newProtectedRecordFixture(t)
		hookForeignGuardExchange = openOutage
		blocked := func(step string) {
			t.Helper()
			got := runGuardEvent(t, fixture, connector, event, "s-1")
			if got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
				t.Fatalf("%s: %s must block with the not-running reason: %q", connector, step, got.ManagedRuntimeFailure)
			}
		}
		allowed := func(step string) {
			t.Helper()
			if got := runGuardEvent(t, fixture, connector, event, "s-1"); got.ManagedRuntimeFailure != "" {
				t.Fatalf("%s: %s must allow: %q", connector, step, got.ManagedRuntimeFailure)
			}
		}

		blocked("no protected record")
		// A record under the account's home (the 1.0.3 rc mirror) is not read.
		fixture.write(t, enterprisepolicy.SessionPath(fixture.home, connector, "p", process),
			`{"v":1,"connector":"`+connector+`","process":"`+process+`","started":"2026-10-20T00:00:00Z","state":"x","blocked":false}`)
		blocked("a home record")

		processRecord := records.write(t, connector, "p", process, false, "")
		blocked("a process record without the session's")
		records.allow(t, connector, process, "s-1")
		allowed("records that prove the process and the session unblocked")

		reason := hookexec.ForeignHookBlockedReasonPrefix + " When this agent session started, the project hook file /repo/x.json defined a hook. Restart the agent."
		records.write(t, connector, "s", "s-1", true, reason)
		if got := runGuardEvent(t, fixture, connector, event, "s-1"); got.ManagedRuntimeFailure != reason {
			t.Fatalf("%s: a blocking session record must deny with the gateway's reason: %q", connector, got.ManagedRuntimeFailure)
		}
		records.write(t, connector, "s", "s-1", false, "")
		allowed("the allow that cleared the block")

		records.write(t, connector, "p", process, true, "")
		if got := runGuardEvent(t, fixture, connector, event, "s-1"); !strings.HasPrefix(got.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) {
			t.Fatalf("%s: a blocking process record without a reason must still deny: %q", connector, got.ManagedRuntimeFailure)
		}

		records.write(t, connector, "p", process, false, "")
		records.untrusted[processRecord] = true
		blocked("a record the user can change")
		delete(records.untrusted, processRecord)

		now := time.Now().UTC().Format(time.RFC3339)
		for name, content := range map[string]string{
			"a corrupt record":             `{"v":3,`,
			"a record of another process":  `{"v":3,"connector":"` + connector + `","kind":"p","id":"other","blocked":false,"at":"` + now + `","mac":"00"}`,
			"a record of another agent":    `{"v":3,"connector":"codex","kind":"p","id":"` + process + `","blocked":false,"at":"` + now + `","mac":"00"}`,
			"a record without a valid MAC": `{"v":3,"connector":"` + connector + `","kind":"p","id":"` + process + `","blocked":false,"at":"` + now + `","mac":"00"}`,
			"a record of an earlier build": `{"v":2,"connector":"` + connector + `","kind":"p","id":"` + process + `","blocked":false,"at":"` + now + `","gen":"1"}`,
		} {
			if err := os.WriteFile(processRecord, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			blocked(name)
		}
		if err := os.Remove(processRecord); err != nil {
			t.Fatal(err)
		}
		blocked("a deleted record")

		// An outage that does not follow open never reads the record.
		records.allow(t, connector, process, "s-1")
		records.consulted = 0
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		blocked("an outage under unset or closed")
		if records.consulted != 0 {
			t.Fatalf("%s: an outage under unset or closed must not read the protected record", connector)
		}
		hookForeignGuardExchange = openOutage
		allowed("the proven process again")

		// Review P2: an agent process the hook cannot name is not proven by a
		// clean session record (it may have started during the outage and
		// resumed the session ID).
		fixture.process = ""
		blocked("an unnamed agent process with a clean session record")
		fixture.process = process

		// The kill switch: a record of an earlier key proves nothing, and
		// neither does any record without exactly one key the hook trusts.
		records.newKey(t)
		blocked("records of an earlier key")
		records.allow(t, connector, process, "s-1")
		allowed("the records of the next exchange")
		key := records.key(t)
		records.untrusted[key] = true
		blocked("a key file the user can change")
		delete(records.untrusted, key)
		if err := enterprisepolicy.RevokePublishedSessionKey(records.root, protectedRecordIdentity); err != nil {
			t.Fatal(err)
		}
		blocked("no key")
		records.newKey(t)
		records.allow(t, connector, process, "s-1")
		allowed("the records of the new key")
	}

	// An unapproved hook the scan finds blocks with its own reason, record
	// or not.
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("copilot")
	fixture.process = process
	records := newProtectedRecordFixture(t)
	records.allow(t, "copilot", process, "s-1")
	hookForeignGuardExchange = openOutage
	foreign := filepath.Join(fixture.project, ".github", "hooks", "x.json")
	fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
	found := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1")
	if !strings.HasPrefix(found.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(found.ManagedRuntimeFailure, foreign) {
		t.Fatalf("an unapproved hook must block with its own reason: %q", found.ManagedRuntimeFailure)
	}
}

// GAP-0352: the check the standalone Hermes hook and the OpenCode plugin run
// gives exactly the allow they accept when the protected record proves the
// process unblocked during an open outage, and the outage denial otherwise.
func TestForeignHookCheckFollowsTheProtectedSessionRecordDuringAnOpenOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	connectors := map[string]string{"opencode": "tool.execute.before"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	for connector, event := range connectors {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		records := newProtectedRecordFixture(t)
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, &foreignHookSessionOutageOpen{err: notRunning}
		}
		check := func() (foreignHookCheckResult, string) {
			t.Helper()
			var out bytes.Buffer
			runForeignHookCheck(connector, strings.NewReader(`{"hook_event_name":"`+event+`","session_id":"s-1"}`), &out)
			var result foreignHookCheckResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("%s: %v: %q", connector, err, out.String())
			}
			return result, strings.TrimSpace(out.String())
		}
		if result, _ := check(); !result.Deny || !strings.Contains(result.Reason, hookexec.ManagedGatewayNotRunningReason) {
			t.Fatalf("%s: no record must deny with the not-running reason: %+v", connector, result)
		}
		records.allow(t, connector, "agent-process", "s-1")
		if result, raw := check(); result.Deny || raw != `{"deny":false}` {
			t.Fatalf("%s: a proven process must get exactly the allow: %q", connector, raw)
		}
	}
}

// GAP-0354: the check the standalone Hermes hook and the Amp and OpenCode
// plugins run applies the hook-time guard's outage rule. A guarded
// connector whose session exchange cannot reach the gateway is denied with
// the outage's reason (the check takes no fail mode, so unset and open
// read the same), Hermes with its block object; a gateway that answers for
// a clean session allows with the exact allow the callers accept; a host
// without the standalone summary (per-user, Secure Client) allows as before.
func TestForeignHookCheckDeniesAGuardedConnectorDuringAGatewayOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	connectors := map[string]string{"opencode": "tool.execute.before", "amp": "tool.call"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	check := func(t *testing.T, connector, event string) (foreignHookCheckResult, string) {
		t.Helper()
		var out bytes.Buffer
		payload := `{"hook_event_name":"` + event + `","session_id":"s-1"}`
		if code := runForeignHookCheck(connector, strings.NewReader(payload), &out); code != 0 {
			t.Fatalf("%s: the check always exits 0, got %d", connector, code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("%s: the answer must be JSON: %v: %q", connector, err, out.String())
		}
		return result, strings.TrimSpace(out.String())
	}
	for connector, event := range connectors {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		exchanged := 0
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			exchanged++
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		result, _ := check(t, connector, event)
		if exchanged != 1 && !foreignHookSessionLocal(connector) {
			t.Fatalf("%s: the check did not exchange the session with the gateway (%d)", connector, exchanged)
		}
		if foreignHookSessionLocal(connector) {
			continue // Windows Amp keeps its session record locally
		}
		if !result.Deny || !strings.Contains(result.Reason, hookexec.ManagedGatewayNotRunningReason) {
			t.Fatalf("%s: a stopped gateway must deny with the not-running reason: %+v", connector, result)
		}
		if connector == "hermes" {
			if result.HookOutput == nil || result.HookOutput.Action != "block" || !strings.HasSuffix(result.HookOutput.Message, "("+hookexec.ManagedGatewayNotRunningReason+")") {
				t.Fatalf("hermes: the outage denial must carry the Hermes block object: %+v", result.HookOutput)
			}
		} else if result.HookOutput != nil {
			t.Fatalf("%s: only Hermes gets a hook_output: %+v", connector, result.HookOutput)
		}

		// The gateway is up and the session is clean.
		hookForeignGuardExchange = func(_ string, _ string, _, _ time.Time, exchange enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return exchange.Decision, nil
		}
		if result, raw := check(t, connector, event); result.Deny || raw != `{"deny":false}` {
			t.Fatalf("%s: a clean session with the gateway up must allow exactly: %q", connector, raw)
		}

		// No standalone summary (per-user or Secure Client): unchanged allow,
		// and no exchange.
		fixture.summary = nil
		exchanged = 0
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			exchanged++
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		if result, raw := check(t, connector, event); result.Deny || raw != `{"deny":false}` || exchanged != 0 {
			t.Fatalf("%s: a host without the standalone summary must allow without an exchange: %q (%d)", connector, raw, exchanged)
		}
	}
}
