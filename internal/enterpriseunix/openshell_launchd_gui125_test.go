// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// launchctlPrint125 is what root's `launchctl print gui/<uid>` returned on
// macOS 15.8 (dc-fc-r102-mac, rc.5) for an account with no GUI session.
const launchctlPrint125 = "Could not print domain: 125: Domain does not support specified action"

// domainAnswerRunner answers `launchctl print <domain>` for the listed domains
// with a fixed failure, formatted as the production runner formats it.
type domainAnswerRunner struct {
	*fixtureLaunchdRunner
	answers map[string]CommandResult
}

func (r *domainAnswerRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "launchctl" && len(args) == 2 && args[0] == "print" {
		if res, ok := r.answers[args[1]]; ok {
			return res, fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.ExitCode, strings.TrimSpace(string(res.Stderr)))
		}
	}
	return r.fixtureLaunchdRunner.Run(ctx, name, args...)
}

func answerDomain(h *osHost, f *fixtureLaunchdRunner, domain string, code int, stderr string) {
	h.env.Runner = &domainAnswerRunner{fixtureLaunchdRunner: f, answers: map[string]CommandResult{domain: {Stderr: []byte(stderr + "\n"), ExitCode: code}}}
}

func setConsoleOwner(h *osHost, uid int) {
	h.owners[h.env.P("/dev/console")] = [2]int{uid, 0}
}

func TestMacOSLoggedOutGUIDomainExit125(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    string // gui or user
		code    int
		stderr  string
		console string // "root", "self" or "" (unreadable)
		wantErr bool
	}{
		{name: "logged out gui domain", kind: "gui", code: 125, stderr: launchctlPrint125, console: "root"},
		{name: "another user at the console", kind: "gui", code: 125, stderr: launchctlPrint125, console: "other"},
		{name: "logged in gui domain", kind: "gui", code: 125, stderr: launchctlPrint125, console: "self", wantErr: true},
		{name: "console unreadable", kind: "gui", code: 125, stderr: launchctlPrint125, wantErr: true},
		{name: "exit 125 other message", kind: "gui", code: 125, stderr: "Could not print domain: 125: Operation not permitted", console: "root", wantErr: true},
		{name: "unknown exit code", kind: "gui", code: 5, stderr: "Could not print domain: 5: Input/output error", console: "root", wantErr: true},
		{name: "user domain", kind: "user", code: 125, stderr: launchctlPrint125, console: "root", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _ := newLaunchdTestHost(t)
			uid := h.alice.UID
			domain := tc.kind + "/" + strconv.Itoa(uid)
			if tc.kind == "user" {
				f.userDomains = map[int]bool{uid: true}
				f.userJobs = map[int]map[string]*launchdJobFixture{uid: {}}
			}
			baseline := map[string]*enterprisestatus.Result{}
			for _, action := range []string{ActionStatus, ActionVerify} {
				baseline[action] = h.run(Options{Action: action})
			}
			switch tc.console {
			case "root":
				setConsoleOwner(h, 0)
			case "other":
				setConsoleOwner(h, uid+1)
			case "self":
				setConsoleOwner(h, uid)
			}
			answerDomain(h, f, domain, tc.code, tc.stderr)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				message := messagesOf(r.Errors, codeSandboxUserState)
				if tc.wantErr {
					if !strings.Contains(message, "inspect LaunchAgent domain "+domain+" of "+h.alice.Name) || !strings.Contains(message, tc.stderr) || r.SecurityComplete {
						t.Fatalf("%s hid the launchctl failure: errors=%+v security_complete=%v", action, r.Errors, r.SecurityComplete)
					}
					continue
				}
				base := baseline[action]
				if message != "" || len(r.Errors) != len(base.Errors) || r.ExitCode != base.ExitCode || r.SecurityComplete != base.SecurityComplete {
					t.Fatalf("%s failed a logged-out account: errors=%+v exit=%d baseline_exit=%d security_complete=%v baseline_security=%v", action, r.Errors, r.ExitCode, base.ExitCode, r.SecurityComplete, base.SecurityComplete)
				}
			}
			seeded := &enterprisestatus.Result{SecurityComplete: true}
			(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeMacOSAgents(context.Background())
			if seeded.SecurityComplete == tc.wantErr || (len(seeded.Errors) != 0) != tc.wantErr {
				t.Fatalf("describe: want error %v, got %+v", tc.wantErr, seeded)
			}
			if len(f.mutated) != 0 {
				t.Fatalf("read-only actions mutated launchd: %v", f.mutated)
			}
		})
	}
}

// TestMacOSPackageUpgradeLoggedOutAccountLeavesNoPending is the rc.3 to rc.5
// field case: the signed gateway changed, the account has no GUI session, and
// a launchd entry recorded by rc.5 for the same account is dropped.
func TestMacOSPackageUpgradeLoggedOutAccountLeavesNoPending(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	uid := h.alice.UID
	setConsoleOwner(h, 0)
	answerDomain(h, f, "gui/"+strconv.Itoa(uid), 125, launchctlPrint125)
	// rc.5 recorded this; the daemon of an idle account does not answer.
	h.ops.statusErr = map[int]error{uid: errors.New("sandbox daemon not running")}
	state := h.env.loadOpenShellState()
	state.Pending[strconv.Itoa(uid)] = pending{User: h.alice.Name, UID: uid, Home: h.alice.Home, Kind: "launchd", Reason: "the signed gateway binary changed (inspect LaunchAgent domain gui/" + strconv.Itoa(uid) + " of " + h.alice.Name + ": " + launchctlPrint125 + ")", Since: "2026-10-14T20:26:26Z", Sandboxes: -1}
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || messagesOf(r.Warnings, codeSandboxUserState) != "" || messagesOf(r.Warnings, codeSandboxPending) != "" || len(f.mutated) != 0 {
		t.Fatalf("package ensure flagged a logged-out account: errors=%+v warnings=%+v calls=%v", r.Errors, r.Warnings, f.mutated)
	}
	if pending := h.env.loadOpenShellState().Pending; len(pending) != 0 {
		t.Fatalf("ensure left a pending entry for a logged-out account: %+v", pending)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if r := h.run(Options{Action: action}); messagesOf(r.Errors, codeSandboxUserState) != "" || messagesOf(r.Warnings, codeSandboxPending) != "" {
			t.Fatalf("%s after the upgrade: errors=%+v warnings=%+v", action, r.Errors, r.Warnings)
		}
	}
}
