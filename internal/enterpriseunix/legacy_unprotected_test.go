// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0901: a live legacy guest, whose old supervisor's broker DefenseClaw
// cannot contain, read as protected on a managed host: status and verify
// said nothing of it. Every account whose daemon reports one (or that a
// daemon of an earlier DefenseClaw still holds sandboxes for, or whose
// daemon cannot answer) now gets a "sandbox unprotected" row and a warning
// that says "running unprotected: legacy sandbox" with the command its user
// runs to end it, and the deployment is not security-complete. A current
// daemon with nothing legacy changes nothing.
func TestALegacySandboxIsReportedUnprotected(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name   string
			status SandboxStatus
			err    error
			want   string
		}{
			{name: "a live legacy guest", status: SandboxStatus{Active: true, Running: 2, Live: 2,
				Unprotected: []UnprotectedSandbox{{Name: "kept", Stop: "defenseclaw sandbox stop kept"}, {Name: "ended", Stop: "defenseclaw sandbox delete ended"}}},
				want: "kept; as alice, `defenseclaw sandbox stop kept` ends it"},
			{name: "an earlier daemon that holds sandboxes", status: SandboxStatus{Active: true, Running: 1, Live: 1, Legacy: true},
				want: "the sandbox daemon of an earlier DefenseClaw holds 1 sandbox, which this version cannot show protected"},
			{name: "a daemon that cannot answer", err: errors.New("read the sandbox status of alice: EOF"),
				want: "its sandbox daemon could not say whether one runs (read the sandbox status of alice: EOF)"},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				h := newOSHost(t, goos)
				h.ops.loggedIn = []SandboxAccount{h.alice}
				h.ops.status[h.alice.UID] = tc.status
				if tc.err != nil {
					h.ops.statusErr[h.alice.UID] = tc.err
				}
				seeded := &enterprisestatus.Result{SecurityComplete: true}
				(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeLegacySandboxes(context.Background())
				warning := messagesOf(seeded.Warnings, codeLegacySandbox)
				state, ok := rowState(seeded, "sandbox unprotected alice")
				if seeded.SecurityComplete || !ok || !strings.HasPrefix(state, sandboxapi.LegacyUnprotected+": ") || !strings.Contains(state, tc.want) ||
					!strings.Contains(warning, "alice: "+sandboxapi.LegacyUnprotected+": "+tc.want) ||
					!strings.Contains(warning, "DefenseClaw stops no sandbox for its user, and runs no new sandbox for alice until it is gone") {
					t.Fatalf("security_complete=%v row=%q (%v) warning=%q", seeded.SecurityComplete, state, ok, warning)
				}
				if len(tc.status.Unprotected) == 2 && (strings.Count(warning, "\n") != 2 || !strings.Contains(warning, "`defenseclaw sandbox delete ended` ends it")) {
					t.Fatalf("not one warning per legacy guest: %q", warning)
				}
			})
		}
		t.Run(goos+"/nothing legacy", func(t *testing.T) {
			h := newOSHost(t, goos)
			h.ops.loggedIn = []SandboxAccount{h.alice}
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Live: 1}
			seeded := &enterprisestatus.Result{SecurityComplete: true}
			(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeLegacySandboxes(context.Background())
			if _, ok := rowState(seeded, "sandbox unprotected alice"); ok || !seeded.SecurityComplete || len(seeded.Warnings) != 0 {
				t.Fatalf("a current daemon was reported unprotected: %+v", seeded)
			}
		})
	}
}

// GAP-0902 review: a MicroVM DefenseClaw had to stop for a security alarm
// but keeps running contained, because its disk could not be synced first,
// is reported unprotected in its own words (not as a legacy guest's old
// supervisor), with the command that ends it, and the deployment is not
// security-complete.
func TestAContainedSandboxIsReportedUnprotected(t *testing.T) {
	h := newOSHost(t, "linux")
	h.ops.loggedIn = []SandboxAccount{h.alice}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 2, Live: 2, Unprotected: []UnprotectedSandbox{
		{Name: "held", Stop: "defenseclaw sandbox stop held", Reason: sandboxapi.UnprotectedContained},
		{Name: "kept", Stop: "defenseclaw sandbox stop kept"}}}
	seeded := &enterprisestatus.Result{SecurityComplete: true}
	(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeLegacySandboxes(context.Background())
	warning := messagesOf(seeded.Warnings, codeLegacySandbox)
	var held, kept string
	for _, line := range strings.Split(warning, "\n") {
		switch {
		case strings.Contains(line, "held;"):
			held = line
		case strings.Contains(line, "kept;"):
			kept = line
		}
	}
	if seeded.SecurityComplete || !strings.HasPrefix(held, "alice: "+sandboxapi.ContainedUnprotected+": held; as alice, `defenseclaw sandbox stop held` ends it") ||
		!strings.Contains(held, "its MicroVM's disk could not be synced first") || strings.Contains(held, "older than") ||
		!strings.HasPrefix(kept, "alice: "+sandboxapi.LegacyUnprotected+": kept") || !strings.Contains(kept, "older than") {
		t.Fatalf("security_complete=%v warning=%q", seeded.SecurityComplete, warning)
	}
	rows := 0
	for _, s := range seeded.Services {
		if s.Name == "sandbox unprotected alice" && strings.HasPrefix(s.State, sandboxapi.ContainedUnprotected+": held") {
			rows++
		}
	}
	if rows != 1 {
		t.Fatalf("services = %+v", seeded.Services)
	}
}

// GAP-1085, GAP-1089: a sandbox that may be a live legacy or contained
// one, whose gateway has not said whether it runs, is reported in its own
// words with the daemon's way on (not as a legacy guest with an empty
// command), and so is one on another gateway than the daemon's; the
// deployment is not security-complete.
func TestAnUnseenSandboxIsReportedUnprotected(t *testing.T) {
	h := newOSHost(t, "linux")
	h.ops.loggedIn = []SandboxAccount{h.alice}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Live: 1, Unprotected: []UnprotectedSandbox{
		{Name: "unseen", Reason: sandboxapi.UnprotectedUnknown, Detail: "it lives on gateway old, which DefenseClaw could not read"},
		{Name: "away", Stop: "defenseclaw sandbox stop away", Detail: "it runs on gateway old: connect DefenseClaw to that gateway, then stop it"}}}
	seeded := &enterprisestatus.Result{SecurityComplete: true}
	(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeLegacySandboxes(context.Background())
	warning := messagesOf(seeded.Warnings, codeLegacySandbox)
	if seeded.SecurityComplete ||
		!strings.Contains(warning, "alice: "+sandboxapi.UnknownUnprotected+": unseen; as alice: it lives on gateway old, which DefenseClaw could not read. It may be") ||
		!strings.Contains(warning, "alice: "+sandboxapi.LegacyUnprotected+": away; as alice: it runs on gateway old: connect DefenseClaw to that gateway") ||
		strings.Contains(warning, "``") {
		t.Fatalf("security_complete=%v warning=%q", seeded.SecurityComplete, warning)
	}
}

// Status warns and is not security-complete while a legacy sandbox runs,
// and verify fails on it.
func TestVerifyFailsWhileALegacySandboxRuns(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})))
	h.ops.loggedIn = []SandboxAccount{h.alice}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Live: 1,
		Unprotected: []UnprotectedSandbox{{Name: "kept", Stop: "defenseclaw sandbox stop kept"}}}
	status := h.run(Options{Action: ActionStatus})
	if messagesOf(status.Warnings, codeLegacySandbox) == "" || status.SecurityComplete {
		t.Fatalf("status: warnings=%+v security_complete=%v", status.Warnings, status.SecurityComplete)
	}
	verify := h.run(Options{Action: ActionVerify})
	if !strings.Contains(messagesOf(verify.Errors, codeVerify), "alice: "+sandboxapi.LegacyUnprotected+": kept") || verify.SecurityComplete || verify.ExitCode == 0 {
		t.Fatalf("verify: errors=%+v security_complete=%v exit=%d", verify.Errors, verify.SecurityComplete, verify.ExitCode)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	if verify := h.run(Options{Action: ActionVerify}); strings.Contains(messagesOf(verify.Errors, codeVerify), sandboxapi.LegacyUnprotected) {
		t.Fatalf("verify still fails once the legacy sandbox is gone: %+v", verify.Errors)
	}
}

// The account's status carries the legacy guests a daemon of 1.0.4 or
// later reports.
func TestCommandOpsStatusReadsTheUnprotectedSandboxes(t *testing.T) {
	ops, _, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
		switch {
		case strings.HasSuffix(line, "is-active defenseclaw-sandbox.service"):
			return CommandResult{Stdout: []byte("active\n")}, nil
		case strings.HasSuffix(line, "sandbox status --output json"):
			return CommandResult{Stdout: []byte(`{"sandboxes":1,"running":1,"live":1,"unprotected":[{"name":"kept","phase":"ready","stop":"defenseclaw sandbox stop kept"}]}`)}, nil
		}
		return CommandResult{}, nil
	})
	st, err := ops.Status(context.Background(), alice)
	if err != nil || len(st.Unprotected) != 1 || st.Unprotected[0] != (UnprotectedSandbox{Name: "kept", Stop: "defenseclaw sandbox stop kept"}) {
		t.Fatalf("Status = %+v %v", st, err)
	}
}
