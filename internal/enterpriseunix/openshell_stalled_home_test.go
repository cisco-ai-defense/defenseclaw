// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// stallHomeLookups makes every bounded home lookup time out, as for a home
// on a stalled FUSE or NFS mount, and records the homes looked up.
func stallHomeLookups(t *testing.T) *[]string {
	t.Helper()
	var asked []string
	old := homeLookupAnswers
	homeLookupAnswers = func(path string) bool {
		asked = append(asked, path)
		return false
	}
	t.Cleanup(func() { homeLookupAnswers = old })
	return &asked
}

// GAP-1751: status and verify opened each sandbox account's home in process
// (retainedComputeRefusal, from the macOS LaunchAgent check). On a stalled
// home mount the open blocked a thread in the kernel and neither printed an
// answer. In status and verify a home that does not answer a bounded lookup
// is not opened; the other actions open it as before.
func TestStatusAndVerifyDoNotOpenASandboxHomeThatDoesNotAnswer(t *testing.T) {
	h := newOSHost(t, "darwin")
	asked := stallHomeLookups(t)

	h.env.boundedHomeLookups = false
	if err := h.env.retainedComputeRefusal(h.alice); err != nil {
		t.Fatalf("a lifecycle change no longer opens the home: %v", err)
	}
	if len(*asked) != 0 {
		t.Fatalf("a lifecycle change looked the home up: %v", *asked)
	}

	h.env.boundedHomeLookups = true
	err := h.env.retainedComputeRefusal(h.alice)
	if !errors.Is(err, errHomeNotAnswering) {
		t.Fatalf("status opened a home that did not answer its lookup: err=%v", err)
	}
	if len(*asked) != 1 || !strings.HasPrefix((*asked)[0], h.env.P(h.alice.Home)+"/.defenseclaw-lookup-") {
		t.Fatalf("lookups=%v, want one lookup of a name below the home %s", *asked, h.env.P(h.alice.Home))
	}
	if err := h.env.retainedComputeRefusal(h.alice); !errors.Is(err, errHomeNotAnswering) || len(*asked) != 1 {
		t.Fatalf("the run did not keep the answer: err=%v lookups=%v", err, *asked)
	}
	if homes := h.env.unansweredHomes(); len(homes) != 1 || homes[0] != h.env.P(h.alice.Home) {
		t.Fatalf("unanswered homes=%v", homes)
	}

	for _, action := range []string{ActionStatus, ActionVerify} {
		h.env.boundedHomeLookups = false
		h.run(Options{Action: action})
		if !h.env.boundedHomeLookups {
			t.Fatalf("%s does not bound its home lookups", action)
		}
	}
}

// A sandbox account whose home did not answer is reported as not confirmed
// and keeps security_complete false; it is not read as an idle account.
func TestMacOSAgentsReportASandboxHomeThatDoesNotAnswer(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", code: "(never exited)", runs: 1}

	healthy := &enterprisestatus.Result{SecurityComplete: true}
	(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: healthy}).describeMacOSAgents(context.Background())
	if !healthy.SecurityComplete || len(healthy.Errors) != 0 {
		t.Fatalf("an idle account is not healthy: %+v", healthy)
	}

	h.ops.statusErr[h.alice.UID] = fmt.Errorf("account home %s: %w", h.alice.Home, errHomeNotAnswering)
	r := &enterprisestatus.Result{SecurityComplete: true}
	(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: r}).describeMacOSAgents(context.Background())
	warning := messagesOf(r.Warnings, codeSandboxUserState)
	if r.SecurityComplete || len(r.Errors) != 0 || !strings.Contains(warning, "of alice") || !strings.Contains(warning, "not confirmed") {
		t.Fatalf("an unanswered home read as an idle account: security_complete=%v errors=%+v warning=%q", r.SecurityComplete, r.Errors, warning)
	}
	if len(f.mutated) != 0 {
		t.Fatalf("status changed launchd: %v", f.mutated)
	}
}

// The enrolled-home and cleanup checks of status and verify look each home
// up in process too (contracts.go), and verify reads Copilot settings below
// each home (machinepolicy.go). A home that does not answer is named once
// as not checked, with security_complete false, without those lookups.
func TestStatusReportsAnEnrolledHomeThatDoesNotAnswerAsNotChecked(t *testing.T) {
	h := newOSHost(t, "darwin")
	writeHostFile(t, h.testHost, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: alice\n    uid: 506\n    user_home: "+h.alice.Home+"\n    connector: amp\n")
	r := &enterprisestatus.Result{SecurityComplete: true}
	l := &lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: r}
	h.env.boundedHomeLookups = true
	l.describeUnavailableEnrolledHomes()
	l.describeUnansweredHomes()
	if hasWarning(r, codeEnrolledHomeUnavailable) || !r.SecurityComplete {
		t.Fatalf("an answering home was reported: %+v", r)
	}
	h.env.homeLookups.answered = nil
	asked := stallHomeLookups(t)
	l.describeUnavailableEnrolledHomes()
	l.describeUnansweredHomes()
	got := messagesOf(r.Warnings, codeEnrolledHomeUnavailable)
	if !strings.Contains(got, "home "+h.env.P(h.alice.Home)+" did not answer") || strings.Contains(got, "user alice (home") || r.SecurityComplete || len(*asked) != 1 {
		t.Fatalf("a home that did not answer was not reported once as not checked: security_complete=%v warnings=%q lookups=%v", r.SecurityComplete, got, *asked)
	}
}
