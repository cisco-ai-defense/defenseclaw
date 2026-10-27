// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-1085, GAP-1089: a sandbox that may be a live legacy or contained one,
// whose gateway has not said whether it runs, is unknown in the daemon's
// status, which holds back every new run. The status names it in those
// words with the daemon's way on, and the doctor fails a row for it; one on
// another gateway names that gateway too. None, no row.
func TestStatusAndDoctorNameAnUnseenSandbox(t *testing.T) {
	row := func(ta *testApp) *openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		return ta.runDoctor(bg).Get(CheckIDUnknownSandbox)
	}
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("plain"))
	ta.daemon.status.Unprotected = []sandboxapi.UnprotectedSandbox{{Name: "held", Phase: "ready", Stop: "defenseclaw sandbox stop held",
		Reason: sandboxapi.UnprotectedContained}}
	if c := row(ta); c != nil {
		t.Fatalf("an unseen row with no unseen sandbox: %+v", c)
	}
	const why = "its session may run ..., and it lives on gateway old, which DefenseClaw could not read (connection refused): connect DefenseClaw to that gateway"
	ta.daemon.status.Unprotected = append(ta.daemon.status.Unprotected,
		sandboxapi.UnprotectedSandbox{Name: "unseen", Phase: "unknown", Reason: sandboxapi.UnprotectedUnknown, Detail: why},
		sandboxapi.UnprotectedSandbox{Name: "away", Phase: "ready", Stop: "defenseclaw sandbox stop away",
			Detail: "it runs on gateway old, not the gateway DefenseClaw is connected to: connect DefenseClaw to that gateway (openshell.gateway), then stop it"})
	c := row(ta)
	if c == nil || c.Status != openshell.StatusFail || c.Fix == nil || !strings.Contains(c.Detail, "unseen: "+sandboxapi.UnknownUnprotected) ||
		strings.Contains(c.Detail, "held") || strings.Contains(c.Detail, "away") || c.Fix.Summary != "unseen: "+why {
		t.Fatalf("unseen row = %+v", c)
	}
	ta.out.Reset()
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "unseen: "+sandboxapi.UnknownUnprotected+"; no new sandbox runs until its gateway says: "+why,
		"away: "+sandboxapi.LegacyUnprotected+"; no new sandbox runs until it is gone: it runs on gateway old",
		"held: "+sandboxapi.ContainedUnprotected+"; no new sandbox runs until it is gone: `defenseclaw sandbox stop held`")
	if strings.Contains(ta.output(), "unseen: "+sandboxapi.LegacyUnprotected) || strings.Contains(ta.output(), "``") {
		t.Fatalf("an unseen sandbox is named a legacy one, or with an empty command:\n%s", ta.output())
	}
}

// GAP-1068: the doctor said sandboxes were ready on a computer without git,
// and the next run failed before its first turn: a run copies the project
// into the sandbox, and keeps its pre-session snapshot, with the host's
// git. The doctor now checks it, and says how to install it (on a managed
// computer, whom to ask).
func TestDoctorChecksTheHostGitEveryRunNeeds(t *testing.T) {
	check := func(git func(context.Context) (string, error)) *openshell.Check {
		t.Helper()
		ta := newTestApp(t, "")
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		ta.HostGit = git
		return ta.runDoctor(bg).Get(CheckIDHostGit)
	}
	if c := check(func(context.Context) (string, error) { return "2.47.3", nil }); c == nil || c.Status != openshell.StatusPass || c.Detail != "git 2.47.3" {
		t.Fatalf("host git row with git = %+v", c)
	}
	missing := func(context.Context) (string, error) {
		return "", errors.New(`workspace: git is required on this machine: exec: "git": executable file not found in $PATH`)
	}
	c := check(missing)
	if c == nil || c.Status != openshell.StatusFail || c.Fix == nil || !strings.Contains(c.Detail, "git is required on this machine") ||
		!strings.Contains(c.Detail, "no run starts without it") || !strings.Contains(c.Fix.Summary, "sudo dnf install git") {
		t.Fatalf("host git row without git = %+v", c)
	}
	ta := newTestApp(t, "")
	ta.HostGit = missing
	if c := ta.hostGitCheck(bg, true); c.Fix == nil || c.Fix.Summary != "ask your administrator to install git 2.29 or newer on this computer" {
		t.Fatalf("managed host git row without git = %+v", c)
	}
}
