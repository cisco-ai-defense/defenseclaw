// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestEnforcementProjectionPreviewOnly(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectPreview, "remove-item"),
	)
	facts.Paths = []PathFact{{
		CommandID: 1,
		Access:    PathAccessDelete,
		Value:     `C:\important`,
	}}
	facts.Network = []NetworkFact{{
		CommandID: 1,
		Action:    NetworkUpload,
		Host:      "preview.example",
	}}
	facts.DataFlows = []DataFlowFact{{
		FromCommandID: 1,
		From:          DataFile,
		To:            DataNetwork,
	}}

	projected := facts.EnforcementProjection()

	if len(projected.Commands) != 0 ||
		len(projected.Paths) != 0 ||
		len(projected.Network) != 0 ||
		len(projected.DataFlows) != 0 {
		t.Fatalf("preview facts survived enforcement projection: %#v", projected)
	}
	if projected.EnforcementEligible() {
		t.Fatal("empty preview projection became enforcement eligible")
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRetainsPOSIXPreviewRedirect(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "exec",
		Command: "ssh -G example.test > /etc/cron.d/persist",
	})
	if !facts.Authoritative() ||
		len(facts.Commands) != 1 ||
		facts.Commands[0].Effect != EffectPreview {
		t.Fatalf("preview facts = %#v", facts)
	}

	projected := facts.EnforcementProjection()

	if !projected.EnforcementEligible() || len(projected.Commands) != 1 {
		t.Fatalf("redirect projection = %#v", projected)
	}
	command := projected.Commands[0]
	if command.Kind != CommandKindShellRedirect ||
		command.Program != "" ||
		command.Executable != "" ||
		len(command.Argv) != 0 ||
		command.Effect != EffectExecute ||
		!commandHasOperation(command, OperationWrite) ||
		commandHasOperation(command, OperationList) {
		t.Fatalf("redirect command = %#v", command)
	}
	if len(projected.Paths) != 1 ||
		projected.Paths[0].Access != PathAccessWrite ||
		projected.Paths[0].Resolved != "/etc/cron.d/persist" {
		t.Fatalf("redirect paths = %#v", projected.Paths)
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRetainsPowerShellPreviewRedirectOnly(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "powershell",
		Command: `Remove-Item C:\victim -WhatIf > C:\persist.txt`,
	})
	if !facts.Authoritative() ||
		len(facts.Commands) != 1 ||
		facts.Commands[0].Effect != EffectPreview {
		t.Fatalf("preview facts = %#v", facts)
	}

	projected := facts.EnforcementProjection()

	if !projected.EnforcementEligible() || len(projected.Commands) != 1 {
		t.Fatalf("redirect projection = %#v", projected)
	}
	command := projected.Commands[0]
	if command.Kind != CommandKindShellRedirect ||
		command.Program != "" ||
		!commandHasOperation(command, OperationWrite) ||
		commandHasOperation(command, OperationDelete) {
		t.Fatalf("redirect command = %#v", command)
	}
	if len(projected.Paths) != 1 ||
		projected.Paths[0].Access != PathAccessWrite ||
		projected.Paths[0].Resolved != "C:/persist.txt" {
		t.Fatalf("redirect paths = %#v", projected.Paths)
	}
	for _, path := range projected.Paths {
		if path.Value == `C:\victim` {
			t.Fatalf("preview delete target survived projection: %#v", projected.Paths)
		}
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRetainsPreviewNetworkRedirect(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "exec",
		Command: "ssh -G example.test > /dev/tcp/127.0.0.1/4444",
	})
	if !facts.Authoritative() ||
		len(facts.Commands) != 1 ||
		facts.Commands[0].Effect != EffectPreview {
		t.Fatalf("preview facts = %#v", facts)
	}

	projected := facts.EnforcementProjection()

	if !projected.EnforcementEligible() ||
		len(projected.Commands) != 1 ||
		!commandHasOperation(projected.Commands[0], OperationConnect) {
		t.Fatalf("network redirect projection = %#v", projected)
	}
	if len(projected.Network) != 1 ||
		projected.Network[0].Action != NetworkConnect ||
		projected.Network[0].NormalizedHost != "127.0.0.1" ||
		projected.Network[0].Port != 4444 {
		t.Fatalf("network redirect facts = %#v", projected.Network)
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRetainsRedirectAsStructuralParent(t *testing.T) {
	preview := enforcementTestCommand(1, 0, EffectPreview, "ssh")
	preview.Redirects = []RedirectFact{{
		FD:     1,
		Access: PathAccessWrite,
		Target: "/tmp/preview-output",
	}}
	child := enforcementTestCommand(2, 1, EffectExecute, "logger")
	facts := enforcementTestFacts(preview, child)

	projected := facts.EnforcementProjection()

	if len(projected.Commands) != 2 {
		t.Fatalf("commands = %#v, want redirect plus execute child", projected.Commands)
	}
	if projected.Commands[0].Kind != CommandKindShellRedirect ||
		projected.Commands[0].ParentCommandID != 0 {
		t.Fatalf("redirect command = %#v", projected.Commands[0])
	}
	if projected.Commands[1].ID != 2 ||
		projected.Commands[1].ParentCommandID != 1 {
		t.Fatalf("execute child lost retained structural parent: %#v", projected.Commands[1])
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRetainsRedirectHierarchyWithoutSemanticOwnership(
	t *testing.T,
) {
	parent := enforcementTestCommand(1, 0, EffectPreview, "ssh")
	parent.Redirects = []RedirectFact{{
		FD:     1,
		Access: PathAccessWrite,
		Target: "/tmp/parent-output",
	}}
	child := enforcementTestCommand(2, 1, EffectPreview, "ssh")
	child.Redirects = []RedirectFact{{
		FD:     1,
		Access: PathAccessWrite,
		Target: "/tmp/child-output",
	}}
	facts := enforcementTestFacts(parent, child)
	facts.Paths = []PathFact{{
		CommandID: 1,
		Access:    PathAccessDelete,
		Value:     "/tmp/preview-path-must-not-survive",
	}}
	facts.Network = []NetworkFact{{
		CommandID: 2,
		Action:    NetworkUpload,
		Host:      "preview.example",
	}}
	facts.DataFlows = []DataFlowFact{{
		FromCommandID: 1,
		ToCommandID:   2,
		From:          DataNetwork,
		To:            DataProcess,
	}}

	projected := facts.EnforcementProjection()

	if len(projected.Commands) != 2 ||
		projected.Commands[0].ID != 1 ||
		projected.Commands[0].ParentCommandID != 0 ||
		projected.Commands[1].ID != 2 ||
		projected.Commands[1].ParentCommandID != 1 {
		t.Fatalf("redirect hierarchy = %#v", projected.Commands)
	}
	if len(projected.Paths) != 2 {
		t.Fatalf("redirect paths = %#v, want two synthesized writes", projected.Paths)
	}
	for _, path := range projected.Paths {
		if path.Access != PathAccessWrite ||
			path.Value == "/tmp/preview-path-must-not-survive" {
			t.Fatalf("preview semantic path leaked into projection: %#v", projected.Paths)
		}
	}
	if len(projected.Network) != 0 {
		t.Fatalf("preview semantic network leaked into projection: %#v", projected.Network)
	}
	for _, flow := range projected.DataFlows {
		if flow.FromCommandID == 1 &&
			flow.ToCommandID == 2 &&
			flow.From == DataNetwork &&
			flow.To == DataProcess {
			t.Fatalf("preview semantic flow leaked into projection: %#v", projected.DataFlows)
		}
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionDoesNotSynthesizeUncertainOrDynamicRedirects(t *testing.T) {
	tests := []struct {
		name    string
		effect  CommandEffect
		expands bool
	}{
		{name: "uncertain command", effect: EffectUncertain},
		{name: "dynamic preview redirect", effect: EffectPreview, expands: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := enforcementTestCommand(1, 0, test.effect, "command")
			command.Redirects = []RedirectFact{{
				FD:      1,
				Access:  PathAccessWrite,
				Target:  "$OUTPUT",
				Expands: test.expands,
			}}
			facts := enforcementTestFacts(command)
			if test.effect == EffectUncertain {
				facts.Parse.Status = StatusPartial
				facts.Parse.Issues = []IssueCode{IssueUnsupportedConstruct}
			}

			projected := facts.EnforcementProjection()

			if len(projected.Commands) != 0 ||
				len(projected.Paths) != 0 ||
				len(projected.Network) != 0 ||
				len(projected.DataFlows) != 0 {
				t.Fatalf("unsafe redirect projection = %#v", projected)
			}
			if projected.EnforcementEligible() {
				t.Fatalf("unsafe redirect became enforcement eligible: %#v", projected)
			}
			assertFactsInvariants(t, projected)
		})
	}
}

func TestEnforcementProjectionDropsEmptyStaticRedirectTargets(t *testing.T) {
	command := enforcementTestCommand(1, 0, EffectPreview, "ssh")
	command.Redirects = []RedirectFact{
		{FD: 1, Access: PathAccessWrite},
		{FD: 1, Access: PathAccessWrite, Target: "/tmp/preview-output"},
	}

	projected := enforcementTestFacts(command).EnforcementProjection()
	if !projected.EnforcementEligible() ||
		len(projected.Commands) != 1 ||
		len(projected.Commands[0].Redirects) != 1 ||
		projected.Commands[0].Redirects[0].Target != "/tmp/preview-output" {
		t.Fatalf("empty redirect target survived projection: %#v", projected)
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionExecuteOnly(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectExecute, "curl"),
	)
	facts.Paths = []PathFact{{
		CommandID: 1,
		Access:    PathAccessRead,
		Value:     "/tmp/payload",
	}}
	facts.Network = []NetworkFact{{
		CommandID: 1,
		Action:    NetworkUpload,
		Scheme:    "https",
		Host:      "sink.example",
	}}
	facts.DataFlows = []DataFlowFact{
		{
			ToCommandID: 1,
			From:        DataFile,
			To:          DataStdin,
		},
		{
			FromCommandID: 1,
			From:          DataStdout,
			To:            DataNetwork,
		},
	}

	projected := facts.EnforcementProjection()

	if !reflect.DeepEqual(projected, facts) {
		t.Fatalf("execute-only projection changed facts:\ngot  %#v\nwant %#v", projected, facts)
	}
	if !projected.EnforcementEligible() {
		t.Fatal("authoritative execute-only projection is not enforcement eligible")
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionPreviewParentExecuteChild(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectPreview, "powershell"),
		enforcementTestCommand(2, 1, EffectExecute, "remove-item"),
	)
	facts.Paths = []PathFact{
		{CommandID: 1, Access: PathAccessExecute, Value: "preview.ps1"},
		{CommandID: 2, Access: PathAccessDelete, Value: `C:\important`},
	}
	facts.DataFlows = []DataFlowFact{
		{
			FromCommandID: 2,
			ToCommandID:   1,
			From:          DataStdout,
			To:            DataProcess,
		},
		{
			FromCommandID: 2,
			From:          DataFile,
			To:            DataStdout,
		},
	}

	projected := facts.EnforcementProjection()

	if facts.EnforcementEligible() {
		t.Fatal("mixed preview/execute source unexpectedly enforcement eligible")
	}
	if len(projected.Commands) != 1 || projected.Commands[0].ID != 2 {
		t.Fatalf("commands = %#v, want only execute child", projected.Commands)
	}
	if projected.Commands[0].ParentCommandID != 0 {
		t.Fatalf("parent = %d, want repaired root", projected.Commands[0].ParentCommandID)
	}
	if len(projected.Paths) != 1 || projected.Paths[0].CommandID != 2 {
		t.Fatalf("paths = %#v, want execute-child path only", projected.Paths)
	}
	if len(projected.DataFlows) != 1 ||
		projected.DataFlows[0].FromCommandID != 2 ||
		projected.DataFlows[0].ToCommandID != 0 {
		t.Fatalf("flows = %#v, want only child-to-external flow", projected.DataFlows)
	}
	if !projected.EnforcementEligible() {
		t.Fatal("execute child projection is not enforcement eligible")
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionExecuteParentPreviewChild(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectExecute, "powershell"),
		enforcementTestCommand(2, 1, EffectPreview, "remove-item"),
	)
	facts.Network = []NetworkFact{
		{CommandID: 1, Action: NetworkConnect, Host: "execute.example"},
		{CommandID: 2, Action: NetworkUpload, Host: "preview.example"},
	}
	facts.DataFlows = []DataFlowFact{
		{
			FromCommandID: 2,
			ToCommandID:   1,
			From:          DataStdout,
			To:            DataProcess,
		},
		{
			FromCommandID: 1,
			From:          DataStdout,
			To:            DataNetwork,
		},
	}

	projected := facts.EnforcementProjection()

	if facts.EnforcementEligible() {
		t.Fatal("mixed execute/preview source unexpectedly enforcement eligible")
	}
	if len(projected.Commands) != 1 ||
		projected.Commands[0].ID != 1 ||
		projected.Commands[0].ParentCommandID != 0 {
		t.Fatalf("commands = %#v, want only execute parent", projected.Commands)
	}
	if len(projected.Network) != 1 ||
		projected.Network[0].Host != "execute.example" {
		t.Fatalf("network = %#v, want execute-parent destination only", projected.Network)
	}
	if len(projected.DataFlows) != 1 ||
		projected.DataFlows[0].FromCommandID != 1 ||
		projected.DataFlows[0].ToCommandID != 0 {
		t.Fatalf("flows = %#v, want only parent-to-external flow", projected.DataFlows)
	}
	if !projected.EnforcementEligible() {
		t.Fatal("execute parent projection is not enforcement eligible")
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRepairsNearestRetainedParent(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectExecute, "outer"),
		enforcementTestCommand(2, 1, EffectUncertain, "middle"),
		enforcementTestCommand(3, 2, EffectExecute, "inner"),
	)
	facts.Parse.Status = StatusPartial
	facts.Parse.Issues = []IssueCode{IssueUnsupportedConstruct}

	projected := facts.EnforcementProjection()

	if len(projected.Commands) != 2 {
		t.Fatalf("commands = %#v, want two execute commands", projected.Commands)
	}
	if projected.Commands[1].ID != 3 ||
		projected.Commands[1].ParentCommandID != 1 {
		t.Fatalf("inner command = %#v, want reparented to command 1", projected.Commands[1])
	}
	if projected.Authoritative() || projected.EnforcementEligible() {
		t.Fatal("reparenting elevated partial source facts")
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionDropsDependentFactsAndFlows(t *testing.T) {
	facts := enforcementTestFacts(
		enforcementTestCommand(1, 0, EffectExecute, "cat"),
		enforcementTestCommand(2, 0, EffectPreview, "curl"),
		enforcementTestCommand(3, 0, EffectExecute, "logger"),
	)
	facts.Paths = []PathFact{
		{CommandID: 1, Access: PathAccessRead, Value: "/secret"},
		{CommandID: 2, Access: PathAccessRead, Value: "/preview"},
		{Access: PathAccessRead, Value: "/unowned"},
	}
	facts.Network = []NetworkFact{
		{CommandID: 2, Action: NetworkUpload, Host: "preview.example"},
		{CommandID: 3, Action: NetworkConnect, Host: "execute.example"},
		{Action: NetworkDNS, Host: "unowned.example"},
	}
	facts.DataFlows = []DataFlowFact{
		{FromCommandID: 1, ToCommandID: 3, From: DataStdout, To: DataStdin},
		{FromCommandID: 1, ToCommandID: 2, From: DataStdout, To: DataStdin},
		{FromCommandID: 2, ToCommandID: 3, From: DataStdout, To: DataStdin},
		{FromCommandID: 1, From: DataFile, To: DataStdout},
		{ToCommandID: 3, From: DataNetwork, To: DataStdin},
		{From: DataFile, To: DataNetwork},
	}

	projected := facts.EnforcementProjection()

	if len(projected.Paths) != 1 || projected.Paths[0].CommandID != 1 {
		t.Fatalf("paths = %#v, want command 1 path only", projected.Paths)
	}
	if len(projected.Network) != 1 || projected.Network[0].CommandID != 3 {
		t.Fatalf("network = %#v, want command 3 endpoint only", projected.Network)
	}
	wantFlows := []DataFlowFact{
		{FromCommandID: 1, ToCommandID: 3, From: DataStdout, To: DataStdin},
		{FromCommandID: 1, From: DataFile, To: DataStdout},
		{ToCommandID: 3, From: DataNetwork, To: DataStdin},
	}
	if !reflect.DeepEqual(projected.DataFlows, wantFlows) {
		t.Fatalf("flows = %#v, want %#v", projected.DataFlows, wantFlows)
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionIsImmutableCopy(t *testing.T) {
	command := enforcementTestCommand(1, 0, EffectExecute, "curl")
	command.Argv = []string{"curl", "https://sink.example"}
	command.Arguments = []ArgumentFact{
		{Value: "curl"},
		{Value: "https://sink.example"},
	}
	command.Operations = []OperationKind{OperationUpload}
	command.Redirects = []RedirectFact{{
		FD:     1,
		Access: PathAccessWrite,
		Target: "/tmp/out",
	}}
	command.Wrappers = []WrapperFact{{
		Executable: "env",
		Argv:       []string{"env"},
	}}
	facts := enforcementTestFacts(command)
	facts.Parse.Issues = []IssueCode{IssueDynamicWord}
	facts.Paths = []PathFact{{
		CommandID: 1,
		Access:    PathAccessRead,
		Value:     "/secret",
	}}
	facts.Network = []NetworkFact{{
		CommandID: 1,
		Action:    NetworkUpload,
		Host:      "sink.example",
	}}
	facts.DataFlows = []DataFlowFact{{
		FromCommandID: 1,
		From:          DataFile,
		To:            DataNetwork,
	}}

	projected := facts.EnforcementProjection()
	if len(projected.Parse.Issues) != 1 ||
		len(projected.Commands) != 1 ||
		len(projected.Commands[0].Argv) == 0 ||
		len(projected.Commands[0].Arguments) == 0 ||
		len(projected.Commands[0].Operations) == 0 ||
		len(projected.Commands[0].Redirects) == 0 ||
		len(projected.Commands[0].Wrappers) == 0 ||
		len(projected.Commands[0].Wrappers[0].Argv) == 0 ||
		len(projected.Paths) != 1 ||
		len(projected.Network) != 1 ||
		len(projected.DataFlows) != 1 {
		t.Fatalf("projection is missing immutable-copy fixtures: %#v", projected)
	}
	assertFactsInvariants(t, projected)
	projected.Parse.Issues[0] = IssueInputLimit
	projected.Commands[0].Argv[0] = "changed"
	projected.Commands[0].Arguments[0].Value = "changed"
	projected.Commands[0].Operations[0] = OperationDelete
	projected.Commands[0].Redirects[0].Target = "/changed"
	projected.Commands[0].Wrappers[0].Executable = "changed"
	projected.Commands[0].Wrappers[0].Argv[0] = "changed"
	projected.Paths[0].Value = "/changed"
	projected.Network[0].Host = "changed.example"
	projected.DataFlows[0].From = DataStdin

	if facts.Parse.Issues[0] != IssueDynamicWord ||
		facts.Commands[0].Argv[0] != "curl" ||
		facts.Commands[0].Arguments[0].Value != "curl" ||
		facts.Commands[0].Operations[0] != OperationUpload ||
		facts.Commands[0].Redirects[0].Target != "/tmp/out" ||
		facts.Commands[0].Wrappers[0].Executable != "env" ||
		facts.Commands[0].Wrappers[0].Argv[0] != "env" ||
		facts.Paths[0].Value != "/secret" ||
		facts.Network[0].Host != "sink.example" ||
		facts.DataFlows[0].From != DataFile {
		t.Fatalf("mutating projection changed source facts: %#v", facts)
	}
}

func TestEnforcementProjectionDoesNotElevateNonAuthoritativeFacts(t *testing.T) {
	for _, status := range []ParseStatus{
		StatusNotApplicable,
		StatusPartial,
		StatusUnsupported,
		StatusInvalid,
		StatusLimitExceeded,
		StatusAmbiguous,
	} {
		t.Run(string(status), func(t *testing.T) {
			facts := enforcementTestFacts(
				enforcementTestCommand(1, 0, EffectExecute, "curl"),
			)
			facts.Parse.Status = status
			facts.Parse.Issues = []IssueCode{IssueUnsupportedConstruct}

			projected := facts.EnforcementProjection()

			if projected.Parse.Status != status ||
				!reflect.DeepEqual(projected.Parse.Issues, facts.Parse.Issues) {
				t.Fatalf("parse metadata changed: got %#v, want %#v",
					projected.Parse, facts.Parse)
			}
			if projected.Authoritative() {
				t.Fatalf("status %q became authoritative", status)
			}
			if projected.EnforcementEligible() {
				t.Fatalf("status %q became enforcement eligible", status)
			}
			assertFactsInvariants(t, projected)
		})
	}
}

func TestEnforcementProjectionPreservesRedirectFactLimit(t *testing.T) {
	analyze := func(count int) Facts {
		return Analyze(Input{
			Tool: "exec",
			Command: "ssh -G example.test " +
				strings.Repeat("> /tmp/preview-output ", count),
		})
	}
	assertBound := func(t *testing.T, facts Facts) {
		t.Helper()
		for _, command := range facts.Commands {
			if len(command.Redirects) > maxRedirectsPerCommand {
				t.Fatalf(
					"command %d redirects = %d, max %d",
					command.ID,
					len(command.Redirects),
					maxRedirectsPerCommand,
				)
			}
		}
	}

	bounded := analyze(maxRedirectsPerCommand)
	if !bounded.Authoritative() ||
		len(bounded.Commands) != 1 ||
		len(bounded.Commands[0].Redirects) != maxRedirectsPerCommand {
		t.Fatalf("bounded source = %#v", bounded)
	}
	projected := bounded.EnforcementProjection()
	if !projected.EnforcementEligible() ||
		len(projected.Commands) != 1 ||
		len(projected.Commands[0].Redirects) != maxRedirectsPerCommand {
		t.Fatalf("bounded projection = %#v", projected)
	}
	assertBound(t, bounded)
	assertBound(t, projected)
	assertFactsInvariants(t, projected)

	sourceTarget := bounded.Commands[0].Redirects[0].Target
	projected.Commands[0].Redirects[0].Target = "/tmp/changed"
	if bounded.Commands[0].Redirects[0].Target != sourceTarget {
		t.Fatal("projection redirect slice aliases source")
	}

	overflowed := analyze(maxRedirectsPerCommand + 1)
	if overflowed.Parse.Status != StatusLimitExceeded ||
		!containsIssue(overflowed.Parse.Issues, IssueFactLimit) ||
		overflowed.Authoritative() ||
		overflowed.EnforcementEligible() {
		t.Fatalf("overflowed source = %#v", overflowed)
	}
	overflowProjection := overflowed.EnforcementProjection()
	if overflowProjection.Parse.Status != StatusLimitExceeded ||
		!containsIssue(overflowProjection.Parse.Issues, IssueFactLimit) ||
		overflowProjection.Authoritative() ||
		overflowProjection.EnforcementEligible() {
		t.Fatalf("overflowed projection = %#v", overflowProjection)
	}
	assertBound(t, overflowed)
	assertBound(t, overflowProjection)
	assertFactsInvariants(t, overflowProjection)
}

func TestEnforcementProjectionReportsRedirectReclassificationLimit(t *testing.T) {
	if maxNetworkFacts >= maxRedirectsPerCommand {
		t.Fatalf(
			"network-limit fixture requires maxNetworkFacts (%d) < "+
				"maxRedirectsPerCommand (%d)",
			maxNetworkFacts,
			maxRedirectsPerCommand,
		)
	}
	command := enforcementTestCommand(1, 0, EffectPreview, "ssh")
	command.Redirects = make([]RedirectFact, maxNetworkFacts+1)
	for i := range command.Redirects {
		command.Redirects[i] = RedirectFact{
			FD:     1,
			Access: PathAccessWrite,
			Target: fmt.Sprintf("/dev/tcp/host-%d.example/443", i),
		}
	}
	facts := enforcementTestFacts(command)

	projected := facts.EnforcementProjection()
	if projected.Parse.Status != StatusLimitExceeded ||
		!containsIssue(projected.Parse.Issues, IssueFactLimit) ||
		projected.Authoritative() ||
		projected.EnforcementEligible() ||
		len(projected.Network) != maxNetworkFacts ||
		len(projected.Commands) != 1 ||
		len(projected.Commands[0].Redirects) != maxNetworkFacts+1 {
		t.Fatalf("projection did not retain redirect limit: %#v", projected)
	}
	assertFactsInvariants(t, projected)
}

func TestEnforcementProjectionRedirectNeverElevatesParseStatus(t *testing.T) {
	statuses := []ParseStatus{
		"",
		StatusNotApplicable,
		StatusPartial,
		StatusUnsupported,
		StatusInvalid,
		StatusLimitExceeded,
		StatusAmbiguous,
	}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			command := enforcementTestCommand(1, 0, EffectPreview, "ssh")
			command.Redirects = []RedirectFact{{
				FD:     1,
				Access: PathAccessWrite,
				Target: "/tmp/preview-output",
			}}
			facts := enforcementTestFacts(command)
			facts.Parse.Status = status

			projected := facts.EnforcementProjection()
			if projected.Parse.Status != status ||
				projected.Authoritative() ||
				projected.EnforcementEligible() {
				t.Fatalf(
					"status %q was elevated by redirect projection: %#v",
					status,
					projected,
				)
			}
			assertFactsInvariants(t, projected)
		})
	}
}

func TestEnforcementProjectionBoundsFactsAcrossPreviewCommands(t *testing.T) {
	commands := make([]CommandFact, 2)
	redirectsPerCommand := maxNetworkFacts/2 + 1
	for commandIndex := range commands {
		commands[commandIndex] = enforcementTestCommand(
			int64(commandIndex+1),
			0,
			EffectPreview,
			"ssh",
		)
		commands[commandIndex].Redirects = make(
			[]RedirectFact,
			redirectsPerCommand,
		)
		for redirectIndex := range commands[commandIndex].Redirects {
			commands[commandIndex].Redirects[redirectIndex] = RedirectFact{
				FD:     1,
				Access: PathAccessWrite,
				Target: fmt.Sprintf(
					"/dev/tcp/host-%d-%d.example/443",
					commandIndex,
					redirectIndex,
				),
			}
		}
	}

	projected := enforcementTestFacts(commands...).EnforcementProjection()
	if projected.Parse.Status != StatusLimitExceeded ||
		!containsIssue(projected.Parse.Issues, IssueFactLimit) ||
		projected.Authoritative() ||
		projected.EnforcementEligible() ||
		len(projected.Network) != maxNetworkFacts {
		t.Fatalf("aggregate projection bounds were not enforced: %#v", projected)
	}
	assertFactsInvariants(t, projected)
}

func enforcementTestFacts(commands ...CommandFact) Facts {
	return Facts{
		Tool: "exec",
		CWD:  "/workspace",
		Parse: ParseResult{
			Status:  StatusComplete,
			Dialect: DialectPOSIX,
		},
		Commands: commands,
	}
}

func enforcementTestCommand(
	id int64,
	parentID int64,
	effect CommandEffect,
	program string,
) CommandFact {
	return CommandFact{
		ID:              id,
		ParentCommandID: parentID,
		Kind:            CommandKindProcess,
		Dialect:         DialectPOSIX,
		Effect:          effect,
		Executable:      program,
		Program:         program,
		Argv:            []string{program},
		Arguments:       []ArgumentFact{{Value: program}},
		ArgvComplete:    true,
		Operations:      []OperationKind{OperationExecute},
	}
}
