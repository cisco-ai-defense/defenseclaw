// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestMergeDropsFactsForCommandsRejectedByLimit(t *testing.T) {
	base := newParseOutput(DialectPOSIX, 1)
	for range maxCommands - 1 {
		base.appendCommand(CommandFact{ID: base.nextCommandID(), Executable: "true"})
	}

	other := newParseOutput(DialectPOSIX, base.nextID)
	acceptedID := other.nextCommandID()
	rejectedID := other.nextCommandID()
	other.appendCommand(CommandFact{ID: acceptedID, Executable: "cat"})
	other.appendCommand(CommandFact{ID: rejectedID, Executable: "curl"})
	other.appendPath(PathFact{CommandID: rejectedID, Access: PathAccessRead, Value: "/secret"})
	other.appendNetwork(NetworkFact{CommandID: rejectedID, Action: NetworkUpload, Host: "sink.example"})
	other.appendDataFlow(DataFlowFact{
		FromCommandID: acceptedID,
		ToCommandID:   rejectedID,
		From:          DataStdout,
		To:            DataStdin,
	})

	base.merge(other)
	if base.status != StatusLimitExceeded || len(base.commands) != maxCommands {
		t.Fatalf("merge result = %#v", base)
	}
	if len(base.paths) != 0 || len(base.network) != 0 || len(base.dataFlows) != 0 {
		t.Fatalf("dangling facts survived command limit: paths=%#v network=%#v flows=%#v",
			base.paths, base.network, base.dataFlows)
	}
}

func TestMergeRejectsCommandIDCollisionsAtomically(t *testing.T) {
	base := newParseOutput(DialectPOSIX, 1)
	baseID := base.nextCommandID()
	base.appendCommand(CommandFact{ID: baseID, Executable: "true"})
	base.appendPath(PathFact{
		CommandID: baseID,
		Access:    PathAccessRead,
		Value:     "/retained",
	})
	baseNextID := base.nextID

	other := newParseOutput(DialectPowerShell, baseID)
	collidingID := other.nextCommandID()
	newID := other.nextCommandID()
	other.appendCommand(CommandFact{ID: collidingID, Executable: "Get-Content"})
	other.appendCommand(CommandFact{ID: newID, Executable: "Invoke-WebRequest"})
	other.appendPath(PathFact{
		CommandID: collidingID,
		Access:    PathAccessRead,
		Value:     `C:\must-not-retarget.txt`,
	})
	other.appendNetwork(NetworkFact{
		CommandID: newID,
		Action:    NetworkDownload,
		Host:      "must-not-merge.example",
	})
	other.appendDataFlow(DataFlowFact{
		FromCommandID: collidingID,
		ToCommandID:   newID,
		From:          DataStdout,
		To:            DataStdin,
	})

	base.merge(other)

	if base.status != StatusAmbiguous ||
		!containsIssue(base.issues, IssueConflictingSources) ||
		base.dialect != DialectPOSIX ||
		base.nextID != baseNextID ||
		len(base.commands) != 1 ||
		base.commands[0].ID != baseID ||
		len(base.paths) != 1 ||
		base.paths[0].Value != "/retained" ||
		len(base.network) != 0 ||
		len(base.dataFlows) != 0 {
		t.Fatalf("colliding merge was not rejected atomically: %#v", base)
	}
}

func TestMarkPartialPromotesUnsupportedOutputWithFacts(t *testing.T) {
	out := newParseOutput(DialectPowerShell, 1)
	out.markUnsupported(IssueUnsupportedConstruct)
	out.appendCommand(CommandFact{
		ID:         out.nextCommandID(),
		Dialect:    DialectPowerShell,
		Effect:     EffectExecute,
		Executable: "remove-item",
		Program:    "remove-item",
	})
	out.markPartial(IssueUnknownOperandGrammar)

	if out.status != StatusPartial ||
		!containsIssue(out.issues, IssueUnsupportedConstruct) ||
		!containsIssue(out.issues, IssueUnknownOperandGrammar) {
		t.Fatalf("output = %#v", out)
	}
}
