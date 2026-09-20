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

package semantic

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func TestProjectCopiesValidFacts(t *testing.T) {
	source := validActionFacts()
	first, code := Project(source)
	if code != ProjectionOK {
		t.Fatalf("Project() code = %q", code)
	}
	second, code := Project(source)
	if code != ProjectionOK {
		t.Fatalf("second Project() code = %q", code)
	}
	if first == second ||
		first.Commands[0] == second.Commands[0] ||
		&first.Commands[0].Argv[0] == &second.Commands[0].Argv[0] {
		t.Fatal("projections share mutable storage")
	}

	source.Commands[0].Argv[0] = "changed"
	source.Commands[0].Arguments[0].Value = "changed"
	source.Commands[0].Operations[0] = actionfacts.OperationDelete
	source.Paths[0].Value = "changed"
	source.Parse.Issues[0] = actionfacts.IssueInvalidSyntax
	if first.Commands[0].Argv[0] != "cat" ||
		first.Commands[0].Arguments[0].Value != "cat" ||
		first.Commands[0].Operations[0] !=
			semanticpb.OperationKind_OPERATION_KIND_READ ||
		first.Commands[0].Operations[1] !=
			semanticpb.OperationKind_OPERATION_KIND_POLICY_BYPASS ||
		first.Paths[0].Value != "/etc/passwd" ||
		first.Parse.Issues[0] !=
			semanticpb.IssueCode_ISSUE_CODE_UNKNOWN_OPERAND_GRAMMAR {
		t.Fatal("projection changed after source mutation")
	}

	first.Commands[0].Argv[0] = "projected"
	if source.Commands[0].Argv[0] != "changed" ||
		second.Commands[0].Argv[0] != "cat" {
		t.Fatal("projection mutation escaped its message")
	}
}

func TestProjectRejectsUnsafeSource(t *testing.T) {
	tests := []struct {
		name string
		want ProjectionCode
		edit func(*actionfacts.Facts)
	}{
		{
			name: "count",
			want: ProjectionCountLimit,
			edit: func(f *actionfacts.Facts) {
				f.Paths = make([]actionfacts.PathFact, maxPaths+1)
			},
		},
		{
			name: "scalar",
			want: ProjectionScalarLimit,
			edit: func(f *actionfacts.Facts) {
				f.Tool = strings.Repeat("x", maxScalarBytes+1)
			},
		},
		{
			name: "enum",
			want: ProjectionInvalidEnum,
			edit: func(f *actionfacts.Facts) {
				f.Network[0].Action = ""
			},
		},
		{
			name: "duplicate operation",
			want: ProjectionInvalidCommand,
			edit: func(f *actionfacts.Facts) {
				f.Commands[0].Operations =
					[]actionfacts.OperationKind{
						actionfacts.OperationRead,
						actionfacts.OperationRead,
					}
			},
		},
		{
			name: "parent cycle",
			want: ProjectionInvalidCommand,
			edit: func(f *actionfacts.Facts) {
				f.Commands[0].ParentCommandID = 2
				child := validProcess(2, 1, "echo")
				f.Commands = append(f.Commands, child)
			},
		},
		{
			name: "dangling path",
			want: ProjectionInvalidReference,
			edit: func(f *actionfacts.Facts) {
				f.Paths[0].CommandID = 99
			},
		},
		{
			name: "noncanonical path",
			want: ProjectionInvalidReference,
			edit: func(f *actionfacts.Facts) {
				f.Paths[0].Resolved = "/etc/../tmp"
			},
		},
		{
			name: "noncanonical device",
			want: ProjectionInvalidReference,
			edit: func(f *actionfacts.Facts) {
				f.Paths[0].Flavor = actionfacts.PathFlavorDevice
				f.Paths[0].Resolved = `//./../PhysicalDrive0`
			},
		},
		{
			name: "noncanonical registry",
			want: ProjectionInvalidReference,
			edit: func(f *actionfacts.Facts) {
				f.Paths[0].Flavor = actionfacts.PathFlavorRegistry
				f.Paths[0].Resolved = `HKLM\Software`
			},
		},
		{
			name: "network port",
			want: ProjectionInvalidNetwork,
			edit: func(f *actionfacts.Facts) {
				f.Network[0].Port = 65536
			},
		},
		{
			name: "empty flow",
			want: ProjectionInvalidDataFlow,
			edit: func(f *actionfacts.Facts) {
				f.DataFlows[0].FromCommandID = 0
				f.DataFlows[0].ToCommandID = 0
			},
		},
		{
			name: "malformed shell redirect",
			want: ProjectionInvalidCommand,
			edit: func(f *actionfacts.Facts) {
				f.Commands[0].Kind = actionfacts.CommandKindShellRedirect
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validActionFacts()
			test.edit(&facts)
			projected, code := Project(facts)
			if code != test.want || projected != nil {
				t.Fatalf("Project() = (%v, %q), want (nil, %q)",
					projected, code, test.want)
			}
		})
	}

	facts := validActionFacts()
	facts.Tool = strings.Repeat("x", maxScalarBytes)
	if projected, code := Project(facts); code != ProjectionOK || projected == nil {
		t.Fatalf("exact scalar boundary = (%v, %q)", projected, code)
	}
}

func TestProjectAcceptsRedirectOnlyEnforcementFact(t *testing.T) {
	facts := validActionFacts()
	facts.Commands[0].Effect = actionfacts.EffectPreview
	facts.Commands[0].Redirects = []actionfacts.RedirectFact{{
		FD:     1,
		Access: actionfacts.PathAccessWrite,
		Target: "/tmp/out",
	}}
	enforcement := facts.EnforcementProjection()
	projected, code := Project(enforcement)
	if code != ProjectionOK {
		t.Fatalf("Project(enforcement) code = %q", code)
	}
	if len(projected.Commands) != 1 ||
		projected.Commands[0].Kind !=
			semanticpb.CommandKind_COMMAND_KIND_SHELL_REDIRECT ||
		projected.Commands[0].Executable != "" ||
		!projected.Commands[0].ArgvComplete {
		t.Fatalf("redirect projection = %#v", projected.Commands)
	}
}

func validActionFacts() actionfacts.Facts {
	return actionfacts.Facts{
		Tool:       "exec",
		CWD:        "/tmp",
		ActiveHome: "/home/test",
		Parse: actionfacts.ParseResult{
			Status:  actionfacts.StatusComplete,
			Dialect: actionfacts.DialectPOSIX,
			Issues: []actionfacts.IssueCode{
				actionfacts.IssueUnknownOperandGrammar,
			},
		},
		Commands: []actionfacts.CommandFact{
			validProcess(1, 0, "cat"),
		},
		Paths: []actionfacts.PathFact{{
			CommandID:  1,
			Access:     actionfacts.PathAccessRead,
			Flavor:     actionfacts.PathFlavorPOSIX,
			Value:      "/etc/passwd",
			Normalized: "/etc/passwd",
			Absolute:   true,
			Resolved:   "/etc/passwd",
		}},
		Network: []actionfacts.NetworkFact{{
			CommandID:      1,
			Action:         actionfacts.NetworkConnect,
			Scheme:         "https",
			Host:           "example.com",
			Port:           443,
			NormalizedHost: "example.com",
			Scope:          actionfacts.NetworkScopePublic,
			TargetKind:     actionfacts.NetworkTargetSingleHost,
		}},
		DataFlows: []actionfacts.DataFlowFact{{
			FromCommandID: 1,
			From:          actionfacts.DataFile,
			To:            actionfacts.DataNetwork,
		}},
	}
}

func validProcess(
	id int64,
	parent int64,
	program string,
) actionfacts.CommandFact {
	return actionfacts.CommandFact{
		ID:              id,
		ParentCommandID: parent,
		PipelineID:      1,
		Kind:            actionfacts.CommandKindProcess,
		Dialect:         actionfacts.DialectPOSIX,
		Effect:          actionfacts.EffectExecute,
		Executable:      "/usr/bin/" + program,
		Program:         program,
		Argv:            []string{program, "/etc/passwd"},
		Arguments: []actionfacts.ArgumentFact{
			{Value: program, Quote: actionfacts.QuoteNone},
			{Value: "/etc/passwd", Quote: actionfacts.QuoteNone},
		},
		ArgvComplete: true,
		Operations: []actionfacts.OperationKind{
			actionfacts.OperationRead,
			actionfacts.OperationPolicyBypass,
		},
	}
}
