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

package actionfacts

import (
	"slices"
	"testing"
)

func TestASRCommandProjectionStaticPOSIX(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "exec",
		Command:     `rm -rf /tmp/cache`,
		CWD:         "/workspace",
		ActiveHome:  "/home/runner",
		DialectHint: DialectPOSIX,
	})
	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceActionFactsStaticPOSIX),
	)

	if projection.ParseStatus != StatusComplete ||
		!projection.WholeActionAuthoritative ||
		!projection.ContextValid ||
		projection.Reason != ASRProjectionReasonReady ||
		len(projection.Candidates) != 1 {
		t.Fatalf("projection = %#v", projection)
	}
	candidate := projection.Candidates[0]
	if candidate.CommandID != facts.Commands[0].ID ||
		candidate.ParentCommandID != facts.Commands[0].ParentCommandID ||
		candidate.PipelineID != facts.Commands[0].PipelineID ||
		candidate.Executable != "rm" || candidate.Program != "rm" ||
		!slices.Equal(candidate.Argv, []string{"rm", "-rf", "/tmp/cache"}) ||
		candidate.Surface != ASRCommandSurfacePOSIX ||
		candidate.CWD != facts.CWD || candidate.ActiveHome != facts.ActiveHome ||
		!candidate.Projectable || !candidate.Authoritative ||
		candidate.Reason != ASRProjectionReasonReady {
		t.Fatalf("candidate = %#v", candidate)
	}
}

func TestASRCommandProjectionStructuredArgv(t *testing.T) {
	argv := []string{"/bin/rm", "-f", "/tmp/cache"}
	facts := Analyze(Input{
		Tool:       "exec",
		Argv:       argv,
		CWD:        "/workspace",
		ActiveHome: "/home/runner",
	})
	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)

	if projection.ParseStatus != StatusComplete ||
		!projection.WholeActionAuthoritative ||
		len(projection.Candidates) != 1 {
		t.Fatalf("projection = %#v", projection)
	}
	candidate := projection.Candidates[0]
	if candidate.Executable != "/bin/rm" || candidate.Program != "rm" ||
		!slices.Equal(candidate.Argv, argv) ||
		candidate.Surface != ASRCommandSurfaceDirectArgv ||
		!candidate.Projectable || !candidate.Authoritative ||
		candidate.Reason != ASRProjectionReasonReady {
		t.Fatalf("candidate = %#v", candidate)
	}
}

func TestASRCommandProjectionPreservesWrapperAndPipelineCorrelation(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "exec",
		Command:     `sh -c 'cat /tmp/input | tee /tmp/output >/tmp/log'`,
		CWD:         "/workspace",
		ActiveHome:  "/home/runner",
		DialectHint: DialectPOSIX,
	})
	if !facts.Authoritative() || len(facts.Commands) != 3 ||
		len(facts.DataFlows) == 0 {
		t.Fatalf("facts = %#v", facts)
	}

	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceActionFactsStaticPOSIX),
	)
	if len(projection.Candidates) != len(facts.Commands) {
		t.Fatalf("projection = %#v", projection)
	}
	for index, command := range facts.Commands {
		candidate := projection.Candidates[index]
		if candidate.CommandID != command.ID ||
			candidate.ParentCommandID != command.ParentCommandID ||
			candidate.PipelineID != command.PipelineID ||
			candidate.Program != command.Program ||
			!slices.Equal(candidate.Argv, command.Argv) ||
			candidate.Surface != ASRCommandSurfacePOSIX ||
			!candidate.Projectable || !candidate.Authoritative {
			t.Fatalf("candidate[%d] = %#v, command = %#v", index, candidate, command)
		}
	}

	catCommand := asrProjectionTestCommand(t, facts.Commands, "cat")
	teeCommand := asrProjectionTestCommand(t, facts.Commands, "tee")
	if catCommand.ParentCommandID == 0 ||
		catCommand.ParentCommandID != teeCommand.ParentCommandID ||
		catCommand.PipelineID == 0 ||
		catCommand.PipelineID != teeCommand.PipelineID ||
		len(teeCommand.Redirects) == 0 {
		t.Fatalf("wrapper or pipeline relation lost in source facts: %#v", facts.Commands)
	}
	teeCandidate := asrProjectionTestCandidate(t, projection.Candidates, "tee")
	if slices.Contains(teeCandidate.Argv, "/tmp/log") {
		t.Fatalf("redirect target leaked into ASR argv: %#v", teeCandidate)
	}
}

func TestASRCommandProjectionStructuredWrapperKeepsNodeSurfaces(t *testing.T) {
	facts := Analyze(Input{
		Tool: "exec",
		Argv: []string{"sudo", "rm", "-rf", "/tmp/cache"},
	})
	if !facts.Authoritative() || len(facts.Commands) != 2 {
		t.Fatalf("facts = %#v", facts)
	}

	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)
	if len(projection.Candidates) != 2 {
		t.Fatalf("projection = %#v", projection)
	}
	sudo := asrProjectionTestCandidate(t, projection.Candidates, "sudo")
	rm := asrProjectionTestCandidate(t, projection.Candidates, "rm")
	if sudo.Surface != ASRCommandSurfaceDirectArgv ||
		rm.Surface != ASRCommandSurfacePOSIX ||
		!sudo.Projectable || !sudo.Authoritative ||
		!rm.Projectable || !rm.Authoritative ||
		rm.ParentCommandID != sudo.CommandID {
		t.Fatalf("structured wrapper projection = %#v", projection)
	}
}

func TestASRCommandProjectionRejectsDynamicAndIncompleteArgv(t *testing.T) {
	tests := []struct {
		name   string
		source string
		reason ASRProjectionReason
	}{
		{
			name:   "dynamic word",
			source: `rm -f "$TARGET"`,
			reason: ASRProjectionReasonCommandNotExecuting,
		},
		{
			name:   "prefix assignment",
			source: `MODE=cleanup rm -f /tmp/cache`,
			reason: ASRProjectionReasonArgvIncomplete,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        "exec",
				Command:     test.source,
				DialectHint: DialectPOSIX,
			})
			projection := ProjectASRCommandNodes(
				facts,
				asrProjectionLinuxContext(ASRCommandProvenanceActionFactsStaticPOSIX),
			)
			candidate := asrProjectionTestCandidate(t, projection.Candidates, "rm")
			if candidate.Projectable || candidate.Authoritative ||
				candidate.Reason != test.reason {
				t.Fatalf("candidate = %#v, facts = %#v", candidate, facts)
			}
		})
	}
}

func TestASRCommandProjectionFailsClosedForContextAndDialect(t *testing.T) {
	facts := Analyze(Input{Tool: "exec", Argv: []string{"rm", "-f", "/tmp/cache"}})
	if !facts.Authoritative() {
		t.Fatalf("facts = %#v", facts)
	}

	tests := []struct {
		name    string
		context ASRProjectionContext
		reason  ASRProjectionReason
	}{
		{
			name: "non Linux platform",
			context: ASRProjectionContext{
				Platform:   ASRPlatform("darwin"),
				Profile:    ASRProfileUniversalLinux,
				Provenance: ASRCommandProvenanceStructuredArgv,
			},
			reason: ASRProjectionReasonPlatformUnsupported,
		},
		{
			name: "unsupported profile",
			context: ASRProjectionContext{
				Platform:   ASRPlatformLinux,
				Profile:    ASRProfile("linux-experimental"),
				Provenance: ASRCommandProvenanceStructuredArgv,
			},
			reason: ASRProjectionReasonProfileUnsupported,
		},
		{
			name: "unsupported provenance",
			context: ASRProjectionContext{
				Platform:   ASRPlatformLinux,
				Profile:    ASRProfileUniversalLinux,
				Provenance: ASRCommandProvenance("inferred_from_text"),
			},
			reason: ASRProjectionReasonProvenanceUnsupported,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := ProjectASRCommandNodes(facts, test.context)
			if projection.ContextValid || projection.Reason != test.reason ||
				projection.ParseStatus != facts.Parse.Status ||
				projection.WholeActionAuthoritative != facts.Authoritative() ||
				len(projection.Candidates) != 0 {
				t.Fatalf("projection = %#v", projection)
			}
		})
	}

	unsupported := facts
	unsupported.Commands = cloneCommands(facts.Commands)
	unsupported.Commands[0].Dialect = DialectPowerShell
	projection := ProjectASRCommandNodes(
		unsupported,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)
	if len(projection.Candidates) != 1 ||
		projection.Candidates[0].Projectable ||
		projection.Candidates[0].Authoritative ||
		projection.Candidates[0].Reason != ASRProjectionReasonDialectUnsupported {
		t.Fatalf("unsupported dialect projection = %#v", projection)
	}

	mismatched := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceActionFactsStaticPOSIX),
	)
	if len(mismatched.Candidates) != 1 ||
		mismatched.Candidates[0].Projectable ||
		mismatched.Candidates[0].Reason != ASRProjectionReasonProvenanceDialectMismatch {
		t.Fatalf("provenance mismatch projection = %#v", mismatched)
	}
}

func TestASRCommandProjectionRejectsUntrustedCommandIdentity(t *testing.T) {
	facts := Analyze(Input{Tool: "exec", Argv: []string{"rm", "-f", "/tmp/cache"}})
	facts.Commands = cloneCommands(facts.Commands)
	facts.Commands[0].Program = "different-program"

	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)
	if len(projection.Candidates) != 1 ||
		projection.Candidates[0].Program != "different-program" ||
		projection.Candidates[0].Projectable ||
		projection.Candidates[0].Authoritative ||
		projection.Candidates[0].Reason != ASRProjectionReasonCommandIdentityUntrusted {
		t.Fatalf("projection = %#v", projection)
	}
}

func TestASRCommandProjectionDefensivelyCopiesArgv(t *testing.T) {
	facts := Analyze(Input{
		Tool: "exec",
		Argv: []string{"rm", "-f", "/tmp/cache"},
	})
	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)
	if len(projection.Candidates) != 1 {
		t.Fatalf("projection = %#v", projection)
	}

	projection.Candidates[0].Argv[1] = "projection-mutated"
	if facts.Commands[0].Argv[1] != "-f" {
		t.Fatalf("projection mutated source facts: %#v", facts.Commands[0].Argv)
	}
	facts.Commands[0].Argv[2] = "source-mutated"
	if projection.Candidates[0].Argv[2] != "/tmp/cache" {
		t.Fatalf("source facts mutated projection: %#v", projection.Candidates[0].Argv)
	}
}

func TestASRCommandProjectionPartialControlFlowIsShadowOnly(t *testing.T) {
	for _, source := range []string{
		`false && rm -rf /tmp/victim`,
		`true || rm -rf /tmp/victim`,
	} {
		t.Run(source, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        "exec",
				Command:     source,
				DialectHint: DialectPOSIX,
			})
			if facts.Parse.Status != StatusPartial || facts.Authoritative() {
				t.Fatalf("facts = %#v", facts)
			}
			projection := ProjectASRCommandNodes(
				facts,
				asrProjectionLinuxContext(ASRCommandProvenanceActionFactsStaticPOSIX),
			)
			if projection.ParseStatus != StatusPartial ||
				projection.WholeActionAuthoritative {
				t.Fatalf("projection = %#v", projection)
			}
			candidate := asrProjectionTestCandidate(t, projection.Candidates, "rm")
			if !candidate.Projectable || candidate.Authoritative ||
				candidate.Reason != ASRProjectionReasonWholeActionNotAuthoritative {
				t.Fatalf("candidate = %#v", candidate)
			}
		})
	}
}

func TestASRCommandProjectionCandidateLimitFailsClosed(t *testing.T) {
	commands := make([]CommandFact, maxASRCommandCandidates+1)
	for index := range commands {
		commands[index] = commandFromArgvAs(
			int64(index+1),
			[]string{"rm", "-f", "/tmp/cache"},
			DialectArgv,
		)
		commands[index].Kind = CommandKindProcess
	}
	facts := Facts{
		Parse:    ParseResult{Status: StatusComplete, Dialect: DialectArgv},
		Commands: commands,
	}
	projection := ProjectASRCommandNodes(
		facts,
		asrProjectionLinuxContext(ASRCommandProvenanceStructuredArgv),
	)
	if !projection.ContextValid || !projection.WholeActionAuthoritative ||
		projection.Reason != ASRProjectionReasonCandidateLimit ||
		len(projection.Candidates) != 0 {
		t.Fatalf("projection = %#v", projection)
	}
}

func asrProjectionLinuxContext(provenance ASRCommandProvenance) ASRProjectionContext {
	return ASRProjectionContext{
		Platform:   ASRPlatformLinux,
		Profile:    ASRProfileUniversalLinux,
		Provenance: provenance,
	}
}

func asrProjectionTestCommand(
	t *testing.T,
	commands []CommandFact,
	program string,
) CommandFact {
	t.Helper()
	for _, command := range commands {
		if command.Program == program {
			return command
		}
	}
	t.Fatalf("program %q not found in commands: %#v", program, commands)
	return CommandFact{}
}

func asrProjectionTestCandidate(
	t *testing.T,
	candidates []ASRCommandCandidate,
	program string,
) ASRCommandCandidate {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Program == program {
			return candidate
		}
	}
	t.Fatalf("program %q not found in candidates: %#v", program, candidates)
	return ASRCommandCandidate{}
}
