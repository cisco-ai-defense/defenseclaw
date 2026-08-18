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

// ASRCommandProvenance identifies the trusted, caller-supplied source proof for
// a command-node projection. Callers must not infer provenance from argv
// contents. Unknown values are rejected.
type ASRCommandProvenance string

const (
	ASRCommandProvenanceStructuredArgv         ASRCommandProvenance = "structured_argv"
	ASRCommandProvenanceActionFactsStaticPOSIX ASRCommandProvenance = "actionfacts_static_posix"
)

// ASRPlatform is the target operating-system family understood by an ASR
// profile. This projection intentionally supports Linux only.
type ASRPlatform string

const ASRPlatformLinux ASRPlatform = "linux"

// ASRProfile identifies the ASR command profile selected by the trusted
// caller. DefenseClaw currently projects only to the canonical Linux profile.
type ASRProfile string

const ASRProfileUniversalLinux ASRProfile = "universal-linux"

// ASRProjectionContext is trusted caller context for one in-memory projection.
// It is not inferred from Facts and must not be persisted with Facts.
type ASRProjectionContext struct {
	Platform   ASRPlatform
	Profile    ASRProfile
	Provenance ASRCommandProvenance
}

// ASRCommandSurface identifies the command representation supplied to ASR.
type ASRCommandSurface string

const (
	ASRCommandSurfaceDirectArgv ASRCommandSurface = "direct_argv"
	ASRCommandSurfacePOSIX      ASRCommandSurface = "posix_shell"
)

// ASRProjectionReason is a closed, value-free explanation of a projection
// decision. Reasons must never contain command, argv, path, or parser text.
type ASRProjectionReason string

const (
	ASRProjectionReasonReady                       ASRProjectionReason = "ready"
	ASRProjectionReasonWholeActionNotAuthoritative ASRProjectionReason = "whole_action_not_authoritative"
	ASRProjectionReasonPlatformUnsupported         ASRProjectionReason = "platform_unsupported"
	ASRProjectionReasonProfileUnsupported          ASRProjectionReason = "profile_unsupported"
	ASRProjectionReasonProvenanceUnsupported       ASRProjectionReason = "provenance_unsupported"
	ASRProjectionReasonCandidateLimit              ASRProjectionReason = "candidate_limit"
	ASRProjectionReasonCommandNotProcess           ASRProjectionReason = "command_not_process"
	ASRProjectionReasonCommandNotExecuting         ASRProjectionReason = "command_not_executing"
	ASRProjectionReasonArgvIncomplete              ASRProjectionReason = "argv_incomplete"
	ASRProjectionReasonArgvEmpty                   ASRProjectionReason = "argv_empty"
	ASRProjectionReasonArgvInvalid                 ASRProjectionReason = "argv_invalid"
	ASRProjectionReasonDialectUnsupported          ASRProjectionReason = "dialect_unsupported"
	ASRProjectionReasonProvenanceDialectMismatch   ASRProjectionReason = "provenance_dialect_mismatch"
	ASRProjectionReasonCommandIdentityUntrusted    ASRProjectionReason = "command_identity_untrusted"
)

// ASRCommandProjection is an ephemeral, in-memory view of ActionFacts command
// nodes. ParseStatus and WholeActionAuthoritative always describe the complete
// source action, even when individual candidates are safe only for shadow
// evaluation.
//
// The projection deliberately excludes redirects, wrappers, operations, path
// facts, network facts, and data-flow edges. ActionFacts retains ownership of
// those semantics; command IDs provide correlation without transferring graph
// interpretation to ASR.
type ASRCommandProjection struct {
	Context                  ASRProjectionContext
	ParseStatus              ParseStatus
	WholeActionAuthoritative bool
	ContextValid             bool
	Reason                   ASRProjectionReason
	Candidates               []ASRCommandCandidate
}

// ASRCommandCandidate is one bounded command-node candidate. Argv is always a
// defensive copy of the exact static argv retained by ActionFacts.
type ASRCommandCandidate struct {
	CommandID       int64
	ParentCommandID int64
	PipelineID      int64
	Executable      string
	Program         string
	Argv            []string
	Surface         ASRCommandSurface
	CWD             string
	ActiveHome      string
	Projectable     bool
	Authoritative   bool
	Reason          ASRProjectionReason
}

const maxASRCommandCandidates = maxCommands

// ProjectASRCommandNodes creates a private command-node projection without
// serializing Facts, invoking ASR, or evaluating any command. Invalid context
// and over-limit input fail closed with no candidates.
func ProjectASRCommandNodes(
	facts Facts,
	context ASRProjectionContext,
) ASRCommandProjection {
	projection := ASRCommandProjection{
		Context:                  context,
		ParseStatus:              facts.Parse.Status,
		WholeActionAuthoritative: facts.Authoritative(),
	}
	if reason := validateASRProjectionContext(context); reason != "" {
		projection.Reason = reason
		return projection
	}
	projection.ContextValid = true
	if len(facts.Commands) > maxASRCommandCandidates {
		projection.Reason = ASRProjectionReasonCandidateLimit
		return projection
	}

	projection.Reason = ASRProjectionReasonReady
	if len(facts.Commands) == 0 {
		return projection
	}
	projection.Candidates = make([]ASRCommandCandidate, 0, len(facts.Commands))
	for _, command := range facts.Commands {
		candidate := projectASRCommandNode(
			command,
			facts.CWD,
			facts.ActiveHome,
			context.Provenance,
			projection.WholeActionAuthoritative,
		)
		projection.Candidates = append(projection.Candidates, candidate)
	}
	return projection
}

func validateASRProjectionContext(context ASRProjectionContext) ASRProjectionReason {
	if context.Platform != ASRPlatformLinux {
		return ASRProjectionReasonPlatformUnsupported
	}
	if context.Profile != ASRProfileUniversalLinux {
		return ASRProjectionReasonProfileUnsupported
	}
	switch context.Provenance {
	case ASRCommandProvenanceStructuredArgv,
		ASRCommandProvenanceActionFactsStaticPOSIX:
		return ""
	default:
		return ASRProjectionReasonProvenanceUnsupported
	}
}

func projectASRCommandNode(
	command CommandFact,
	cwd string,
	activeHome string,
	provenance ASRCommandProvenance,
	wholeActionAuthoritative bool,
) ASRCommandCandidate {
	candidate := ASRCommandCandidate{
		CommandID:       command.ID,
		ParentCommandID: command.ParentCommandID,
		PipelineID:      command.PipelineID,
		Executable:      command.Executable,
		Program:         command.Program,
		Argv:            cloneSlice(command.Argv),
		CWD:             cwd,
		ActiveHome:      activeHome,
	}

	surface, surfaceReason := asrCommandSurface(command.Dialect, provenance)
	candidate.Surface = surface
	switch {
	case command.Kind != CommandKindProcess:
		candidate.Reason = ASRProjectionReasonCommandNotProcess
	case command.Effect != EffectExecute:
		candidate.Reason = ASRProjectionReasonCommandNotExecuting
	case !command.ArgvComplete:
		candidate.Reason = ASRProjectionReasonArgvIncomplete
	case len(command.Argv) == 0:
		candidate.Reason = ASRProjectionReasonArgvEmpty
	case surfaceReason != "":
		candidate.Reason = surfaceReason
	case validateArgv(command.Argv) != "":
		candidate.Reason = ASRProjectionReasonArgvInvalid
	case !trustedASRCommandIdentity(command):
		candidate.Reason = ASRProjectionReasonCommandIdentityUntrusted
	default:
		candidate.Projectable = true
		candidate.Authoritative = wholeActionAuthoritative
		if wholeActionAuthoritative {
			candidate.Reason = ASRProjectionReasonReady
		} else {
			candidate.Reason = ASRProjectionReasonWholeActionNotAuthoritative
		}
	}
	return candidate
}

func asrCommandSurface(
	dialect Dialect,
	provenance ASRCommandProvenance,
) (ASRCommandSurface, ASRProjectionReason) {
	switch dialect {
	case DialectArgv:
		if provenance != ASRCommandProvenanceStructuredArgv {
			return "", ASRProjectionReasonProvenanceDialectMismatch
		}
		return ASRCommandSurfaceDirectArgv, ""
	case DialectPOSIX:
		// Exact wrappers originating in structured argv can produce static POSIX
		// child nodes. The node surface is POSIX while the trusted source proof
		// remains the original structured argv envelope.
		return ASRCommandSurfacePOSIX, ""
	default:
		return "", ASRProjectionReasonDialectUnsupported
	}
}

func trustedASRCommandIdentity(command CommandFact) bool {
	if command.Executable == "" || command.Program == "" ||
		len(command.Argv) == 0 || command.Argv[0] != command.Executable {
		return false
	}
	expected := commandProgramForDialect(command.Executable, command.Dialect)
	return expected != "" && command.Program == expected
}
