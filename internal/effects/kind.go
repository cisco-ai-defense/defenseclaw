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

// Package effects turns one tool call into an explicit, bounded list of the
// effects it would have (read, write, delete, link, exec, network send/fetch,
// permission change), each on a target that is either statically KNOWN or
// UNKNOWN with a closed reason code. It is a pure, deterministic, OS-agnostic
// projection: it never reads runtime.GOOS, never touches the filesystem,
// never evaluates a command, and never imports internal/actionfacts or
// internal/hookpaths. The target dialect and path flavor are inputs
// (effects.Options), so every Windows case is a table test on Linux. A
// separate resolver step (package fsres) follows links; the pure step leaves
// Target.Link = LinkNotChecked.
//
// Design: ~/dc-eh/plans/r110/streams/S7/EFFECTS.md (v2) and EFFECTS-REVIEW.md.
package effects

// Kind is the closed vocabulary of effect kinds.
type Kind string

const (
	KindRead             Kind = "read"
	KindWrite            Kind = "write"
	KindAppend           Kind = "append"
	KindDelete           Kind = "delete"
	KindLink             Kind = "link"
	KindExec             Kind = "exec"
	KindNetworkSend      Kind = "network_send"
	KindNetworkFetch     Kind = "network_fetch"
	KindPermissionChange Kind = "permission_change"
	// KindOpaque is an effect we cannot name: a construct outside the modeled
	// set. Its Target is what little we know of its scope (often none). It
	// always carries at least one structure-scoped reason.
	KindOpaque Kind = "opaque"
)

// TargetType classifies what a target refers to.
type TargetType string

const (
	TargetNone    TargetType = "none"
	TargetPath    TargetType = "path"
	TargetURL     TargetType = "url"
	TargetHost    TargetType = "host"
	TargetProcess TargetType = "process"
	// TargetRemote is a path or endpoint on another host (ssh host:path, an
	// scp/rsync remote operand, docker/kubectl exec, wsl, Invoke-Command
	// -ComputerName). It is never a local protected file (review R5).
	TargetRemote TargetType = "remote"
)

// TargetState and RoleState answer two different questions (review R1): is the
// target itself known, and is the effect kind/role on it known. An MCP
// argument names a known path but the kind is only guessed from the tool name.
type TargetState string

const (
	TargetStateKnown   TargetState = "known"
	TargetStateUnknown TargetState = "unknown"
)

type RoleState string

const (
	RoleStateKnown   RoleState = "known"
	RoleStateGuessed RoleState = "guessed"
	RoleStateUnknown RoleState = "unknown"
)

// ReasonScope says which question a reason answers.
type ReasonScope string

const (
	ScopeTarget    ReasonScope = "target"
	ScopeRole      ReasonScope = "role"
	ScopeStructure ReasonScope = "structure"
)

// ReasonCode is the closed set of reasons an effect is not fully known.
type ReasonCode string

const (
	ReasonUnparsedConstruct  ReasonCode = "unparsed_construct"
	ReasonInvalidSyntax      ReasonCode = "invalid_syntax"
	ReasonDynamicExpansion   ReasonCode = "dynamic_expansion"
	ReasonGlob               ReasonCode = "glob"
	ReasonDynamicCWD         ReasonCode = "dynamic_cwd"
	ReasonUnresolvedLink     ReasonCode = "unresolved_link"
	ReasonUnmodeledProgram   ReasonCode = "unmodeled_program"
	ReasonUnknownFlag        ReasonCode = "unknown_flag"
	ReasonOpaqueCode         ReasonCode = "opaque_code"
	ReasonOperandsFromInput  ReasonCode = "operands_from_input"
	ReasonProgramShadowed    ReasonCode = "program_shadowed"
	ReasonForeignContext     ReasonCode = "foreign_context"
	ReasonNestingLimit       ReasonCode = "nesting_limit"
	ReasonLimit              ReasonCode = "limit"
	ReasonConflictingSources ReasonCode = "conflicting_sources"
	ReasonUnknownTool        ReasonCode = "unknown_tool"
	ReasonMCPSemantics       ReasonCode = "mcp_semantics"
	ReasonParserFailure      ReasonCode = "parser_failure"
	ReasonOpaqueArchive      ReasonCode = "opaque_archive"
)

// reasonPrecedence orders reasons so a composite unknown reports the most
// structural cause first (review P2: precedence). Lower = earlier.
var reasonPrecedence = map[ReasonCode]int{
	ReasonParserFailure:      0,
	ReasonInvalidSyntax:      1,
	ReasonNestingLimit:       2,
	ReasonLimit:              3,
	ReasonUnparsedConstruct:  4,
	ReasonConflictingSources: 5,
	ReasonOpaqueCode:         6,
	ReasonProgramShadowed:    7,
	ReasonForeignContext:     8,
	ReasonOperandsFromInput:  9,
	ReasonUnmodeledProgram:   10,
	ReasonUnknownFlag:        11,
	ReasonDynamicCWD:         12,
	ReasonDynamicExpansion:   13,
	ReasonGlob:               14,
	ReasonUnresolvedLink:     15,
	ReasonMCPSemantics:       16,
	ReasonUnknownTool:        17,
	ReasonOpaqueArchive:      9,
}

// Reason is one closed reason with its scope.
type Reason struct {
	Code  ReasonCode  `json:"code"`
	Scope ReasonScope `json:"scope"`
}

// Flavor selects the path rules. It is an input, never derived from GOOS.
type Flavor string

const (
	FlavorPOSIX   Flavor = "posix"
	FlavorWindows Flavor = "windows"
)

// Dialect is the command grammar the effect's origin was parsed with.
type Dialect string

const (
	DialectNone       Dialect = "none"
	DialectPOSIX      Dialect = "posix"
	DialectPowerShell Dialect = "powershell"
	DialectCMD        Dialect = "cmd"
)

// Surface is where the effect came from.
type Surface string

const (
	SurfaceShell    Surface = "shell"
	SurfaceFileTool Surface = "file_tool"
	SurfacePatch    Surface = "patch"
	SurfaceMCP      Surface = "mcp"
	SurfaceArgv     Surface = "argv"
)

// DataKind classifies what an effect carries.
type DataKind string

const (
	DataNone       DataKind = "none"
	DataLiteral    DataKind = "literal"
	DataHeredoc    DataKind = "heredoc"
	DataHereString DataKind = "here_string"
	DataPatchText  DataKind = "patch_text"
	DataFile       DataKind = "file"
	DataStdin      DataKind = "stdin"
	DataPipe       DataKind = "pipe"
	DataArgument   DataKind = "argument"
	DataCode       DataKind = "code"
	DataCommandOut DataKind = "command_output"
)

// SourceKind classifies one producer of an effect's data (review R6).
type SourceKind string

const (
	SourceEffect   SourceKind = "effect"
	SourcePath     SourceKind = "path"
	SourceVariable SourceKind = "variable"
	SourceStdin    SourceKind = "stdin"
)

// LinkState records whether the resolver step followed links for a target.
// LinkNotChecked is deliberately distinct from "no link": a rule may never
// treat a not-checked target as clean for a protected-set match (review R7,
// EFFECTS.md section 9).
type LinkState string

const (
	LinkNotChecked LinkState = "not_checked"
	LinkNone       LinkState = "none"
	LinkFollowed   LinkState = "followed"
	LinkUnresolved LinkState = "unresolved"
)
