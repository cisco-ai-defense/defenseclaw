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

// Package actionfacts derives bounded, private semantic facts from action
// inputs. Facts are intended for in-process policy evaluation only. They are
// not an event schema and must not be serialized into audit or telemetry data.
package actionfacts

import "encoding/json"

// Input is the normalized action material available at a tool-call or
// execution-approval boundary. Callers should preserve structured argv instead
// of reconstructing a command string.
type Input struct {
	Tool    string
	Args    json.RawMessage
	Command string
	Argv    []string
	CWD     string
	// ActiveHome is trusted caller context for the identity executing the
	// action. It must be an absolute POSIX or Windows filesystem path.
	// ActionFacts never discovers it from process state.
	ActiveHome  string
	DialectHint Dialect
}

// Facts contains the statically proven subset of one action. Attacker-
// controlled parse failures are represented by Parse and never returned as
// errors.
type Facts struct {
	Tool       string
	CWD        string
	ActiveHome string
	Parse      ParseResult
	Commands   []CommandFact
	Paths      []PathFact
	Network    []NetworkFact
	DataFlows  []DataFlowFact
}

// Authoritative reports whether the entire action can be evaluated by migrated
// semantic rules. For a migrated rule, authoritative facts select CEL
// exclusively. Any non-authoritative result is diagnostic only and must select
// the legacy regex fallback; callers must never evaluate both paths for the
// same rule. Callers suppress legacy evaluation only for that migrated rule
// after CEL compilation and evaluation succeed; otherwise they run the legacy
// rule.
func (f Facts) Authoritative() bool {
	return f.Parse.Status == StatusComplete
}

// EnforcementEligible reports whether semantic matches from these facts may
// participate in a synchronous deny decision. Preview and uncertain commands
// may still support detection, but they never authorize blocking.
func (f Facts) EnforcementEligible() bool {
	if !f.Authoritative() || len(f.Commands) == 0 {
		return false
	}
	for _, command := range f.Commands {
		if command.Effect != EffectExecute {
			return false
		}
		switch command.Kind {
		case "", CommandKindProcess:
		case CommandKindShellRedirect:
			if command.Executable != "" ||
				command.Program != "" ||
				!hasStaticRedirect(command.Redirects) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ParseResult describes how much of the action could be projected safely.
type ParseResult struct {
	Status  ParseStatus
	Dialect Dialect
	Issues  []IssueCode
}

// ParseStatus is a closed set of parser outcomes.
type ParseStatus string

const (
	StatusNotApplicable ParseStatus = "not_applicable"
	StatusComplete      ParseStatus = "complete"
	StatusPartial       ParseStatus = "partial"
	StatusUnsupported   ParseStatus = "unsupported"
	StatusInvalid       ParseStatus = "invalid"
	StatusLimitExceeded ParseStatus = "limit_exceeded"
	StatusAmbiguous     ParseStatus = "ambiguous"
)

// Dialect identifies the command grammar used for the projected facts.
type Dialect string

const (
	DialectNone       Dialect = "none"
	DialectArgv       Dialect = "argv"
	DialectPOSIX      Dialect = "posix"
	DialectPowerShell Dialect = "powershell"
	DialectCMD        Dialect = "cmd"
	DialectMixed      Dialect = "mixed"
)

// IssueCode is a value-free diagnostic. It must never embed parser errors or
// input fragments.
type IssueCode string

const (
	IssueInvalidJSON           IssueCode = "invalid_json"
	IssueInvalidUTF8           IssueCode = "invalid_utf8"
	IssueInvalidSyntax         IssueCode = "invalid_syntax"
	IssueDynamicWord           IssueCode = "dynamic_word"
	IssueUnsupportedConstruct  IssueCode = "unsupported_construct"
	IssueUnknownOperandGrammar IssueCode = "unknown_operand_grammar"
	IssueConflictingSources    IssueCode = "conflicting_sources"
	IssueInputLimit            IssueCode = "input_limit"
	IssueNodeLimit             IssueCode = "node_limit"
	IssueDepthLimit            IssueCode = "depth_limit"
	IssueFactLimit             IssueCode = "fact_limit"
	IssueWrapperLimit          IssueCode = "wrapper_limit"
	IssueDuplicateJSONKey      IssueCode = "duplicate_json_key"
	IssueInternalParserFailure IssueCode = "internal_parser_failure"
)

// CommandFact is one statically identified command invocation. IDs start at 1
// and are deterministic in source order.
type CommandFact struct {
	ID              int64
	ParentCommandID int64
	PipelineID      int64
	Kind            CommandKind
	Dialect         Dialect
	Effect          CommandEffect
	Executable      string
	Program         string
	Argv            []string
	Arguments       []ArgumentFact
	ArgvComplete    bool
	Operations      []OperationKind
	Redirects       []RedirectFact
	Wrappers        []WrapperFact
}

// CommandKind distinguishes an input command from a structural shell effect.
// Shell redirects have no executable or argv and are emitted only by an
// enforcement projection of an otherwise preview-only command.
type CommandKind string

const (
	CommandKindProcess       CommandKind = "process"
	CommandKindShellRedirect CommandKind = "shell_redirect"
)

// CommandEffect distinguishes a real execution from a statically proven
// preview. Uncertain commands always make the enclosing Facts
// non-authoritative.
type CommandEffect string

const (
	EffectExecute   CommandEffect = "execute"
	EffectPreview   CommandEffect = "preview"
	EffectUncertain CommandEffect = "uncertain"
)

// ArgumentFact preserves the static value and the syntax properties needed to
// distinguish executable shell syntax from inert quoted text.
type ArgumentFact struct {
	Value   string
	Quote   QuoteKind
	Expands bool
}

type QuoteKind string

const (
	QuoteNone   QuoteKind = "none"
	QuoteSingle QuoteKind = "single"
	QuoteDouble QuoteKind = "double"
	QuoteMixed  QuoteKind = "mixed"
)

// WrapperFact records a statically resolved launcher around another command.
type WrapperFact struct {
	Executable string
	Argv       []string
}

// RedirectFact is a syntactically proven redirection on one command.
type RedirectFact struct {
	FD      int64
	Access  PathAccess
	Target  string
	Expands bool
}

// OperationKind is a deliberately small semantic vocabulary. Unknown operand
// grammars make a parse non-authoritative instead of inventing an operation.
type OperationKind string

const (
	OperationExecute          OperationKind = "execute"
	OperationRead             OperationKind = "read"
	OperationWrite            OperationKind = "write"
	OperationAppend           OperationKind = "append"
	OperationDelete           OperationKind = "delete"
	OperationCopy             OperationKind = "copy"
	OperationMove             OperationKind = "move"
	OperationList             OperationKind = "list"
	OperationSearch           OperationKind = "search"
	OperationFetch            OperationKind = "fetch"
	OperationUpload           OperationKind = "upload"
	OperationConnect          OperationKind = "connect"
	OperationListen           OperationKind = "listen"
	OperationTunnel           OperationKind = "tunnel"
	OperationNetworkScan      OperationKind = "network_scan"
	OperationDecode           OperationKind = "decode"
	OperationProcessKill      OperationKind = "process_kill"
	OperationDiskWrite        OperationKind = "disk_write"
	OperationPrivilege        OperationKind = "privilege"
	OperationPermissionChange OperationKind = "permission_change"
	OperationConfigChange     OperationKind = "config_change"
	OperationAccountChange    OperationKind = "account_change"
	OperationSchedule         OperationKind = "schedule"
	OperationContainerRun     OperationKind = "container_run"
	OperationWorkloadExec     OperationKind = "workload_exec"
	OperationNamespaceEnter   OperationKind = "namespace_enter"
	OperationRootChange       OperationKind = "root_change"
	OperationEnvironmentRead  OperationKind = "environment_read"
	OperationCredentialRead   OperationKind = "credential_read"
	OperationPolicyBypass     OperationKind = "policy_bypass"
)

// PathFact identifies a statically proven path operand.
type PathFact struct {
	CommandID  int64
	Access     PathAccess
	Flavor     PathFlavor
	Value      string
	Normalized string
	Absolute   bool
	Resolved   string
}

type PathAccess string

const (
	PathAccessRead     PathAccess = "read"
	PathAccessWrite    PathAccess = "write"
	PathAccessAppend   PathAccess = "append"
	PathAccessDelete   PathAccess = "delete"
	PathAccessExecute  PathAccess = "execute"
	PathAccessList     PathAccess = "list"
	PathAccessMetadata PathAccess = "metadata"
	PathAccessConnect  PathAccess = "connect"
)

type PathFlavor string

const (
	PathFlavorUnknown  PathFlavor = "unknown"
	PathFlavorPOSIX    PathFlavor = "posix"
	PathFlavorWindows  PathFlavor = "windows"
	PathFlavorDevice   PathFlavor = "device"
	PathFlavorRegistry PathFlavor = "registry"
)

// NetworkFact identifies a static network destination or listener.
type NetworkFact struct {
	CommandID      int64
	Action         NetworkAction
	Scheme         string
	Host           string
	Port           int64
	NormalizedHost string
	Scope          NetworkScope
	TargetKind     NetworkTargetKind
	PrefixLength   int64
}

// NetworkScope is a bounded, address-derived reachability class. Hostnames and
// targets spanning more than one class remain unknown; ActionFacts never
// performs DNS resolution.
type NetworkScope string

const (
	NetworkScopeUnknown   NetworkScope = "unknown"
	NetworkScopeLoopback  NetworkScope = "loopback"
	NetworkScopeLinkLocal NetworkScope = "link_local"
	NetworkScopePrivate   NetworkScope = "private"
	NetworkScopePublic    NetworkScope = "public"
)

// NetworkTargetKind describes the statically visible target cardinality.
type NetworkTargetKind string

const (
	NetworkTargetUnknown           NetworkTargetKind = "unknown"
	NetworkTargetSingleHost        NetworkTargetKind = "single_host"
	NetworkTargetSingleAddressCIDR NetworkTargetKind = "single_address_cidr"
	NetworkTargetMultiAddressCIDR  NetworkTargetKind = "multi_address_cidr"
	NetworkTargetRange             NetworkTargetKind = "range"
	NetworkTargetList              NetworkTargetKind = "list"
	NetworkTargetGenerated         NetworkTargetKind = "generated"
)

type NetworkAction string

const (
	NetworkConnect  NetworkAction = "connect"
	NetworkListen   NetworkAction = "listen"
	NetworkDownload NetworkAction = "download"
	NetworkUpload   NetworkAction = "upload"
	NetworkDNS      NetworkAction = "dns"
	NetworkTunnel   NetworkAction = "tunnel"
	NetworkScan     NetworkAction = "scan"
)

// DataFlowFact describes a structurally proven flow. A command ID of zero is a
// non-command endpoint such as a file or network.
type DataFlowFact struct {
	FromCommandID int64
	ToCommandID   int64
	From          DataKind
	To            DataKind
}

type DataKind string

const (
	DataStdin   DataKind = "stdin"
	DataStdout  DataKind = "stdout"
	DataFile    DataKind = "file"
	DataNetwork DataKind = "network"
	DataProcess DataKind = "process"
)
