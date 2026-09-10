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
	ActiveHome string
	// ActiveAgentFiles is trusted connector context containing the exact files
	// whose instructions are active for this action. Entries must be absolute
	// filesystem paths. ActionFacts validates, canonicalizes, bounds, and copies
	// the list; it never discovers active files from argv, CWD, or process state.
	ActiveAgentFiles []string
	// ActiveAgentFilesCaseInsensitive is private, trusted connector metadata
	// captured when an active POSIX file is loaded. Each entry must also occur
	// in ActiveAgentFiles. It is carried only in process so later policy checks
	// can honor native case-insensitive filename lookup without filesystem I/O.
	ActiveAgentFilesCaseInsensitive []string `json:"-"`
	// ActiveAgentFilesCaseInsensitiveUncertain is private trusted connector
	// state proving that at least one active POSIX file omitted by bounded cache
	// loss had case-insensitive filename lookup. It may be true only when
	// ActiveAgentFilesUncertain is true and is never derived from action input.
	ActiveAgentFilesCaseInsensitiveUncertain bool `json:"-"`
	// ActiveAgentFilesUncertain is trusted connector state indicating that the
	// exact list above may be incomplete because its bounded authority cache
	// evicted or overflowed an entry, or because an authenticated load named a
	// recognized instruction path whose native identity could not be proved.
	// Parsers never derive it from action input.
	ActiveAgentFilesUncertain bool
	DialectHint               Dialect
	// CurlCapabilities is trusted caller context for resolved curl executables.
	// ActionFacts never discovers capabilities from GOOS, dialect, basename,
	// PATH, or process state. Callers must authenticate and invalidate this
	// evidence before supplying it.
	CurlCapabilities []CurlCapability `json:"-"`
}

// Facts contains the statically proven subset of one action. Attacker-
// controlled parse failures are represented by Parse and never returned as
// errors.
type Facts struct {
	Tool                                     string
	CWD                                      string
	ActiveHome                               string
	ActiveAgentFiles                         []string
	ActiveAgentFilesCaseInsensitive          []string `json:"-"`
	ActiveAgentFilesCaseInsensitiveUncertain bool     `json:"-"`
	ActiveAgentFilesUncertain                bool
	Parse                                    ParseResult
	Commands                                 []CommandFact
	Paths                                    []PathFact
	Network                                  []NetworkFact
	DataFlows                                []DataFlowFact
	// SensitiveEgressArtifactWrites contains only exact local artifact paths.
	// An entry proves that a closed structured-write schema created source text
	// containing both a protected credential/secret path and a non-local literal
	// network endpoint. The source text and endpoint are deliberately discarded.
	// This private, in-process projection exists only for bounded chain joins.
	SensitiveEgressArtifactWrites []PathFact `json:"-"`
	// StructuredTextReplacements contains only closed-schema, literal
	// text-editor replacements. Old and new content are discarded after
	// deriving bounded value-free deltas. The projection currently retains the
	// exact target path and literal IPv4 addresses present in the replacement
	// but absent from the replaced text so bounded chains can prove identity
	// continuity without persisting file content.
	StructuredTextReplacements []StructuredTextReplacementFact `json:"-"`
	// SQLServerCommandExecutions contains only a value-free operation class and
	// an opaque SHA-256 digest of one exact structured sql_query connection
	// identity. Query text, command payloads, connection strings, usernames, and
	// passwords are discarded before Facts crosses the ActionFacts boundary.
	SQLServerCommandExecutions []SQLServerCommandExecutionFact `json:"-"`
	// PostgreSQLCopyPrograms contains only an opaque digest of the exact
	// PostgreSQL connection/database identity for a closed-schema sql_query
	// action that uses COPY ... PROGRAM. SQL text, program text, connection
	// strings, usernames, and passwords are discarded before Facts crosses the
	// ActionFacts boundary.
	PostgreSQLCopyPrograms []PostgreSQLCopyProgramFact `json:"-"`
	// SQLCommandUDFOperations contains only a closed create/invoke operation,
	// a database-engine class, and domain-separated SHA-256 identity digests.
	// SQL, function bodies, command arguments, connection strings, usernames,
	// and passwords are discarded before Facts crosses the ActionFacts
	// boundary. The projection exists only to support a bounded same-function,
	// same-connection chain after a successful create result.
	SQLCommandUDFOperations []SQLCommandUDFOperationFact `json:"-"`
	// PrivilegedKubernetesOperations contains only closed operation classes and
	// domain-separated SHA-256 identity digests. Manifest bytes, kubectl
	// payloads, paths, namespaces, and pod names are discarded before Facts
	// crosses the ActionFacts boundary.
	PrivilegedKubernetesOperations []PrivilegedKubernetesOperationFact `json:"-"`
	// KubernetesCronJobOperations contains only closed privileged-CronJob
	// mutation/job-creation classes and a domain-separated digest of the exact
	// namespace/name identity. Patch bytes, resource names, namespaces, and job
	// names are discarded before Facts crosses the ActionFacts boundary.
	KubernetesCronJobOperations []KubernetesCronJobOperationFact `json:"-"`
	// WirelessCaptureDeauthOperations contains only a closed operation class and
	// a domain-separated SHA-256 digest of one exact static BSSID. Packet filter,
	// output path, interface, client, and deauthentication arguments are
	// discarded before Facts crosses the ActionFacts boundary.
	WirelessCaptureDeauthOperations []WirelessCaptureDeauthOperationFact `json:"-"`
	// CloudIAMPrincipalOperations contains only a closed AWS IAM operation
	// class and a domain-separated digest of one exact user or role name. The
	// provider command, trust policy, policy ARN, and principal name are
	// discarded before Facts crosses the ActionFacts boundary.
	CloudIAMPrincipalOperations []CloudIAMPrincipalOperationFact `json:"-"`
	// CredentialRemoteExecutionOperations contains only a closed operation class
	// and a domain-separated digest of one exact target/principal tuple. Method,
	// command, domain, and password values are discarded before Facts crosses the
	// ActionFacts boundary.
	CredentialRemoteExecutionOperations []CredentialRemoteExecutionOperationFact `json:"-"`
	// StagedPayloadPersistenceOperations contains only a closed operation class
	// and a domain-separated SHA-256 digest of one exact normalized absolute
	// POSIX path. Script bytes, persistence payloads, methods, and raw paths are
	// discarded before Facts crosses the ActionFacts boundary. An accepted
	// reverse-shell write is a payload_write; any other valid closed-schema write
	// is a same-path payload_mutation barrier.
	StagedPayloadPersistenceOperations []StagedPayloadPersistenceOperationFact `json:"-"`
	Artifacts                          []ArtifactFact
}

// StructuredTextReplacementFact is a private, in-process projection of one
// direct literal replacement. It is intentionally not an event or audit
// schema. AddedIPv4 contains canonical single-address IPv4 literals only.
type StructuredTextReplacementFact struct {
	Path      PathFact
	AddedIPv4 []string
}

// SQLServerCommandOperation is the closed set needed by the bounded
// xp_cmdshell proof. Disable is retained only as an exact lineage barrier.
type SQLServerCommandOperation string

const (
	SQLServerXPCommandShellEnable  SQLServerCommandOperation = "xp_cmdshell_enable"
	SQLServerXPCommandShellInvoke  SQLServerCommandOperation = "xp_cmdshell_invoke"
	SQLServerXPCommandShellDisable SQLServerCommandOperation = "xp_cmdshell_disable"
)

// SQLServerCommandExecutionFact deliberately carries no SQL or connection
// value. ConnectionIdentityDigest is a lowercase SHA-256 digest over a
// domain-separated, length-framed exact connection identity.
type SQLServerCommandExecutionFact struct {
	Operation                SQLServerCommandOperation
	ConnectionIdentityDigest string
}

// PostgreSQLCopyProgramFact deliberately carries no SQL or command value.
// ConnectionIdentityDigest is a lowercase SHA-256 digest over a
// domain-separated, length-framed exact PostgreSQL connection identity.
type PostgreSQLCopyProgramFact struct {
	ConnectionIdentityDigest string
}

// SQLCommandUDFOperation is the closed vocabulary for a command-executing
// SQL UDF create followed by invocation of that exact UDF.
type SQLCommandUDFOperation string

const (
	SQLCommandUDFCreate  SQLCommandUDFOperation = "command_udf_create"
	SQLCommandUDFInvoke  SQLCommandUDFOperation = "command_udf_invoke"
	SQLCommandUDFBarrier SQLCommandUDFOperation = "command_udf_barrier"
)

// SQLCommandUDFOperationFact deliberately carries no SQL, command, function,
// or connection value. DatabaseEngine is a closed non-sensitive class;
// digests are lowercase SHA-256 over domain-separated, length-framed exact
// identities.
type SQLCommandUDFOperationFact struct {
	Operation                SQLCommandUDFOperation
	DatabaseEngine           string
	ConnectionIdentityDigest string
	FunctionIdentityDigest   string
}

// PrivilegedKubernetesOperation is the closed vocabulary used by the bounded
// privileged-pod host-root proof.
type PrivilegedKubernetesOperation string

const (
	KubernetesPrivilegedManifestWrite PrivilegedKubernetesOperation = "privileged_manifest_write"
	KubernetesManifestApply           PrivilegedKubernetesOperation = "manifest_apply"
	KubernetesPodHostPathExec         PrivilegedKubernetesOperation = "pod_host_path_exec"
)

// PrivilegedKubernetesOperationFact deliberately contains no source material.
// ArtifactIdentityDigest identifies one exact normalized manifest path;
// PodIdentityDigest identifies one exact namespace/name pair.
type PrivilegedKubernetesOperationFact struct {
	Operation              PrivilegedKubernetesOperation
	ArtifactIdentityDigest string
	PodIdentityDigest      string
}

// KubernetesCronJobOperation is the closed vocabulary for the bounded
// privileged-CronJob mutation then same-CronJob job-creation proof.
type KubernetesCronJobOperation string

const (
	KubernetesCronJobPrivilegedPatch KubernetesCronJobOperation = "privileged_cronjob_patch"
	KubernetesCronJobCreateFrom      KubernetesCronJobOperation = "create_job_from_cronjob"
	KubernetesCronJobPatchBarrier    KubernetesCronJobOperation = "cronjob_patch_barrier"
)

// KubernetesCronJobOperationFact deliberately contains no source material.
// CronJobIdentityDigest identifies one exact canonical namespace/name pair.
// HostRoot is true only when the same literal patch both declares hostPath `/`
// and mounts that volume into a container made privileged by that patch.
type KubernetesCronJobOperationFact struct {
	Operation             KubernetesCronJobOperation
	CronJobIdentityDigest string
	HostRoot              bool
}

// WirelessCaptureDeauthOperation is the closed vocabulary used by the bounded
// targeted-capture then deauthentication proof.
type WirelessCaptureDeauthOperation string

const (
	WirelessTargetedPacketCapture WirelessCaptureDeauthOperation = "targeted_packet_capture"
	WirelessDeauthentication      WirelessCaptureDeauthOperation = "deauthentication"
)

// WirelessCaptureDeauthOperationFact deliberately contains no tool argument.
// BSSIDIdentityDigest is a lowercase SHA-256 digest over a normalized BSSID.
type WirelessCaptureDeauthOperationFact struct {
	Operation           WirelessCaptureDeauthOperation
	BSSIDIdentityDigest string
}

// CloudIAMPrincipalOperation is the closed vocabulary needed by the bounded
// principal-create then administrator-attachment proof.
type CloudIAMPrincipalOperation string

const (
	CloudIAMUserCreate      CloudIAMPrincipalOperation = "aws_user_create"
	CloudIAMRoleCreate      CloudIAMPrincipalOperation = "aws_role_create"
	CloudIAMUserAdminAttach CloudIAMPrincipalOperation = "aws_user_admin_attach"
	CloudIAMRoleAdminAttach CloudIAMPrincipalOperation = "aws_role_admin_attach"
)

// CloudIAMPrincipalOperationFact deliberately carries no cloud argument.
// PrincipalIdentityDigest binds the provider, principal kind, and exact
// static name without retaining that name in chain state.
type CloudIAMPrincipalOperationFact struct {
	Operation               CloudIAMPrincipalOperation
	PrincipalIdentityDigest string
}

// CredentialRemoteExecutionOperation is the closed vocabulary used by the
// bounded credential-extraction then remote-execution proof.
type CredentialRemoteExecutionOperation string

const (
	CredentialExtractionSecretsdump CredentialRemoteExecutionOperation = "credential_extraction"
	CredentialRemoteExecutionPsExec CredentialRemoteExecutionOperation = "remote_execution"
)

// CredentialRemoteExecutionOperationFact deliberately contains no tool
// argument. TargetPrincipalIdentityDigest is a lowercase SHA-256 digest over
// one normalized static target and Windows principal tuple.
type CredentialRemoteExecutionOperationFact struct {
	Operation                     CredentialRemoteExecutionOperation
	TargetPrincipalIdentityDigest string
}

// StagedPayloadPersistenceOperation is the closed vocabulary for an exact
// malicious payload write followed by installation of that same path as a
// persistence target.
type StagedPayloadPersistenceOperation string

const (
	StagedPayloadWrite       StagedPayloadPersistenceOperation = "payload_write"
	StagedPayloadMutation    StagedPayloadPersistenceOperation = "payload_mutation"
	StagedPersistenceInstall StagedPayloadPersistenceOperation = "persistence_install"
)

// StagedPayloadPersistenceOperationFact deliberately contains no source
// material. PathIdentityDigest is a lowercase SHA-256 digest over one exact,
// normalized absolute POSIX path.
type StagedPayloadPersistenceOperationFact struct {
	Operation          StagedPayloadPersistenceOperation
	PathIdentityDigest string
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
	IssueOpaqueArtifact        IssueCode = "opaque_artifact"
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
	// ControlFlowUncertain is true when this command is nested in control flow
	// whose execution cannot be proven from the static action. It lets bounded
	// subgraph proofs reject conditional commands without discarding unrelated,
	// unconditional commands from the same otherwise-partial shell action.
	ControlFlowUncertain bool
	Kind                 CommandKind
	Dialect              Dialect
	Effect               CommandEffect
	Executable           string
	Program              string
	Argv                 []string
	Arguments            []ArgumentFact
	ArgvComplete         bool
	// LiteralStdin is retained only for one bounded, single-quoted POSIX
	// heredoc whose bytes cannot undergo shell expansion. It is private
	// in-process evidence and is intentionally not part of the public semantic
	// projection.
	LiteralStdin          string
	LiteralStdinComplete  bool
	LiteralStdinAmbiguous bool
	Operations            []OperationKind
	Redirects             []RedirectFact
	Wrappers              []WrapperFact
	curlCapability        *CurlCapability `json:"-"`
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
	Value string
	// StaticGlob retains only a syntactically static, unquoted POSIX glob. It is
	// empty for parameter expansion, command substitution, quoted literals, or
	// mixed dynamic words. Generic argv remains incomplete for glob expansion;
	// reviewed bounded proofs may use this field without inventing expansion
	// results.
	StaticGlob string
	Quote      QuoteKind
	Expands    bool
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
