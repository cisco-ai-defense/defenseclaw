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
	// ToolResourceIdentity is private, connector-authenticated context naming
	// the exact tool-side resource used by this invocation (for example, one
	// configured MCP database or storage server). It must never be populated
	// from tool arguments, command text, model output, or other user-controlled
	// material. ActionFacts retains only domain-separated digests derived from
	// it.
	ToolResourceIdentity string `json:"-"`
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
	// CredentialLineageHMACKey is trusted process-local key material used only
	// to project exact compromised-account and authentication inputs into opaque
	// lineage references. A zero key disables that projection. Neither the key
	// nor the input values are retained by Facts.
	CredentialLineageHMACKey [32]byte `json:"-"`
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
	// SQLSensitiveServerFileReads contains only a closed database-engine class
	// and sensitive-path class for one exact structured sql_query server-side
	// file read. SQL text, paths, connection strings, usernames, and passwords
	// are discarded before Facts crosses the ActionFacts boundary.
	SQLSensitiveServerFileReads []SQLSensitiveServerFileReadFact `json:"-"`
	// SensitiveSQLRowsetReads contains only a closed sensitive-table class and
	// a domain-separated digest of trusted connector resource identity. Query
	// text, selected values, connection strings, and raw resource identity are
	// discarded before Facts crosses the ActionFacts boundary.
	SensitiveSQLRowsetReads []SensitiveSQLRowsetReadFact `json:"-"`
	// SQLDirectExternalEgresses records only that one authenticated db.query
	// call selects a reviewed credential/secret field and directs the result to
	// one literal external HTTP(S) destination. SQL, field and table names,
	// URLs, and trusted resource identities are discarded before Facts crosses
	// the ActionFacts boundary.
	SQLDirectExternalEgresses []SQLDirectExternalEgressFact `json:"-"`
	// StructuredLiteralPersistences contains only a closed sink class and a
	// domain-separated digest binding trusted connector resource identity to an
	// exact literal sink target. Content, observations, target names, paths, and
	// raw connector identity are not retained in this private projection.
	StructuredLiteralPersistences []StructuredLiteralPersistenceFact `json:"-"`
	// SQLCommandUDFOperations contains only a closed create/invoke operation,
	// a database-engine class, and domain-separated SHA-256 identity digests.
	// SQL, function bodies, command arguments, connection strings, usernames,
	// and passwords are discarded before Facts crosses the ActionFacts
	// boundary. The projection exists only to support a bounded same-function,
	// same-connection chain after a successful create result.
	SQLCommandUDFOperations []SQLCommandUDFOperationFact `json:"-"`
	// SQLMutations contains only exact destructive mutation classes and
	// domain-separated SHA-256 identity digests. SQL text, connection strings,
	// usernames, passwords, and raw database/object names are discarded before
	// Facts crosses the ActionFacts boundary. These facts are detection evidence;
	// enforcement requires an explicit protective policy.
	SQLMutations []SQLMutationFact `json:"-"`
	// HTTPSQLInjections contains only closed SQL-injection technique classes
	// derived from one exact structured HTTP request. URLs, bodies, headers,
	// parameter names, SQL text, and destinations are discarded before Facts
	// crosses the ActionFacts boundary. These facts are alert-only evidence.
	HTTPSQLInjections []HTTPSQLInjectionFact `json:"-"`
	// HTTPCommandInjections records only that one closed structured HTTP
	// request scalar contains exact literal shell control syntax invoking a
	// reviewed harmless proof command. Request values, parameter names, paths,
	// methods, commands, and control operators are discarded. This private fact
	// is alert-only evidence.
	HTTPCommandInjections []HTTPCommandInjectionFact `json:"-"`
	// SQLClientShellEscapes contains only direct, exact SQL client meta-command
	// escapes to a reviewed POSIX shell. Query text, database identities,
	// connection arguments, and shell arguments are discarded. CommandID binds
	// the closed client class to the authoritative process command used by CEL.
	SQLClientShellEscapes []SQLClientShellEscapeFact `json:"-"`
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
	// KubernetesPodRuns contains only a closed pod-run operation class and a
	// domain-separated digest of the exact namespace/name identity. Images,
	// commands, override documents, and raw identities are discarded before
	// Facts crosses the ActionFacts boundary.
	KubernetesPodRuns []KubernetesPodRunFact `json:"-"`
	// KubernetesCronJobReverseShells contains only a domain-separated digest of
	// one literal namespace/CronJob identity after a closed `kubectl create
	// cronjob` grammar proves a single static reverse-shell command. Images,
	// schedules, commands, endpoints, ports, and raw identities are discarded.
	KubernetesCronJobReverseShells []KubernetesCronJobReverseShellFact `json:"-"`
	// KubernetesSensitiveAccesses contains only a closed resource and scope
	// class for exact kubectl requests. Tokens, selectors, contexts,
	// namespaces, output formats, and other argument values are discarded.
	KubernetesSensitiveAccesses []KubernetesSensitiveAccessFact `json:"-"`
	// StructuredPortForwards contains a closed forward class, bounded ports,
	// and an opaque destination identity. Raw target hosts are discarded.
	StructuredPortForwards []StructuredPortForwardFact `json:"-"`
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
	// CloudResourceMutations contains only closed cloud mutation classes,
	// bounded scope, and domain-separated resource/object identity digests.
	// Cloud identifiers, endpoints, profiles, credentials, and command text are
	// discarded. Observed provider-audit facts are detection evidence only.
	CloudResourceMutations []CloudResourceMutationFact `json:"-"`
	// AWSBulkEC2Terminations contains only a value-free proof that one trusted
	// structured EC2 call will terminate a bounded set of at least ten distinct
	// canonical literal instance IDs. Account, region, and instance identities
	// are discarded before Facts crosses the ActionFacts boundary.
	AWSBulkEC2Terminations []AWSBulkEC2TerminationFact `json:"-"`
	// CloudAuditSecurityOperations contains only closed, successful AWS
	// CloudTrail operation classes derived from the aws.cloudtrail_event schema.
	// Request bodies, principals, account IDs, resource names, and event metadata
	// are discarded. These post-action observations are detection evidence only
	// and are never copied into the enforcement projection.
	CloudAuditSecurityOperations []CloudAuditSecurityOperationFact `json:"-"`
	// EndpointSecurityControlMutations contains only completed, exact Windows
	// security-control mutation classes from the windows.event schema. Registry
	// paths, excluded values, hosts, users, and process identities are discarded.
	EndpointSecurityControlMutations []EndpointSecurityControlMutationFact `json:"-"`
	// WindowsSecurityControlMutations contains only direct, unconditional,
	// statically parsed Windows Defender or audit-policy mutations from a
	// closed command grammar. Raw exclusions, paths, category names, and GUIDs
	// are discarded after classification. These facts are detection evidence
	// only and never grant enforcement authority by themselves.
	WindowsSecurityControlMutations []WindowsSecurityControlMutationFact `json:"-"`
	// CredentialRemoteExecutionOperations contains only a closed operation class
	// and a domain-separated digest of one exact target/principal tuple. Method,
	// command, domain, and password values are discarded before Facts crosses the
	// ActionFacts boundary.
	CredentialRemoteExecutionOperations []CredentialRemoteExecutionOperationFact `json:"-"`
	// CompromisedCredentialAuthentications contains only a closed operation role
	// and process-keyed HMAC references for one exact account and credential.
	// Usernames, domains, passwords, hashes, and command text are discarded
	// before Facts crosses the ActionFacts boundary.
	CompromisedCredentialAuthentications []CompromisedCredentialAuthenticationFact `json:"-"`
	// DirectoryCredentialAcquisitions contains only exact, completed command
	// grammars that request or recover reusable Active Directory credential
	// material. Targets, principals, hashes, passwords, paths, and wordlists are
	// discarded. The projection is intentionally distinct from generic
	// credential reads so policy can assign a posture to dual-use security tools.
	DirectoryCredentialAcquisitions []DirectoryCredentialAcquisitionFact `json:"-"`
	// KerberosS4USecretsDumps contains only the one-way cache and target
	// identities from an exact KRB5CCNAME-bound, Kerberos-only secretsdump
	// invocation. Raw cache names, targets, principals, and command text are
	// discarded before Facts crosses the ActionFacts boundary.
	KerberosS4USecretsDumps []KerberosS4USecretsDumpFact `json:"-"`
	// StagedPayloadPersistenceOperations contains only a closed operation class
	// and a domain-separated SHA-256 digest of one exact normalized absolute
	// POSIX path. Script bytes, persistence payloads, methods, and raw paths are
	// discarded before Facts crosses the ActionFacts boundary. An accepted
	// reverse-shell write is a payload_write; any other valid closed-schema write
	// is a same-path payload_mutation barrier.
	StagedPayloadPersistenceOperations []StagedPayloadPersistenceOperationFact `json:"-"`
	// CloudMetadataCredentialReads contains only a closed cloud-provider class
	// for an exact structured metadata-token request. Metadata paths, query
	// parameters, resource audiences, role names, and returned credentials are
	// discarded before Facts crosses the ActionFacts boundary.
	CloudMetadataCredentialReads []CloudMetadataCredentialReadFact `json:"-"`
	// StructuredCredentialReads retains only a closed credential-store class
	// from the exact credential_extract(source) schema. Extracted values and
	// tool output are never present in ActionFacts.
	StructuredCredentialReads []StructuredCredentialReadFact `json:"-"`
	// LiteralSensitiveUploads records only that a complete, literal JSON body
	// contains a reviewed credential-bearing field. Body values, field names,
	// request headers, and destinations are discarded; policy must separately
	// prove that the same command uploads to an external destination.
	LiteralSensitiveUploads []LiteralSensitiveUploadFact `json:"-"`
	// CredentialFileUploads records only a closed credential-file class and the
	// command that performs an exact file-backed curl upload. Source paths,
	// destinations, and file contents are discarded; policy must separately
	// prove that the same command targets an external destination.
	CredentialFileUploads []CredentialFileUploadFact `json:"-"`
	// SourceArchiveUploads records an exact repository archive stream that is
	// optionally encoded and sent to one static external upload command. Raw
	// source bytes, repository names, revisions, and destinations are omitted.
	SourceArchiveUploads []SourceArchiveUploadFact `json:"-"`
	// PowerShellTCPCommandLoops records a closed PowerShell TCP read, command
	// evaluation, and response-write loop to one static non-local endpoint.
	// Script text, endpoint, port, variables, and output are omitted.
	PowerShellTCPCommandLoops []PowerShellTCPCommandLoopFact `json:"-"`
	// MaliciousPersistencePayloads records an exact closed persistence schema
	// whose payload performs a literal network download and execution. Method,
	// script text, URLs, paths, and arguments are omitted.
	MaliciousPersistencePayloads []MaliciousPersistencePayloadFact `json:"-"`
	// CustomRootSUIDImplants records a closed same-action proof that literal C
	// source containing an effective root-UID transition is compiled to one
	// exact executable, made root-owned, and assigned a setuid executable mode.
	// Source text and paths are discarded after the identity joins complete.
	CustomRootSUIDImplants []CustomRootSUIDImplantFact `json:"-"`
	// POSIXSystemInterpreterWrappers records a value-free same-action proof that
	// a versioned /usr/bin Python interpreter is backed up to the matching
	// `.real` path and replaced atomically by a literal environment-injecting
	// wrapper which delegates to that exact backup. Wrapper bytes and paths are
	// discarded after the identity joins complete.
	POSIXSystemInterpreterWrappers []POSIXSystemInterpreterWrapperFact `json:"-"`
	// PKRootSetuidShells records a value-free proof of one closed shell input
	// that invokes a literal temporary pkroot/run executable with an exactly
	// quoted payload creating /tmp/.pksh as a 4755 copy of /bin/bash.
	PKRootSetuidShells []PKRootSetuidShellFact `json:"-"`
	// ResourceReads contains value-free identities for exact structured resource
	// reads. Raw resource identifiers and returned content are discarded before
	// Facts crosses the ActionFacts boundary. These facts prove lineage only;
	// they do not classify a read as malicious.
	ResourceReads []ResourceReadFact `json:"-"`
	// ArtifactTransfers contains value-free identities for exact structured
	// transfers. Raw artifact identifiers, recipients, subjects, bodies, and
	// attachment metadata are discarded before Facts crosses the ActionFacts
	// boundary. These facts prove lineage only and require policy context before
	// they can support enforcement.
	ArtifactTransfers []ArtifactTransferFact `json:"-"`
	// ResourceMutations contains value-free identities for exact structured
	// resource mutations. Raw resource identifiers, content, destination
	// principals, and provider permission values are discarded before Facts
	// crosses the ActionFacts boundary. These facts describe capability and
	// lineage only; they do not classify a mutation as malicious.
	ResourceMutations []ResourceMutationFact `json:"-"`
	// POSIXNonRootUIDZeroAccountWrites contains only a value-free proof of one
	// exact structured /etc/passwd replacement containing a complete non-root
	// UID-0 record. Raw passwd content never crosses this boundary.
	POSIXNonRootUIDZeroAccountWrites []POSIXNonRootUIDZeroAccountWriteFact `json:"-"`
	// POSIXUnrestrictedSudoersGrantWrites contains only a value-free proof that
	// one closed structured write replaces /etc/sudoers (or one direct child of
	// /etc/sudoers.d) with a literal unrestricted NOPASSWD grant. Raw content
	// and principal names never cross the ActionFacts boundary.
	POSIXUnrestrictedSudoersGrantWrites []POSIXUnrestrictedSudoersGrantWriteFact `json:"-"`
	Artifacts                           []ArtifactFact
}

// CloudMetadataCredentialReadFact retains only the provider family proven by
// a closed cloud_metadata(provider,path) schema and an exact credential-token
// endpoint grammar.
type CloudMetadataCredentialReadFact struct {
	Provider string
}

// StructuredCredentialReadFact is a value-free capability fact. Source is
// restricted to the reviewed closed vocabulary accepted by the tool schema.
type StructuredCredentialReadFact struct {
	Source string
}

// LiteralSensitiveUploadFact is a value-free projection of one exact curl
// request body. Class belongs to a closed vocabulary and CommandID binds it to
// the parser-owned network facts for the same process.
type LiteralSensitiveUploadFact struct {
	CommandID int64
	Class     string
}

// CredentialFileUploadFact is a value-free projection of one exact curl file
// source. Class belongs to a closed vocabulary; CommandID binds the proof to
// parser-owned network facts without retaining the path or destination.
type CredentialFileUploadFact struct {
	CommandID int64
	Class     string
}

// SourceArchiveUploadFact is a value-free bounded pipeline proof.
type SourceArchiveUploadFact struct {
	SourceCommandID int64
	UploadCommandID int64
	Base64Encoded   bool
}

// PowerShellTCPCommandLoopFact is a value-free capability proof. Its empty
// shape is intentional: existence alone records the closed grammar.
type PowerShellTCPCommandLoopFact struct{}

// MaliciousPersistencePayloadFact retains only a reviewed operation class.
type MaliciousPersistencePayloadFact struct {
	Class string
}

// CustomRootSUIDImplantFact is deliberately value-free. Existence proves all
// four stages of the closed same-action grammar and their exact path joins.
type CustomRootSUIDImplantFact struct{}

// PKRootSetuidShellFact is deliberately value-free. Existence proves the
// complete fixed nested-command grammar accepted by ExactPKRootSetuidShell.
type PKRootSetuidShellFact struct{}

// ResourceReadFact retains only a closed resource class and an opaque digest
// of one exact resource identity.
type ResourceReadFact struct {
	ResourceKind           string
	ResourceIdentityDigest string
	Exact                  bool
}

// ArtifactTransferFact retains only a closed transfer mechanism and opaque
// identities for the exact artifacts and destination principals. Each slice
// is sorted and deduplicated so equivalent structured calls project equally.
type ArtifactTransferFact struct {
	Mechanism                           string
	ArtifactIdentityDigests             []string
	DestinationPrincipalIdentityDigests []string
	Exact                               bool
}

// ResourceMutationOperation is the closed structured-resource mutation
// vocabulary. These operation classes are dual-use and carry no disposition.
type ResourceMutationOperation string

const (
	ResourceMutationAppend ResourceMutationOperation = "append"
	ResourceMutationShare  ResourceMutationOperation = "share"
	ResourceMutationDelete ResourceMutationOperation = "delete"
)

// ResourceMutationPermission is a normalized semantic permission class. It
// deliberately differs from provider wire values so raw permissions do not
// cross the ActionFacts boundary.
type ResourceMutationPermission string

const (
	ResourceMutationPermissionRead      ResourceMutationPermission = "read"
	ResourceMutationPermissionReadWrite ResourceMutationPermission = "read_write"
)

// ResourceMutationFact retains only one closed operation, an opaque resource
// identity, and optional opaque destination/normalized permission evidence for
// an exact share. Raw IDs, content, principals, and permissions are omitted.
type ResourceMutationFact struct {
	Operation                          ResourceMutationOperation
	ResourceKind                       string
	ResourceIdentityDigest             string
	DestinationPrincipalIdentityDigest string
	Permission                         ResourceMutationPermission
	Exact                              bool
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

// SQLSensitiveServerFileReadFact deliberately carries no SQL, path, or
// connection value. Both fields use closed, non-sensitive vocabularies.
type SQLSensitiveServerFileReadFact struct {
	DatabaseEngine string
	PathClass      string
}

// SensitiveSQLTableClass is the closed set of rowsets whose reviewed fields
// may participate in a future exact value-lineage proof.
type SensitiveSQLTableClass string

const (
	SensitiveSQLTableCredentials SensitiveSQLTableClass = "credentials"
	SensitiveSQLTableOAuthTokens SensitiveSQLTableClass = "oauth_tokens"
	SensitiveSQLTableEmployees   SensitiveSQLTableClass = "employees"
)

// SensitiveSQLRowsetReadFact contains no SQL, database name, table name,
// connection material, or row value. Identity fields are lowercase,
// domain-separated SHA-256 digests. TableClass is a closed parser vocabulary
// retained for result classification; joins use only the opaque digests.
type SensitiveSQLRowsetReadFact struct {
	TableClass             SensitiveSQLTableClass
	DatabaseIdentityDigest string
	TableIdentityDigest    string
	Exact                  bool
}

// SQLDirectExternalEgressFact is a value-free proof that one closed db.query
// action binds a high-confidence SQL credential source directly to an
// external HTTP(S) result sink.
type SQLDirectExternalEgressFact struct {
	Exact bool
}

// StructuredLiteralPersistenceSink is the closed set of literal persistence
// schemas that a future value-lineage proof may resolve after success.
type StructuredLiteralPersistenceSink string

const (
	StructuredLiteralPersistenceFile   StructuredLiteralPersistenceSink = "file"
	StructuredLiteralPersistenceEntity StructuredLiteralPersistenceSink = "knowledge_graph_entity"
)

// StructuredLiteralPersistenceFact contains no path, entity name, type,
// observation, content, or connector identity. TargetIdentityDigest binds the
// exact target to trusted connector context without retaining either value.
type StructuredLiteralPersistenceFact struct {
	SinkClass            StructuredLiteralPersistenceSink
	TargetIdentityDigest string
	Exact                bool
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

// KubernetesPodRunFact describes one exact, non-dry-run `kubectl run` that
// requests a privileged container. PodIdentityDigest is value-free and can be
// used by bounded follow-on proofs without retaining namespace or pod names.
type KubernetesPodRunFact struct {
	PodIdentityDigest string
	Privileged        bool
	HostPID           bool
	HostNetwork       bool
}

// KubernetesCronJobReverseShellFact describes one exact, non-dry-run
// `kubectl create cronjob` whose sole container command is a proved static
// reverse shell. CronJobIdentityDigest is value-free detection evidence.
type KubernetesCronJobReverseShellFact struct {
	CronJobIdentityDigest string
}

// KubernetesSensitiveAccessFact is a value-free projection of an exact
// sensitive Kubernetes read. The closed vocabulary admits cluster-wide
// Secret enumeration and exact in-pod workload identity token reads.
type KubernetesSensitiveAccessFact struct {
	Resource      string
	AllNamespaces bool
	TokenProvided bool
}

// StructuredPortForwardFact is a value-minimized capability fact for a closed
// port_forward tool schema. It is intentionally not malicious on its own.
type StructuredPortForwardFact struct {
	Kind                 string
	ListenPort           uint16
	TargetPort           uint16
	TargetIdentityDigest string
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
	CloudIAMUserCreate         CloudIAMPrincipalOperation = "aws_user_create"
	CloudIAMRoleCreate         CloudIAMPrincipalOperation = "aws_role_create"
	CloudIAMUserAdminAttach    CloudIAMPrincipalOperation = "aws_user_admin_attach"
	CloudIAMRoleAdminAttach    CloudIAMPrincipalOperation = "aws_role_admin_attach"
	CloudIAMUserWildcardPolicy CloudIAMPrincipalOperation = "aws_user_wildcard_inline_policy"
	CloudIAMRoleWildcardPolicy CloudIAMPrincipalOperation = "aws_role_wildcard_inline_policy"
)

// CloudIAMPrincipalOperationFact deliberately carries no cloud argument.
// PrincipalIdentityDigest binds the provider, principal kind, and exact
// static name without retaining that name in chain state.
type CloudIAMPrincipalOperationFact struct {
	Operation               CloudIAMPrincipalOperation
	PrincipalIdentityDigest string
}

// CloudResourceMutationOperation is the closed cloud-data mutation vocabulary.
type CloudResourceMutationOperation string

const (
	CloudResourceDeleteObject     CloudResourceMutationOperation = "delete_object"
	CloudResourceDeletePrefix     CloudResourceMutationOperation = "delete_prefix"
	CloudResourceDeleteBucket     CloudResourceMutationOperation = "delete_bucket"
	CloudResourceDeleteDisk       CloudResourceMutationOperation = "delete_disk"
	CloudResourceDeleteIAMBinding CloudResourceMutationOperation = "delete_iam_binding"
)

// CloudResourceMutationFact is a value-free projection of one exact cloud
// deletion. ResourceIdentityDigest identifies the containing resource (for
// example an Azure scope or GCP bucket), while ObjectIdentityDigest identifies
// the exact deleted binding, disk, object, prefix, or bucket. Observed facts
// originate from successful provider audit events and never enter the generic
// synchronous enforcement projection.
type CloudResourceMutationFact struct {
	Provider               string
	Service                string
	Operation              CloudResourceMutationOperation
	Scope                  string
	ResourceIdentityDigest string
	ObjectIdentityDigest   string
	Recursive              bool
	Observed               bool
	Exact                  bool
}

// CloudAuditSecurityOperation is the closed vocabulary of independently
// security-relevant, successful cloud-audit operations.
type CloudAuditSecurityOperation string

const (
	CloudAuditTelemetryDisable      CloudAuditSecurityOperation = "telemetry_disable"
	CloudAuditExternalSnapshotShare CloudAuditSecurityOperation = "external_snapshot_share"
	CloudAuditWorldwideSSHExposure  CloudAuditSecurityOperation = "worldwide_ssh_exposure"
	CloudAuditAdministratorAttach   CloudAuditSecurityOperation = "administrator_policy_attach"
)

// CloudAuditSecurityOperationFact deliberately retains no cloud-controlled
// values. Exact is required so malformed or extended schemas fail closed.
type CloudAuditSecurityOperationFact struct {
	Provider  string
	Operation CloudAuditSecurityOperation
	Exact     bool
}

type EndpointSecurityControlMutation string

const (
	EndpointDefenderExclusionRequested      EndpointSecurityControlMutation = "defender_exclusion_requested"
	EndpointDefenderExclusionAdded          EndpointSecurityControlMutation = "defender_exclusion_added"
	EndpointDefenderLoggingDisableRequested EndpointSecurityControlMutation = "defender_logging_disable_requested"
	EndpointDefenderLoggingDisabled         EndpointSecurityControlMutation = "defender_logging_disabled"
)

// EndpointSecurityControlMutationFact is post-action detection evidence only.
type EndpointSecurityControlMutationFact struct {
	Platform              string
	Operation             EndpointSecurityControlMutation
	ProcessIdentityDigest string
	Exact                 bool
}

// WindowsSecurityControlMutation is the closed vocabulary for exact command-
// line security-control changes that are useful as high-confidence telemetry
// but remain legitimate in some administrative workflows.
type WindowsSecurityControlMutation string

const (
	WindowsDefenderExecutableExtensionExclusion WindowsSecurityControlMutation = "defender_executable_extension_exclusion"
	WindowsDefenderDriveRootExclusion           WindowsSecurityControlMutation = "defender_drive_root_exclusion"
	WindowsAuditDetailedTrackingFailureDisable  WindowsSecurityControlMutation = "audit_detailed_tracking_failure_disable"
	WindowsAuditProcessCreationSuccessDisable   WindowsSecurityControlMutation = "audit_process_creation_success_disable"
	WindowsAuditFullPrivilegeDisable            WindowsSecurityControlMutation = "audit_full_privilege_disable"
)

// WindowsSecurityControlMutationFact deliberately retains only the command
// identity and closed mutation class. Exact is required so extended or
// malformed command grammars cannot become policy evidence.
type WindowsSecurityControlMutationFact struct {
	CommandID int64
	Operation WindowsSecurityControlMutation
	Exact     bool
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

// DirectoryCredentialAcquisition is the closed vocabulary for exact Active
// Directory credential-acquisition and offline Kerberos cracking operations.
type DirectoryCredentialAcquisition string

const (
	DirectoryCredentialSecretsDump DirectoryCredentialAcquisition = "directory_secrets_dump"
	DirectoryCredentialKerberoast  DirectoryCredentialAcquisition = "kerberoast_request"
	DirectoryCredentialASREPRoast  DirectoryCredentialAcquisition = "asrep_roast_request"
	DirectoryCredentialHashCrack   DirectoryCredentialAcquisition = "kerberos_hash_crack"
)

// DirectoryCredentialAcquisitionFact contains no attacker-controlled values.
// CommandID binds the fact to the exact authoritative CommandFact exposed to
// CEL; Operation is restricted to DirectoryCredentialAcquisition constants.
type DirectoryCredentialAcquisitionFact struct {
	CommandID int64
	Operation DirectoryCredentialAcquisition
}

// SQLMutationOperation is the closed destructive SQL operation vocabulary.
type SQLMutationOperation string

const (
	SQLMutationDeleteUnbounded SQLMutationOperation = "delete_unbounded"
	SQLMutationTruncate        SQLMutationOperation = "truncate"
	SQLMutationDropTable       SQLMutationOperation = "drop_table"
	SQLMutationDropSchema      SQLMutationOperation = "drop_schema"
	SQLMutationDropDatabase    SQLMutationOperation = "drop_database"
)

// SQLMutationScope is the exact resource scope affected by a SQL mutation.
type SQLMutationScope string

const (
	SQLMutationScopeTable    SQLMutationScope = "table"
	SQLMutationScopeSchema   SQLMutationScope = "schema"
	SQLMutationScopeDatabase SQLMutationScope = "database"
)

// SQLMutationQuerySource records which closed input grammar supplied the SQL.
type SQLMutationQuerySource string

const (
	SQLMutationQueryArgv         SQLMutationQuerySource = "argv"
	SQLMutationQueryLiteralStdin SQLMutationQuerySource = "literal_stdin"
	SQLMutationQueryStructured   SQLMutationQuerySource = "structured"
)

// SQLMutationFact contains no raw SQL or resource identity. Identity digests
// are lowercase, domain-separated SHA-256 values. Exact is always true for a
// projected fact and makes accidental future widening fail closed at owners.
type SQLMutationFact struct {
	Engine                   string
	Operation                SQLMutationOperation
	Scope                    SQLMutationScope
	QuerySource              SQLMutationQuerySource
	ConnectionIdentityDigest string
	DatabaseIdentityDigest   string
	ObjectIdentityDigest     string
	Exact                    bool
}

// HTTPSQLInjectionTechnique is the closed vocabulary for exact executable
// SQL-injection grammar embedded in one structured HTTP request value.
type HTTPSQLInjectionTechnique string

const (
	HTTPSQLInjectionQuotedBooleanTautology HTTPSQLInjectionTechnique = "quoted_boolean_tautology"
	HTTPSQLInjectionUnionSelect            HTTPSQLInjectionTechnique = "union_select"
	HTTPSQLInjectionXPCmdShell             HTTPSQLInjectionTechnique = "xp_cmdshell"
	HTTPSQLInjectionIntoOutfile            HTTPSQLInjectionTechnique = "into_outfile"
)

// HTTPSQLInjectionFact deliberately retains only a reviewed technique class.
type HTTPSQLInjectionFact struct {
	Technique HTTPSQLInjectionTechnique
}

// HTTPCommandInjectionFact is deliberately value-free. Existence proves the
// complete closed request and literal proof-command grammar.
type HTTPCommandInjectionFact struct{}

// SQLClientShellEscapeClient is the closed SQL client vocabulary for literal
// local-shell meta-commands. It deliberately does not model arbitrary SQL or
// arbitrary client extensions.
type SQLClientShellEscapeClient string

const (
	SQLClientShellEscapeSQLite SQLClientShellEscapeClient = "sqlite"
	SQLClientShellEscapeMySQL  SQLClientShellEscapeClient = "mysql"
)

// SQLClientShellEscapeFact is a value-free proof that one authoritative,
// unconditional top-level SQL client invocation contains exactly one literal
// shell escape to /bin/sh or /bin/bash.
type SQLClientShellEscapeFact struct {
	CommandID int64
	Client    SQLClientShellEscapeClient
	Exact     bool
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
	if !f.Authoritative() {
		return false
	}
	if len(f.Commands) == 0 {
		// Closed structured sql_query inputs intentionally do not mint generic
		// command facts. An exact destructive mutation may still be enforced by
		// an explicitly enabled protective policy; standard owners remain
		// alert-only. Validate every private fact before granting eligibility.
		validSQLMutation := len(f.SQLMutations) != 0 &&
			len(ExactSQLMutations(f)) == len(f.SQLMutations)
		validDirectEgress := len(f.SQLDirectExternalEgresses) == 1 &&
			ExactSQLDirectExternalEgress(f)
		validAWSBulkTermination := len(f.AWSBulkEC2Terminations) == 1
		return validSQLMutation || validDirectEgress || validAWSBulkTermination
	}
	for _, command := range f.Commands {
		if command.Effect != EffectExecute || command.ControlFlowUncertain {
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
	DialectPython     Dialect = "python"
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
	// ControlFlowOperator retains only the closed short-circuit operator class
	// surrounding this command. It never contains source text or arbitrary AST
	// material and is deliberately excluded from serialization. Existing users
	// should continue to use ControlFlowUncertain unless a bounded proof must
	// distinguish an AND attempt from OR or mixed/unsupported control flow.
	ControlFlowOperator CommandControlFlowOperator `json:"-"`
	// Background distinguishes one statically present asynchronous POSIX
	// statement from conditional or otherwise unresolved control flow. It is
	// value-free and private to exact code-owned proofs.
	Background   bool `json:"-"`
	Kind         CommandKind
	Dialect      Dialect
	Effect       CommandEffect
	Executable   string
	Program      string
	Argv         []string
	Arguments    []ArgumentFact
	ArgvComplete bool
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

// CommandControlFlowOperator is a private, value-free summary of the POSIX
// control-flow ancestors surrounding one projected command. MixedOrUnsupported
// deliberately collapses combinations and non-short-circuit control flow so a
// reviewed proof can fail closed without retaining arbitrary parser structure.
type CommandControlFlowOperator string

const (
	ControlFlowOperatorNone               CommandControlFlowOperator = ""
	ControlFlowOperatorAnd                CommandControlFlowOperator = "and"
	ControlFlowOperatorOr                 CommandControlFlowOperator = "or"
	ControlFlowOperatorMixedOrUnsupported CommandControlFlowOperator = "mixed_or_unsupported"
)

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
