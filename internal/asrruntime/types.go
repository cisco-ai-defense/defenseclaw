package asrruntime

import "encoding/json"

// Status is the bounded outcome of evaluating one normalized command.
type Status string

const (
	StatusComplete    Status = "COMPLETE"
	StatusPartial     Status = "PARTIAL"
	StatusInvalid     Status = "INVALID"
	StatusUnsupported Status = "UNSUPPORTED"
	StatusError       Status = "ERROR"
)

// Surface identifies how argv was established. The runtime never reparses shell
// source; posix_shell means a trusted frontend supplied the normalized argv.
type Surface string

const (
	SurfaceDirectArgv Surface = "direct_argv"
	SurfacePOSIXShell Surface = "posix_shell"
)

// Resolution describes how a word was resolved by the trusted shell frontend.
type Resolution string

const (
	ResolutionExact           Resolution = "EXACT"
	ResolutionContextual      Resolution = "CONTEXTUAL"
	ResolutionAnchoredPattern Resolution = "ANCHORED_PATTERN"
	ResolutionGenerated       Resolution = "GENERATED"
	ResolutionUnknown         Resolution = "UNKNOWN"
)

// Expansion is a bounded expansion class reported by the trusted frontend.
type Expansion string

const (
	ExpansionVariable            Expansion = "VARIABLE"
	ExpansionTilde               Expansion = "TILDE"
	ExpansionGlob                Expansion = "GLOB"
	ExpansionCommandSubstitution Expansion = "COMMAND_SUBSTITUTION"
)

// InvocationContext contains only resolution context. Evaluate does not read
// these paths or otherwise consult the host filesystem.
type InvocationContext struct {
	CWD            string   `json:"cwd,omitempty"`
	WorkspaceRoots []string `json:"workspace_roots,omitempty"`
	ActiveHome     string   `json:"active_home,omitempty"`
	TemporaryRoots []string `json:"temporary_roots,omitempty"`
}

// WordFact carries parser-proven information for one argv word.
type WordFact struct {
	Value           string      `json:"value"`
	RawValue        string      `json:"raw_value"`
	NormalizedValue *string     `json:"normalized_value"`
	ResolvedValue   *string     `json:"resolved_value"`
	Resolution      Resolution  `json:"resolution"`
	Expansions      []Expansion `json:"expansions"`
}

// NormalizedInvocation is the command-local input accepted by ASR. It contains
// no shell source and is never executed by this package.
type NormalizedInvocation struct {
	CallID       string             `json:"call_id,omitempty"`
	Program      string             `json:"program,omitempty"`
	Surface      Surface            `json:"surface"`
	Profile      string             `json:"profile,omitempty"`
	Argv         []string           `json:"argv"`
	ArgvComplete bool               `json:"argv_complete"`
	Context      *InvocationContext `json:"context,omitempty"`
	WordFacts    []WordFact         `json:"word_facts,omitempty"`
}

// Pins are the exact identities verified while loading a snapshot bundle.
type Pins struct {
	SchemaVersion          string
	CatalogVersion         string
	CatalogDigest          string
	EvaluatorABI           string
	SemanticContractDigest string
	ConformanceDigest      string
}

// Result is one command-local evaluation. Semantics is the language-neutral
// ActionSemantics projection produced by the native evaluator. Runtime always
// owns Authoritative; evaluator implementations cannot set it directly.
type Result struct {
	CallID        string
	Status        Status
	Issues        []string
	Semantics     json.RawMessage
	Pins          Pins
	Authoritative bool
}

// Evaluator is the narrow native implementation boundary. Implementations must
// be deterministic, bounded, and pure: no filesystem, network, process, or
// ambient-environment access is permitted during Evaluate.
type Evaluator interface {
	Evaluate(NormalizedInvocation) Result
}

// Bundle contains a release snapshot and its independently pinned contract and
// conformance artifacts. LoadVerified never retains or mutates these slices.
type Bundle struct {
	Snapshot         []byte
	Manifest         []byte
	Conformance      []byte
	SemanticContract []byte
}
