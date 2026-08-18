package asrruntime

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxArgvItems       = 256
	maxTokenBytes      = 65_536
	maxProgramBytes    = 4_096
	maxCallIDBytes     = 256
	maxContextRoots    = 64
	maxWordFacts       = 256
	maxEvaluationIssue = 64
	maxSemanticsBytes  = 1 << 20
)

// Runtime owns a verified immutable snapshot and its native evaluator.
type Runtime struct {
	pins             Pins
	evaluator        Evaluator
	conformance      ConformanceReport
	authorityEnabled bool
}

// Pins returns the immutable identities bound to this runtime.
func (r *Runtime) Pins() Pins {
	if r == nil {
		return Pins{}
	}
	return r.pins
}

// Conformance returns the startup parity check. The returned slices are copies.
func (r *Runtime) Conformance() ConformanceReport {
	if r == nil {
		return ConformanceReport{}
	}
	report := r.conformance
	report.Mismatches = append([]string(nil), report.Mismatches...)
	return report
}

// CanAuthorize reports whether exact pins, an upstream parity attestation, and
// the embedded conformance vectors all agree. The bootstrap artifact returns
// false by construction.
func (r *Runtime) CanAuthorize() bool {
	return r != nil && r.authorityEnabled
}

// Evaluate validates and evaluates one command without shell reparsing or host
// I/O. All panics and invalid evaluator results fail closed as ERROR.
func (r *Runtime) Evaluate(invocation NormalizedInvocation) (result Result) {
	callID := safeCallID(invocation.CallID)
	if r == nil || r.evaluator == nil {
		return Result{CallID: callID, Status: StatusError, Issues: []string{"runtime_unavailable"}}
	}
	result.CallID = callID
	result.Pins = r.pins
	defer func() {
		if recovered := recover(); recovered != nil {
			result = Result{
				CallID: callID,
				Status: StatusError,
				Issues: []string{"evaluator_failure"},
				Pins:   r.pins,
			}
		}
	}()

	if issues := validateInvocation(invocation); len(issues) != 0 {
		return Result{CallID: callID, Status: StatusInvalid, Issues: issues, Pins: r.pins}
	}

	result = r.evaluator.Evaluate(invocation)
	result.CallID = callID
	result.Pins = r.pins
	result.Authoritative = false
	result.Issues = normalizeIssues(result.Issues)
	if !validStatus(result.Status) {
		return Result{
			CallID: callID,
			Status: StatusError,
			Issues: []string{"invalid_evaluator_status"},
			Pins:   r.pins,
		}
	}
	if result.Status == StatusComplete || result.Status == StatusPartial ||
		result.Status == StatusInvalid && len(result.Semantics) != 0 {
		if !validSemantics(result.Semantics) {
			return Result{
				CallID: callID,
				Status: StatusError,
				Issues: []string{"invalid_evaluator_semantics"},
				Pins:   r.pins,
			}
		}
		result.Semantics = append([]byte(nil), result.Semantics...)
	} else {
		result.Semantics = nil
	}
	if !invocation.ArgvComplete && result.Status == StatusComplete {
		result.Status = StatusPartial
		result.Issues = normalizeIssues(append(result.Issues, "argv_incomplete"))
	}
	result.Authoritative = r.authorityEnabled &&
		invocation.ArgvComplete && result.Status == StatusComplete
	return result
}

func validStatus(status Status) bool {
	switch status {
	case StatusComplete, StatusPartial, StatusInvalid, StatusUnsupported, StatusError:
		return true
	default:
		return false
	}
}

func normalizeIssues(issues []string) []string {
	if len(issues) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(issues))
	normalized := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue == "" || len(issue) > 256 || !utf8.ValidString(issue) {
			continue
		}
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		normalized = append(normalized, issue)
		if len(normalized) == maxEvaluationIssue {
			break
		}
	}
	sort.Strings(normalized)
	return normalized
}

func validateInvocation(invocation NormalizedInvocation) []string {
	issues := make([]string, 0, 8)
	add := func(issue string) {
		for _, existing := range issues {
			if existing == issue {
				return
			}
		}
		issues = append(issues, issue)
	}

	if invocation.CallID != "" && !boundedUTF8(invocation.CallID, maxCallIDBytes) {
		add("invalid_call_id")
	}
	if invocation.Surface != SurfaceDirectArgv && invocation.Surface != SurfacePOSIXShell {
		add("invalid_surface")
	}
	if invocation.Profile != "" && invocation.Profile != "universal-linux" {
		add("invalid_profile")
	}
	if len(invocation.Argv) == 0 || len(invocation.Argv) > maxArgvItems {
		add("invalid_argv")
	} else {
		for _, token := range invocation.Argv {
			if !boundedUTF8(token, maxTokenBytes) {
				add("input_limit")
				break
			}
		}
		if invocation.Argv[0] == "" {
			add("invalid_argv")
		}
	}
	if invocation.Program != "" {
		if !boundedUTF8(invocation.Program, maxProgramBytes) ||
			strings.Contains(invocation.Program, "/") {
			add("invalid_program")
		} else if len(invocation.Argv) != 0 && path.Base(invocation.Argv[0]) != invocation.Program {
			add("program_argv_mismatch")
		}
	}
	if invocation.Context != nil && issuesForContext(*invocation.Context) {
		add("invalid_context")
	}
	if len(invocation.WordFacts) > maxWordFacts {
		add("invalid_word_facts")
	} else {
		facts := make(map[string]WordFact, len(invocation.WordFacts))
		for _, fact := range invocation.WordFacts {
			if !validWordFact(fact) || !contains(invocation.Argv, fact.Value) {
				add("invalid_word_facts")
				break
			}
			if existing, duplicate := facts[fact.Value]; duplicate && !reflect.DeepEqual(existing, fact) {
				add("invalid_word_facts")
				break
			}
			facts[fact.Value] = fact
		}
	}
	sort.Strings(issues)
	return issues
}

func issuesForContext(context InvocationContext) bool {
	if !validOptionalAbsolutePath(context.CWD) || !validOptionalAbsolutePath(context.ActiveHome) {
		return true
	}
	return !validRootSet(context.WorkspaceRoots) || !validRootSet(context.TemporaryRoots)
}

func validRootSet(roots []string) bool {
	if len(roots) > maxContextRoots {
		return false
	}
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if !validOptionalAbsolutePath(root) || root == "" {
			return false
		}
		if _, ok := seen[root]; ok {
			return false
		}
		seen[root] = struct{}{}
	}
	return true
}

func validOptionalAbsolutePath(value string) bool {
	return value == "" || boundedUTF8(value, maxTokenBytes) && path.IsAbs(value)
}

func validWordFact(fact WordFact) bool {
	if !boundedUTF8(fact.Value, maxTokenBytes) || !boundedUTF8(fact.RawValue, maxTokenBytes) {
		return false
	}
	if fact.NormalizedValue != nil && !boundedUTF8(*fact.NormalizedValue, maxTokenBytes) {
		return false
	}
	if fact.ResolvedValue != nil && !boundedUTF8(*fact.ResolvedValue, maxTokenBytes) {
		return false
	}
	switch fact.Resolution {
	case ResolutionExact, ResolutionContextual, ResolutionAnchoredPattern,
		ResolutionGenerated, ResolutionUnknown:
	default:
		return false
	}
	if (fact.Resolution == ResolutionContextual ||
		fact.Resolution == ResolutionAnchoredPattern ||
		fact.Resolution == ResolutionGenerated) && fact.ResolvedValue == nil {
		return false
	}
	seen := make(map[Expansion]struct{}, len(fact.Expansions))
	for _, expansion := range fact.Expansions {
		switch expansion {
		case ExpansionVariable, ExpansionTilde, ExpansionGlob, ExpansionCommandSubstitution:
		default:
			return false
		}
		if _, ok := seen[expansion]; ok {
			return false
		}
		seen[expansion] = struct{}{}
	}
	return true
}

func boundedUTF8(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsRune(value, '\x00') && utf8.ValidString(value)
}

func safeCallID(value string) string {
	if value == "" || !boundedUTF8(value, maxCallIDBytes) {
		return ""
	}
	return value
}

func validSemantics(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxSemanticsBytes {
		return false
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return false
	}
	canonical, err := canonicalJSON(raw)
	return err == nil && len(canonical) != 0 && canonical[0] == '{'
}

func newRuntime(pins Pins, evaluator Evaluator, vectors []conformanceVector, parityAttested bool) *Runtime {
	runtime := &Runtime{
		pins:      pins,
		evaluator: evaluator,
	}
	runtime.conformance = runConformance(runtime, vectors)
	runtime.authorityEnabled = parityAttested &&
		runtime.conformance.Passed && runtime.conformance.Cases > 0
	return runtime
}

func evaluatorIssue(caseName string, got, want Status) string {
	return fmt.Sprintf("%s: status %s, want %s", caseName, got, want)
}
