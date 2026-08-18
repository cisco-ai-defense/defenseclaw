package asrruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

type fixedEvaluator struct {
	result Result
}

func (e fixedEvaluator) Evaluate(NormalizedInvocation) Result {
	return e.result
}

type panicEvaluator struct{}

func (panicEvaluator) Evaluate(NormalizedInvocation) Result {
	panic("must fail closed")
}

func validInvocation() NormalizedInvocation {
	return NormalizedInvocation{
		Program:      "rm",
		Surface:      SurfaceDirectArgv,
		Profile:      "universal-linux",
		Argv:         []string{"rm", "--help"},
		ArgvComplete: true,
	}
}

func completeSemantics() json.RawMessage {
	return json.RawMessage(`{"mapping_id":"universal-linux.rm.v1","mode":"HELP","modifiers":[],"evidence":{"kind":"REVIEWED_REGISTRY_MAPPING","mapping_id":"universal-linux.rm.v1","mapping_revision":1,"profile":"universal-linux","coverage_status":"COMPLETE","evaluation_default":"COMPLETE","coverage_basis":"UNIVERSAL_LINUX","review_state":"REVIEWED"},"controls":[],"effects":[],"flows":[]}`)
}

func TestLoadEmbeddedNativeConformanceIsPinnedAndShadowOnly(t *testing.T) {
	runtime, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	wantPins := Pins{
		SchemaVersion:          PinnedSchemaVersion,
		CatalogVersion:         PinnedCatalogVersion,
		CatalogDigest:          PinnedCatalogDigest,
		EvaluatorABI:           PinnedEvaluatorABI,
		SemanticContractDigest: PinnedSemanticContractDigest,
		ConformanceDigest:      PinnedConformanceDigest,
	}
	if got := runtime.Pins(); got != wantPins {
		t.Fatalf("Pins() = %#v, want %#v", got, wantPins)
	}
	if runtime.CanAuthorize() {
		t.Fatal("bootstrap runtime must not authorize")
	}
	report := runtime.Conformance()
	if report.Cases != PinnedConformanceCaseCount || !report.Passed {
		t.Fatalf("Conformance() = %#v, want passing native shadow conformance", report)
	}
	if len(report.Mismatches) != 0 {
		t.Fatalf("Conformance().Mismatches = %#v", report.Mismatches)
	}

	result := runtime.Evaluate(validInvocation())
	if result.Status != StatusComplete || result.Authoritative {
		t.Fatalf("Evaluate() = %#v, want non-authoritative COMPLETE", result)
	}
	unsupported := validInvocation()
	unsupported.Program = "echo"
	unsupported.Argv = []string{"echo", "hello"}
	if result := runtime.Evaluate(unsupported); result.Status != StatusUnsupported ||
		result.Authoritative || !containsString(result.Issues, "no_mapping") {
		t.Fatalf("unsupported Evaluate() = %#v", result)
	}
	if len(result.Issues) != 0 || !validSemantics(result.Semantics) {
		t.Fatalf("Evaluate().Issues = %#v", result.Issues)
	}
}

func TestEvaluateRejectsMalformedInvocationBeforeEvaluator(t *testing.T) {
	runtime := newRuntime(
		Pins{SchemaVersion: PinnedSchemaVersion},
		fixedEvaluator{result: Result{Status: StatusComplete}},
		nil,
		false,
	)
	tests := []struct {
		name       string
		invocation NormalizedInvocation
		wantIssue  string
	}{
		{name: "empty argv", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv}, wantIssue: "invalid_argv"},
		{name: "unknown surface", invocation: NormalizedInvocation{Surface: "shell", Argv: []string{"rm"}}, wantIssue: "invalid_surface"},
		{name: "slash program", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv, Program: "/bin/rm", Argv: []string{"rm"}}, wantIssue: "invalid_program"},
		{name: "relative cwd", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv, Argv: []string{"rm"}, Context: &InvocationContext{CWD: "relative"}}, wantIssue: "invalid_context"},
		{name: "duplicate root", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv, Argv: []string{"rm"}, Context: &InvocationContext{WorkspaceRoots: []string{"/repo", "/repo"}}}, wantIssue: "invalid_context"},
		{name: "word fact cardinality", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv, Argv: []string{"rm", "x"}, WordFacts: []WordFact{{Resolution: ResolutionExact}}}, wantIssue: "invalid_word_facts"},
		{name: "oversized token", invocation: NormalizedInvocation{Surface: SurfaceDirectArgv, Argv: []string{strings.Repeat("x", maxTokenBytes+1)}}, wantIssue: "input_limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runtime.Evaluate(test.invocation)
			if result.Status != StatusInvalid || result.Authoritative {
				t.Fatalf("Evaluate() = %#v, want non-authoritative INVALID", result)
			}
			if !containsString(result.Issues, test.wantIssue) {
				t.Fatalf("Evaluate().Issues = %#v, want %q", result.Issues, test.wantIssue)
			}
		})
	}
}

func TestAuthorityRequiresAttestationPassingVectorsCompleteArgvAndStatus(t *testing.T) {
	vectors := []conformanceVector{{
		Name:       "complete",
		Invocation: validInvocation(),
		Expected: expectedResult{
			Status:    StatusComplete,
			Semantics: completeSemantics(),
		},
	}}
	evaluator := fixedEvaluator{result: Result{Status: StatusComplete, Semantics: completeSemantics()}}

	shadow := newRuntime(Pins{}, evaluator, vectors, false)
	if shadow.CanAuthorize() || shadow.Evaluate(validInvocation()).Authoritative {
		t.Fatal("passing vectors without a parity attestation must remain shadow-only")
	}

	proven := newRuntime(Pins{}, evaluator, vectors, true)
	if !proven.CanAuthorize() || !proven.Evaluate(validInvocation()).Authoritative {
		t.Fatal("exact attestation and passing vectors should enable COMPLETE authority")
	}
	incomplete := validInvocation()
	incomplete.ArgvComplete = false
	if result := proven.Evaluate(incomplete); result.Status != StatusPartial ||
		result.Authoritative || !containsString(result.Issues, "argv_incomplete") {
		t.Fatalf("incomplete Evaluate() = %#v, want shadow PARTIAL", result)
	}
	partialRuntime := newRuntime(
		Pins{},
		fixedEvaluator{result: Result{Status: StatusPartial, Semantics: completeSemantics()}},
		[]conformanceVector{{Name: "partial", Invocation: validInvocation(), Expected: expectedResult{Status: StatusPartial, Semantics: completeSemantics()}}},
		true,
	)
	if result := partialRuntime.Evaluate(validInvocation()); result.Status != StatusPartial || result.Authoritative {
		t.Fatalf("partial Evaluate() = %#v, want non-authoritative PARTIAL", result)
	}
}

func TestConformanceRejectsSemanticDriftEvenWhenStatusMatches(t *testing.T) {
	vectors := []conformanceVector{{
		Name:       "semantic-parity",
		Invocation: validInvocation(),
		Expected: expectedResult{
			Status:    StatusComplete,
			Semantics: completeSemantics(),
		},
	}}
	drifted := json.RawMessage(`{"mapping_id":"universal-linux.rm.v1","mode":"EXECUTE","modifiers":[],"evidence":null,"controls":[],"effects":[],"flows":[]}`)
	runtime := newRuntime(
		Pins{},
		fixedEvaluator{result: Result{Status: StatusComplete, Semantics: drifted}},
		vectors,
		true,
	)
	if runtime.Conformance().Passed || runtime.CanAuthorize() {
		t.Fatalf("semantic drift must disable authority: %#v", runtime.Conformance())
	}
	if !containsSubstring(runtime.Conformance().Mismatches, "canonical semantics mismatch") {
		t.Fatalf("mismatches = %#v", runtime.Conformance().Mismatches)
	}
}

func TestEvaluateFailsClosedOnEvaluatorDefects(t *testing.T) {
	for _, test := range []struct {
		name      string
		evaluator Evaluator
	}{
		{name: "panic", evaluator: panicEvaluator{}},
		{name: "unknown status", evaluator: fixedEvaluator{result: Result{Status: "MAYBE", Authoritative: true}}},
		{name: "duplicate semantics", evaluator: fixedEvaluator{result: Result{Status: StatusComplete, Semantics: json.RawMessage(`{"mode":"HELP","mode":"EXECUTE"}`)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newRuntime(Pins{CatalogDigest: PinnedCatalogDigest}, test.evaluator, nil, false)
			result := runtime.Evaluate(validInvocation())
			if result.Status != StatusError || result.Authoritative {
				t.Fatalf("Evaluate() = %#v, want non-authoritative ERROR", result)
			}
			if result.Pins.CatalogDigest != PinnedCatalogDigest {
				t.Fatalf("Evaluate().Pins = %#v", result.Pins)
			}
		})
	}
}

func TestIssuesAreBoundedDeduplicatedAndSorted(t *testing.T) {
	issues := make([]string, 0, 100)
	for index := 99; index >= 0; index-- {
		issues = append(issues, string(rune('a'+index%26)))
	}
	issues = append(issues, "", strings.Repeat("x", 257))
	runtime := newRuntime(
		Pins{},
		fixedEvaluator{result: Result{Status: StatusPartial, Issues: issues, Semantics: completeSemantics()}},
		nil,
		false,
	)
	result := runtime.Evaluate(validInvocation())
	if len(result.Issues) != 26 {
		t.Fatalf("len(Issues) = %d, want 26", len(result.Issues))
	}
	for index := 1; index < len(result.Issues); index++ {
		if result.Issues[index-1] >= result.Issues[index] {
			t.Fatalf("Issues are not sorted and unique: %#v", result.Issues)
		}
	}
}

func TestRuntimeOwnsCallIDCorrelation(t *testing.T) {
	runtime := newRuntime(
		Pins{},
		fixedEvaluator{result: Result{
			CallID:    "spoofed",
			Status:    StatusPartial,
			Semantics: completeSemantics(),
		}},
		nil,
		false,
	)
	invocation := validInvocation()
	invocation.CallID = "command-node-17"
	if result := runtime.Evaluate(invocation); result.CallID != invocation.CallID {
		t.Fatalf("Evaluate().CallID = %q, want %q", result.CallID, invocation.CallID)
	}
	invocation.CallID = strings.Repeat("x", maxCallIDBytes+1)
	if result := runtime.Evaluate(invocation); result.CallID != "" || result.Status != StatusInvalid {
		t.Fatalf("invalid correlation result = %#v", result)
	}
}

func TestLoadVerifiedPublicBoundaryRemainsShadowOnly(t *testing.T) {
	runtime, err := LoadVerified(Bundle{
		Snapshot:         embeddedSnapshot,
		Manifest:         embeddedManifest,
		Conformance:      embeddedConformance,
		SemanticContract: embeddedSemanticContract,
	}, fixedEvaluator{result: Result{Status: StatusComplete, Semantics: completeSemantics()}})
	if err != nil {
		t.Fatalf("LoadVerified: %v", err)
	}
	if runtime.Conformance().Passed {
		t.Fatalf("constant evaluator must not pass differential vectors: %#v", runtime.Conformance())
	}
	if runtime.CanAuthorize() || runtime.Evaluate(validInvocation()).Authoritative {
		t.Fatal("public verified load must honor the pinned false parity attestation")
	}
}

func TestLoadBundleRejectsTamperingAndUntrustedJSON(t *testing.T) {
	tests := []struct {
		name       string
		snapshot   []byte
		manifest   []byte
		vectors    []byte
		contract   []byte
		wantDetail string
	}{
		{
			name:       "snapshot bytes",
			snapshot:   append(append([]byte(nil), embeddedSnapshot...), ' '),
			manifest:   embeddedManifest,
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "snapshot byte digest mismatch",
		},
		{
			name:       "manifest pin",
			snapshot:   embeddedSnapshot,
			manifest:   []byte(strings.Replace(string(embeddedManifest), PinnedEvaluatorABI, "asr.evaluator.v2", 1)),
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "evaluator_abi pin mismatch",
		},
		{
			name:       "parity attestation",
			snapshot:   embeddedSnapshot,
			manifest:   []byte(strings.Replace(string(embeddedManifest), `"parity_attested": false`, `"parity_attested": true`, 1)),
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "parity attestation pin mismatch",
		},
		{
			name:       "semantic contract",
			snapshot:   embeddedSnapshot,
			manifest:   embeddedManifest,
			vectors:    embeddedConformance,
			contract:   append(append([]byte(nil), embeddedSemanticContract...), 'x'),
			wantDetail: "semantic contract digest mismatch",
		},
		{
			name:       "conformance vectors",
			snapshot:   embeddedSnapshot,
			manifest:   embeddedManifest,
			vectors:    []byte(strings.Replace(string(embeddedConformance), `"COMPLETE"`, `"PARTIAL"`, 1)),
			contract:   embeddedSemanticContract,
			wantDetail: "conformance digest mismatch",
		},
		{
			name:       "duplicate JSON key",
			snapshot:   embeddedSnapshot,
			manifest:   []byte(strings.Replace(string(embeddedManifest), "{", `{"format":"duplicate",`, 1)),
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "duplicate JSON key",
		},
		{
			name:       "oversized snapshot",
			snapshot:   make([]byte, maxSnapshotBytes+1),
			manifest:   embeddedManifest,
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "oversized",
		},
		{
			name:       "malformed manifest",
			snapshot:   embeddedSnapshot,
			manifest:   []byte("{"),
			vectors:    embeddedConformance,
			contract:   embeddedSemanticContract,
			wantDetail: "malformed JSON object",
		},
		{
			name:       "unknown conformance structure",
			snapshot:   embeddedSnapshot,
			manifest:   embeddedManifest,
			vectors:    []byte(strings.Replace(string(embeddedConformance), `"expect": {`, `"unknown": true, "expect": {`, 1)),
			contract:   embeddedSemanticContract,
			wantDetail: "unknown field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadBundle(test.snapshot, test.manifest, test.vectors, test.contract, nil)
			if err == nil || !strings.Contains(err.Error(), test.wantDetail) {
				t.Fatalf("loadBundle() error = %v, want detail %q", err, test.wantDetail)
			}
		})
	}
}

func TestStrictDecodeRejectsUnknownAndDuplicateStructures(t *testing.T) {
	var manifest artifactManifest
	if err := strictDecode("manifest", []byte(`{"unknown":true}`), &manifest); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown strictDecode error = %v", err)
	}
	var value map[string]any
	if err := strictDecode("duplicate", []byte(`{"a":1,"nested":{"b":1,"b":2}}`), &value); err == nil ||
		!strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate strictDecode error = %v", err)
	}
	if err := strictDecode("multiple", []byte(`{} {}`), &value); err == nil ||
		!strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("multiple strictDecode error = %v", err)
	}
}

func TestSnapshotAndVectorDigestsMatchPins(t *testing.T) {
	if got := digestBytes(embeddedSnapshot); got != PinnedSnapshotDigest {
		t.Fatalf("snapshot byte digest = %s", got)
	}
	if got, err := canonicalDigest(embeddedSnapshot, "catalog_digest"); err != nil || got != PinnedCatalogDigest {
		t.Fatalf("snapshot catalog digest = %s, %v", got, err)
	}
	if got := digestBytes(embeddedSemanticContract); got != PinnedSemanticContractDigest {
		t.Fatalf("semantic contract digest = %s", got)
	}
	if got, err := canonicalDigest(embeddedConformance, ""); err != nil || got != PinnedConformanceDigest {
		t.Fatalf("conformance digest = %s, %v", got, err)
	}
}

func TestVerifyMappingIdentitiesRejectsDuplicatesAndUnknownFields(t *testing.T) {
	var snapshot snapshotDocument
	if err := json.Unmarshal(embeddedSnapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := verifyMappingIdentities([]json.RawMessage{snapshot.Mappings[0], snapshot.Mappings[0]}); err == nil ||
		!strings.Contains(err.Error(), "duplicate mapping_id") {
		t.Fatalf("duplicate mapping error = %v", err)
	}
	unknown := []byte(strings.Replace(string(snapshot.Mappings[0]), "{", `{"unknown":true,`, 1))
	if err := verifyMappingIdentities([]json.RawMessage{unknown}); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown mapping error = %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
