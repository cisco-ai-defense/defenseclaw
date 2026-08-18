package asrruntime

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	PinnedSchemaVersion                 = "1.0.0"
	PinnedCatalogVersion                = "2026.08.17.5"
	PinnedCatalogDigest                 = "sha256:8bbafc85764ef36c8847ea048b496fd671b73e930becc34036fe2829dde18242"
	PinnedSnapshotDigest                = "sha256:ef3a94c3b340a35c5aa5893f7ae4877a34eafbcd7b4faf887a69be8853f91093"
	PinnedEvaluatorABI                  = "asr.evaluator.v1"
	PinnedReferenceImplementationDigest = "sha256:d469b4345cbb11cdc68efa8c5989d6a9a5e66e821554f9453a87c5fc99e3403b"
	PinnedSemanticContractDigest        = "sha256:7eb7c6e1d614612fa4d8723e77dc5519751703c3c22c7be5728c0f7097ebd68f"
	PinnedConformanceDigest             = "sha256:1abd04b7b9ed8bee89361f4a90040afeb896c4a69125d870493ed28749ea90be"
	PinnedConformanceCaseCount          = 16
	PinnedParityAttested                = false

	maxSnapshotBytes     = 2 << 20
	maxManifestBytes     = 16 << 10
	maxConformanceBytes  = 256 << 10
	maxSemanticContract  = 16 << 10
	maxJSONDepth         = 64
	maxJSONObjectMembers = 32_768
	maxJSONArrayItems    = 32_768
	maxJSONStringBytes   = 65_536
	maxMappings          = 512
)

//go:embed catalog.snapshot.json
var embeddedSnapshot []byte

//go:embed artifact.manifest.json
var embeddedManifest []byte

//go:embed conformance.vectors.json
var embeddedConformance []byte

//go:embed semantic-contract.txt
var embeddedSemanticContract []byte

type artifactManifest struct {
	Format                 string              `json:"format"`
	SchemaVersion          string              `json:"schema_version"`
	CatalogVersion         string              `json:"catalog_version"`
	CatalogDigest          string              `json:"catalog_digest"`
	SnapshotDigest         string              `json:"snapshot_digest"`
	EvaluatorABI           string              `json:"evaluator_abi"`
	SemanticContractDigest string              `json:"semantic_contract_digest"`
	Conformance            conformanceManifest `json:"conformance"`
}

type conformanceManifest struct {
	Digest                        string `json:"digest"`
	CaseCount                     int    `json:"case_count"`
	ReferenceImplementationDigest string `json:"reference_implementation_digest"`
	ParityAttested                bool   `json:"parity_attested"`
}

type snapshotDocument struct {
	SchemaVersion   string            `json:"schema_version"`
	CatalogName     string            `json:"catalog_name"`
	CatalogVersion  string            `json:"catalog_version"`
	DecoderManifest json.RawMessage   `json:"decoder_manifest"`
	RuntimeManifest json.RawMessage   `json:"runtime_manifest"`
	SchemaManifest  json.RawMessage   `json:"schema_manifest"`
	Mappings        []json.RawMessage `json:"mappings"`
	CatalogDigest   string            `json:"catalog_digest"`
}

type snapshotRuntimeManifest struct {
	ABI                  string            `json:"abi"`
	ImplementationDigest string            `json:"implementation_digest"`
	Components           map[string]string `json:"components"`
}

type mappingCommand struct {
	Name     string   `json:"name"`
	Aliases  []string `json:"aliases"`
	Family   string   `json:"family"`
	Profile  string   `json:"profile"`
	Surfaces []string `json:"surfaces"`
	Priority string   `json:"priority"`
}

// LoadEmbedded verifies every embedded byte and constructs the shadow-only
// native runtime. It performs no filesystem or network access.
func LoadEmbedded() (*Runtime, error) {
	return LoadVerified(Bundle{
		Snapshot:         embeddedSnapshot,
		Manifest:         embeddedManifest,
		Conformance:      embeddedConformance,
		SemanticContract: embeddedSemanticContract,
	}, nil)
}

// LoadVerified constructs a runtime only after exact pin, digest, boundedness,
// duplicate-key, and conformance-artifact checks. A nil evaluator selects the
// generic native snapshot interpreter; a supplied evaluator must satisfy the
// pure in-process Evaluator contract. This release's pinned manifest has no
// parity attestation, so a successfully loaded runtime remains shadow-only.
func LoadVerified(bundle Bundle, evaluator Evaluator) (*Runtime, error) {
	return loadBundle(
		bundle.Snapshot,
		bundle.Manifest,
		bundle.Conformance,
		bundle.SemanticContract,
		evaluator,
	)
}

func loadBundle(
	snapshotBytes []byte,
	manifestBytes []byte,
	conformanceBytes []byte,
	semanticContract []byte,
	evaluator Evaluator,
) (*Runtime, error) {
	if err := boundedDocument("manifest", manifestBytes, maxManifestBytes); err != nil {
		return nil, err
	}
	var manifest artifactManifest
	if err := strictDecode("manifest", manifestBytes, &manifest); err != nil {
		return nil, err
	}
	if err := verifyManifest(manifest); err != nil {
		return nil, err
	}

	if err := boundedDocument("snapshot", snapshotBytes, maxSnapshotBytes); err != nil {
		return nil, err
	}
	if got := digestBytes(snapshotBytes); got != manifest.SnapshotDigest {
		return nil, fmt.Errorf("asrruntime: snapshot byte digest mismatch: got %s", got)
	}
	var snapshot snapshotDocument
	if err := strictDecode("snapshot", snapshotBytes, &snapshot); err != nil {
		return nil, err
	}
	if err := verifySnapshot(snapshotBytes, snapshot); err != nil {
		return nil, err
	}
	if evaluator == nil {
		var err error
		evaluator, err = newNativeEvaluator(snapshot)
		if err != nil {
			return nil, err
		}
	}

	if err := boundedDocument("semantic contract", semanticContract, maxSemanticContract); err != nil {
		return nil, err
	}
	if got := digestBytes(semanticContract); got != manifest.SemanticContractDigest {
		return nil, fmt.Errorf("asrruntime: semantic contract digest mismatch: got %s", got)
	}

	if err := boundedDocument("conformance vectors", conformanceBytes, maxConformanceBytes); err != nil {
		return nil, err
	}
	var vectors conformanceDocument
	if err := strictDecode("conformance vectors", conformanceBytes, &vectors); err != nil {
		return nil, err
	}
	if got, err := canonicalDigest(conformanceBytes, ""); err != nil {
		return nil, fmt.Errorf("asrruntime: conformance vectors: %w", err)
	} else if got != manifest.Conformance.Digest {
		return nil, fmt.Errorf("asrruntime: conformance digest mismatch: got %s", got)
	}
	if err := verifyConformance(vectors, manifest.Conformance.CaseCount); err != nil {
		return nil, err
	}

	pins := Pins{
		SchemaVersion:          manifest.SchemaVersion,
		CatalogVersion:         manifest.CatalogVersion,
		CatalogDigest:          manifest.CatalogDigest,
		EvaluatorABI:           manifest.EvaluatorABI,
		SemanticContractDigest: manifest.SemanticContractDigest,
		ConformanceDigest:      manifest.Conformance.Digest,
	}
	return newRuntime(pins, evaluator, vectors.Cases, manifest.Conformance.ParityAttested), nil
}

func verifyManifest(manifest artifactManifest) error {
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"format", manifest.Format, "defenseclaw.asr.bundle.v1"},
		{"schema_version", manifest.SchemaVersion, PinnedSchemaVersion},
		{"catalog_version", manifest.CatalogVersion, PinnedCatalogVersion},
		{"catalog_digest", manifest.CatalogDigest, PinnedCatalogDigest},
		{"snapshot_digest", manifest.SnapshotDigest, PinnedSnapshotDigest},
		{"evaluator_abi", manifest.EvaluatorABI, PinnedEvaluatorABI},
		{"semantic_contract_digest", manifest.SemanticContractDigest, PinnedSemanticContractDigest},
		{"conformance.digest", manifest.Conformance.Digest, PinnedConformanceDigest},
		{"conformance.reference_implementation_digest", manifest.Conformance.ReferenceImplementationDigest, PinnedReferenceImplementationDigest},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf(
				"asrruntime: %s pin mismatch: got %q, want %q",
				check.name,
				check.got,
				check.want,
			)
		}
	}
	if manifest.Conformance.CaseCount != PinnedConformanceCaseCount {
		return fmt.Errorf(
			"asrruntime: conformance case count pin mismatch: got %d, want %d",
			manifest.Conformance.CaseCount,
			PinnedConformanceCaseCount,
		)
	}
	if manifest.Conformance.ParityAttested != PinnedParityAttested {
		return fmt.Errorf(
			"asrruntime: parity attestation pin mismatch: got %t, want %t",
			manifest.Conformance.ParityAttested,
			PinnedParityAttested,
		)
	}
	return nil
}

func verifySnapshot(raw []byte, snapshot snapshotDocument) error {
	if snapshot.SchemaVersion != PinnedSchemaVersion {
		return fmt.Errorf("asrruntime: snapshot schema pin mismatch: got %q", snapshot.SchemaVersion)
	}
	if snapshot.CatalogVersion != PinnedCatalogVersion {
		return fmt.Errorf("asrruntime: snapshot catalog version mismatch: got %q", snapshot.CatalogVersion)
	}
	if snapshot.CatalogDigest != PinnedCatalogDigest {
		return fmt.Errorf("asrruntime: snapshot catalog digest pin mismatch: got %q", snapshot.CatalogDigest)
	}
	var runtimeManifest snapshotRuntimeManifest
	if err := strictDecode("snapshot runtime manifest", snapshot.RuntimeManifest, &runtimeManifest); err != nil {
		return err
	}
	if runtimeManifest.ABI != PinnedEvaluatorABI {
		return fmt.Errorf("asrruntime: snapshot evaluator ABI mismatch: got %q", runtimeManifest.ABI)
	}
	if runtimeManifest.ImplementationDigest != PinnedReferenceImplementationDigest {
		return fmt.Errorf("asrruntime: snapshot reference implementation digest mismatch: got %q", runtimeManifest.ImplementationDigest)
	}
	calculated, err := canonicalDigest(raw, "catalog_digest")
	if err != nil {
		return fmt.Errorf("asrruntime: snapshot digest: %w", err)
	}
	if calculated != snapshot.CatalogDigest {
		return fmt.Errorf("asrruntime: snapshot content digest mismatch: got %s", calculated)
	}
	if snapshot.CatalogName == "" || len(snapshot.Mappings) == 0 || len(snapshot.Mappings) > maxMappings {
		return errors.New("asrruntime: invalid snapshot catalog or mapping count")
	}
	return verifyMappingIdentities(snapshot.Mappings)
}

func verifyMappingIdentities(mappings []json.RawMessage) error {
	allowedKeys := map[string]struct{}{
		"$schema": {}, "command": {}, "coverage": {}, "mapping_id": {},
		"provenance": {}, "revision": {}, "schema_version": {},
		"semantics": {}, "summary": {}, "syntax": {},
	}
	requiredKeys := []string{
		"command", "coverage", "mapping_id", "provenance", "revision",
		"schema_version", "semantics", "summary", "syntax",
	}
	mappingIDs := make(map[string]struct{}, len(mappings))
	programs := make(map[string]struct{}, len(mappings))
	for index, raw := range mappings {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return fmt.Errorf("asrruntime: mapping %d: %w", index, err)
		}
		for key := range fields {
			if _, ok := allowedKeys[key]; !ok {
				return fmt.Errorf("asrruntime: mapping %d: unknown field %q", index, key)
			}
		}
		for _, key := range requiredKeys {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("asrruntime: mapping %d: missing field %q", index, key)
			}
		}
		var mappingID, schemaVersion string
		var command mappingCommand
		if err := json.Unmarshal(fields["mapping_id"], &mappingID); err != nil || mappingID == "" {
			return fmt.Errorf("asrruntime: mapping %d: invalid mapping_id", index)
		}
		if _, exists := mappingIDs[mappingID]; exists {
			return fmt.Errorf("asrruntime: duplicate mapping_id %q", mappingID)
		}
		mappingIDs[mappingID] = struct{}{}
		if err := json.Unmarshal(fields["schema_version"], &schemaVersion); err != nil ||
			schemaVersion != PinnedSchemaVersion {
			return fmt.Errorf("asrruntime: mapping %q: invalid schema_version", mappingID)
		}
		if err := strictDecode("mapping command", fields["command"], &command); err != nil {
			return fmt.Errorf("asrruntime: mapping %q: %w", mappingID, err)
		}
		for _, program := range append([]string{command.Name}, command.Aliases...) {
			if program == "" || len(program) > maxProgramBytes || strings.Contains(program, "/") {
				return fmt.Errorf("asrruntime: mapping %q: invalid program", mappingID)
			}
			if _, exists := programs[program]; exists {
				return fmt.Errorf("asrruntime: duplicate program %q", program)
			}
			programs[program] = struct{}{}
		}
	}
	return nil
}

func verifyConformance(document conformanceDocument, wantCases int) error {
	if document.SchemaVersion != PinnedSchemaVersion || len(document.Cases) != wantCases {
		return errors.New("asrruntime: conformance schema or case count mismatch")
	}
	names := make(map[string]struct{}, len(document.Cases))
	for index, vector := range document.Cases {
		if vector.Name == "" || len(vector.Name) > 256 {
			return fmt.Errorf("asrruntime: conformance case %d has invalid name", index)
		}
		if _, exists := names[vector.Name]; exists {
			return fmt.Errorf("asrruntime: duplicate conformance case %q", vector.Name)
		}
		names[vector.Name] = struct{}{}
		if !validStatus(vector.Expected.Status) || vector.Expected.Status == StatusError {
			return fmt.Errorf("asrruntime: conformance case %q has invalid expected status", vector.Name)
		}
		if issues := validateInvocation(vector.Invocation); len(issues) != 0 {
			return fmt.Errorf("asrruntime: conformance case %q has invalid invocation: %v", vector.Name, issues)
		}
		normalizedIssues := normalizeIssues(vector.Expected.Issues)
		if !equalStrings(normalizedIssues, vector.Expected.Issues) {
			return fmt.Errorf("asrruntime: conformance case %q has non-canonical issues", vector.Name)
		}
		if vector.Expected.Status != StatusUnsupported && !validSemantics(vector.Expected.Semantics) {
			return fmt.Errorf("asrruntime: conformance case %q has invalid semantics", vector.Name)
		}
		if vector.Expected.Status == StatusUnsupported && len(vector.Expected.Semantics) != 0 {
			return fmt.Errorf("asrruntime: unsupported conformance case %q must omit semantics", vector.Name)
		}
	}
	return nil
}

func boundedDocument(name string, raw []byte, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return fmt.Errorf("asrruntime: %s is empty, oversized, or invalid UTF-8", name)
	}
	return nil
}

func strictDecode(name string, raw []byte, target any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("asrruntime: %s: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("asrruntime: %s: %w", name, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("asrruntime: %s: %w", name, err)
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON depth limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if value, ok := token.(string); ok && len(value) > maxJSONStringBytes {
			return errors.New("JSON string limit exceeded")
		}
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for members := 0; decoder.More(); members++ {
			if members >= maxJSONObjectMembers {
				return errors.New("JSON object member limit exceeded")
			}
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok || len(key) > maxJSONStringBytes {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for items := 0; decoder.More(); items++ {
			if items >= maxJSONArrayItems {
				return errors.New("JSON array item limit exceeded")
			}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func canonicalDigest(raw []byte, omittedKey string) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", err
	}
	if omittedKey != "" {
		delete(document, omittedKey)
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return "", err
	}
	return digestBytes(bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'})), nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
