// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"path"
	"strconv"
	"strings"
)

const findingStateFingerprintDomain = "defenseclaw-finding-state-v1"

// FindingStateIdentity is the stable, content-addressed identity of one
// scanner finding. It is deliberately separate from FindingOccurrenceID:
// occurrences remain immutable forensic facts while this identity drives the
// compact current-state projection across successful rescans.
type FindingStateIdentity struct {
	Fingerprint        string
	NormalizedTarget   string
	FilePath           string
	NormalizedFilePath string
	LineNumber         int
	ContentDigest      string
}

// StableFindingStateIdentity derives a scope-safe finding identity from the
// fields that define the source fact: scanner, target, rule, normalized file,
// line, and matched content. The content itself is never retained by this
// helper; only its SHA-256 digest contributes to the final domain-separated
// fingerprint.
//
// The audit boundary's installation-keyed content token is preferred when
// present so sensitive redaction does not collapse different matched values.
// EvidenceSummary is otherwise used because that boundary has made it
// deterministic and sanitized sensitive findings before persistence. Direct
// scanner callers that have populated neither fall back to Description.
func StableFindingStateIdentity(scannerName, targetType, target string, finding Finding) FindingStateIdentity {
	normalizedScanner := strings.ToLower(strings.TrimSpace(scannerName))
	normalizedTargetType := NormalizeFindingStateTargetType(targetType)
	findingScanner := strings.ToLower(strings.TrimSpace(finding.Scanner))
	if findingScanner == "" {
		findingScanner = normalizedScanner
	}
	normalizedTarget := normalizeFindingIdentityPath(target)
	filePath, lineNumber := findingIdentityLocation(finding)
	if filePath == "" {
		filePath = strings.TrimSpace(target)
	}
	normalizedFilePath := normalizeFindingIdentityPath(filePath)

	content := finding.EvidenceSummary
	if isPersistedFindingContentFingerprint(finding.ContentFingerprint) {
		// The logger replaces producer values with its installation-keyed
		// evidence token before sensitive evidence is redacted. Prefer that
		// token so two same-length redacted secrets at one location remain
		// distinct without putting an offline-enumerable content hash here.
		content = "keyed-evidence:" + finding.ContentFingerprint + "\x00" + content
	} else if content == "" {
		content = finding.Description
	}
	contentSum := sha256.Sum256([]byte(content))
	contentDigest := hex.EncodeToString(contentSum[:])

	parts := []string{
		findingStateFingerprintDomain,
		normalizedScanner,
		normalizedTargetType,
		normalizedTarget,
		findingScanner,
		strings.ToLower(strings.TrimSpace(finding.RuleID)),
		normalizedFilePath,
		strconv.Itoa(lineNumber),
		contentDigest,
	}
	h := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(part))
	}

	return FindingStateIdentity{
		Fingerprint:        hex.EncodeToString(h.Sum(nil)),
		NormalizedTarget:   normalizedTarget,
		FilePath:           filePath,
		NormalizedFilePath: normalizedFilePath,
		LineNumber:         lineNumber,
		ContentDigest:      contentDigest,
	}
}

func isPersistedFindingContentFingerprint(value string) bool {
	if len(value) != 8 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// NormalizeFindingStateTarget exposes the exact scope normalization used by
// StableFindingStateIdentity so persistence queries cannot drift from writes.
func NormalizeFindingStateTarget(target string) string {
	return normalizeFindingIdentityPath(target)
}

// NormalizeFindingStateTargetType folds compatibility aliases that identify
// the same complete asset scope without coercing unknown/runtime types into a
// lifecycle-eligible value.
func NormalizeFindingStateTargetType(targetType string) string {
	switch targetType = strings.ToLower(strings.TrimSpace(targetType)); targetType {
	case "code":
		return "file"
	case "inventory":
		return "aibom"
	default:
		return targetType
	}
}

func normalizeFindingIdentityPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Scanner locations are serialized paths, so canonicalize both separator
	// forms independent of the host running the database. This keeps an audit
	// database moved between Windows and Unix from minting a second identity.
	value = strings.ReplaceAll(value, `\`, "/")
	unc := strings.HasPrefix(value, "//")
	value = path.Clean(value)
	if unc && !strings.HasPrefix(value, "//") {
		value = "/" + value
	}
	if len(value) >= 2 && value[1] == ':' && value[0] >= 'A' && value[0] <= 'Z' {
		value = strings.ToLower(value[:1]) + value[1:]
	}
	return value
}

func findingIdentityLocation(finding Finding) (string, int) {
	location := strings.TrimSpace(finding.Location)
	lineNumber := 0
	if finding.LineNumber != nil && *finding.LineNumber > 0 {
		lineNumber = *finding.LineNumber
	}
	if location == "" {
		return "", lineNumber
	}

	// A final `:<number>` is ambiguous without structured scanner metadata: it
	// can be a legitimate POSIX filename or Windows drive-relative path. Strip
	// only the suffix that exactly repeats an explicit positive LineNumber.
	if lineNumber > 0 {
		suffix := ":" + strconv.Itoa(lineNumber)
		if strings.HasSuffix(location, suffix) && len(location) > len(suffix) {
			location = strings.TrimSuffix(location, suffix)
		}
	}
	return location, lineNumber
}

// FindingLifecycleStatus describes how one immutable occurrence affected the
// canonical state projection.
type FindingLifecycleStatus string

const (
	FindingLifecycleNew      FindingLifecycleStatus = "new"
	FindingLifecycleRepeated FindingLifecycleStatus = "repeated"
	FindingLifecycleReopened FindingLifecycleStatus = "reopened"
	FindingLifecycleUpdated  FindingLifecycleStatus = "updated"
)

// FindingLifecycleObservation records one occurrence's canonical transition.
type FindingLifecycleObservation struct {
	OccurrenceID      string
	Fingerprint       string
	RuleID            string
	Severity          Severity
	Status            FindingLifecycleStatus
	PersistOccurrence bool
}

// FindingLifecycleResolution records a current finding that disappeared from
// a newer complete scan of the same scanner/target scope.
type FindingLifecycleResolution struct {
	Fingerprint string
	RuleID      string
	Severity    Severity
}

// FindingLifecycleDelta is attached to ScanResult after atomic persistence.
// Managed is false for runtime/failed/unsupported scans, which retain the
// historical emit-every-occurrence behavior.
type FindingLifecycleDelta struct {
	Managed           bool
	Observations      []FindingLifecycleObservation
	Resolved          []FindingLifecycleResolution
	GaugeDelta        map[Severity]int64
	CurrentBySeverity map[Severity]int64
	emitByOccurrence  map[string]bool
}

// IndexOccurrenceEmissions prepares constant-time transition lookups after the
// lifecycle observations have been assembled. Persistence calls this before a
// delta is attached to a scan result, so normal emission paths only read the
// finalized index.
func (delta *FindingLifecycleDelta) IndexOccurrenceEmissions() {
	if delta == nil || !delta.Managed || delta.emitByOccurrence != nil {
		return
	}
	delta.emitByOccurrence = make(map[string]bool, len(delta.Observations))
	for index := range delta.Observations {
		observation := delta.Observations[index]
		if _, exists := delta.emitByOccurrence[observation.OccurrenceID]; exists {
			continue
		}
		delta.emitByOccurrence[observation.OccurrenceID] =
			observation.Status != FindingLifecycleRepeated
	}
}

// ShouldEmitOccurrence reports whether a finding is a meaningful current-state
// transition. Repeated static findings update the distinct lifecycle state but
// do not inflate the transition ledger, default logs, or finding counters.
func (delta *FindingLifecycleDelta) ShouldEmitOccurrence(occurrenceID string) bool {
	if delta == nil || !delta.Managed {
		return true
	}
	if delta.emitByOccurrence != nil {
		return delta.emitByOccurrence[occurrenceID]
	}
	// Manually constructed deltas have not been finalized by persistence. Keep
	// this fallback read-only so concurrent lookups cannot race on lazy map
	// initialization and later observation edits retain the former behavior.
	for index := range delta.Observations {
		observation := delta.Observations[index]
		if observation.OccurrenceID == occurrenceID {
			return observation.Status != FindingLifecycleRepeated
		}
	}
	return false
}
