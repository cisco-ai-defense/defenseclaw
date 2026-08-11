// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const (
	historicalSensitiveEvidenceMigrationDescription = "privacy: scrub historical sensitive finding evidence"
	historicalSensitiveEvidenceBatchSize            = 128
)

// migrateHistoricalSensitiveEvidence repairs rows written before the common
// sensitive-finding persistence boundary. Store.applyMigration supplies the
// transaction: every surface and the schema cursor commit together or none do.
func migrateHistoricalSensitiveEvidence(ex dbExecer) error {
	if ex == nil {
		return fmt.Errorf("audit: historical sensitive-evidence migration has no database")
	}
	fmt.Fprintln(os.Stderr, "[audit] historical sensitive-evidence repair: findings")
	if err := scrubHistoricalLegacyFindingRows(ex); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[audit] historical sensitive-evidence repair: scan_findings")
	if err := scrubHistoricalScanFindingRows(ex); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[audit] historical sensitive-evidence repair: scan_results")
	if err := scrubHistoricalScanResultRows(ex); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[audit] historical sensitive-evidence repair: audit_events")
	if err := scrubHistoricalAuditEventRows(ex); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "[audit] historical sensitive-evidence repair: complete")
	return nil
}

type historicalLegacyFindingRow struct {
	rowID                                                      int64
	scanner, ruleID, title, description, location, remediation string
	tags                                                       string
}

// scrubHistoricalLegacyFindingRows repairs the migration-1 findings table.
// The legacy TUI query still reads this table, so it is a first-class forensic
// surface even after scan_findings became the canonical v7 detail store.
func scrubHistoricalLegacyFindingRows(ex dbExecer) error {
	present, err := tableExists(ex, "findings")
	if err != nil || !present {
		return err
	}
	for _, column := range []string{
		"id", "scan_id", "severity", "scanner", "rule_id", "title",
		"description", "location", "remediation", "tags",
	} {
		exists, columnErr := hasColumnDB(ex, "findings", column)
		if columnErr != nil {
			return columnErr
		}
		if !exists {
			return fmt.Errorf("audit: findings.%s is missing before historical evidence repair", column)
		}
	}

	var cursor int64
	for {
		rows, queryErr := ex.Query(`
			SELECT rowid, COALESCE(scanner,''), COALESCE(rule_id,''), COALESCE(title,''),
			       COALESCE(description,''), COALESCE(location,''), COALESCE(remediation,''),
			       COALESCE(tags,'')
			FROM findings WHERE rowid > ? ORDER BY rowid LIMIT ?`,
			cursor, historicalSensitiveEvidenceBatchSize,
		)
		if queryErr != nil {
			return fmt.Errorf("audit: query historical legacy findings: %w", queryErr)
		}
		batch := make([]historicalLegacyFindingRow, 0, historicalSensitiveEvidenceBatchSize)
		for rows.Next() {
			var row historicalLegacyFindingRow
			if scanErr := rows.Scan(
				&row.rowID, &row.scanner, &row.ruleID, &row.title,
				&row.description, &row.location, &row.remediation, &row.tags,
			); scanErr != nil {
				_ = rows.Close()
				return fmt.Errorf("audit: scan historical legacy finding: %w", scanErr)
			}
			batch = append(batch, row)
		}
		iterationErr := rows.Err()
		_ = rows.Close()
		if iterationErr != nil {
			return fmt.Errorf("audit: iterate historical legacy findings: %w", iterationErr)
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			cursor = row.rowID
			decodedTags, tagsErr := decodeHistoricalFindingTags(row.tags)
			finding := scanner.Finding{
				Scanner: row.scanner, RuleID: row.ruleID, Title: row.title,
				Description: row.description, Location: row.location,
				Remediation: row.remediation, Tags: decodedTags,
			}
			kind, sensitive := historicalSensitiveRuleIDKind(row.ruleID, row.scanner)
			if tagsErr != nil {
				// A sensitive rule identity is sufficient to force a canonical
				// overwrite. Otherwise malformed non-empty tags make the row's
				// classification unknowable, so abort the surrounding transaction.
				if !sensitive {
					return fmt.Errorf("audit: decode historical legacy finding tags at rowid %d: %w", row.rowID, tagsErr)
				}
			} else if !sensitive {
				kind, sensitive = historicalSensitiveFindingKind(finding)
			}
			if !sensitive {
				continue
			}
			historicalRedactFinding(&finding, row.scanner, kind)
			encodedTags := encodeHistoricalStringSlice(finding.Tags)
			if finding.RuleID == row.ruleID && finding.Title == row.title &&
				finding.Description == row.description && finding.Location == row.location &&
				finding.Remediation == row.remediation && encodedTags == row.tags {
				continue
			}
			if _, updateErr := ex.Exec(`
				UPDATE findings
				SET rule_id=?, title=?, description=?, location=?, remediation=?, tags=?
				WHERE rowid=?`,
				nullStr(finding.RuleID), nullStr(finding.Title), nullStr(finding.Description),
				nullStr(finding.Location), nullStr(finding.Remediation), nullStr(encodedTags), row.rowID,
			); updateErr != nil {
				return fmt.Errorf("audit: repair historical legacy finding: %w", updateErr)
			}
		}
	}
}

type historicalScanFindingRow struct {
	rowID                                                   int64
	scanner, ruleID, category, title, description, evidence string
	location, remediation, tags, dataAxis, toolCapability   string
	fingerprint, endpoint, decisionPath                     string
}

func scrubHistoricalScanFindingRows(ex dbExecer) error {
	present, err := tableExists(ex, "scan_findings")
	if err != nil || !present {
		return err
	}
	for _, column := range []string{
		"scanner", "rule_id", "category", "title", "description", "evidence_summary",
		"location", "remediation", "tags", "data_axis", "tool_capability_class",
		"content_fingerprint", "external_endpoint", "decision_path",
	} {
		exists, columnErr := hasColumnDB(ex, "scan_findings", column)
		if columnErr != nil {
			return columnErr
		}
		if !exists {
			return fmt.Errorf("audit: scan_findings.%s is missing before historical evidence repair", column)
		}
	}

	var cursor int64
	for {
		rows, queryErr := ex.Query(`
			SELECT rowid, COALESCE(scanner,''), COALESCE(rule_id,''), COALESCE(category,''),
			       COALESCE(title,''), COALESCE(description,''), COALESCE(evidence_summary,''),
			       COALESCE(location,''), COALESCE(remediation,''), COALESCE(tags,''),
			       COALESCE(data_axis,''), COALESCE(tool_capability_class,''),
			       COALESCE(content_fingerprint,''), COALESCE(external_endpoint,''),
			       COALESCE(decision_path,'')
			FROM scan_findings WHERE rowid > ? ORDER BY rowid LIMIT ?`,
			cursor, historicalSensitiveEvidenceBatchSize,
		)
		if queryErr != nil {
			return fmt.Errorf("audit: query historical scan findings: %w", queryErr)
		}
		batch := make([]historicalScanFindingRow, 0, historicalSensitiveEvidenceBatchSize)
		for rows.Next() {
			var row historicalScanFindingRow
			if scanErr := rows.Scan(
				&row.rowID, &row.scanner, &row.ruleID, &row.category,
				&row.title, &row.description, &row.evidence,
				&row.location, &row.remediation, &row.tags,
				&row.dataAxis, &row.toolCapability, &row.fingerprint,
				&row.endpoint, &row.decisionPath,
			); scanErr != nil {
				_ = rows.Close()
				return fmt.Errorf("audit: scan historical scan finding: %w", scanErr)
			}
			batch = append(batch, row)
		}
		iterationErr := rows.Err()
		_ = rows.Close()
		if iterationErr != nil {
			return fmt.Errorf("audit: iterate historical scan findings: %w", iterationErr)
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			cursor = row.rowID
			decodedTags, tagsErr := decodeHistoricalFindingTags(row.tags)
			finding := scanner.Finding{
				RuleID: row.ruleID, Category: row.category, Title: row.title,
				Description: row.description, EvidenceSummary: row.evidence,
				Location: row.location, Remediation: row.remediation,
				Tags:                decodedTags,
				DataAxis:            decodeHistoricalStringSlice(row.dataAxis),
				ToolCapabilityClass: row.toolCapability,
				ContentFingerprint:  row.fingerprint, ExternalEndpoint: row.endpoint,
				DecisionPath: json.RawMessage(row.decisionPath),
			}
			var kind sensitiveFindingKind
			var sensitive bool
			if tagsErr != nil {
				// If trustworthy identity already proves sensitivity, malformed
				// tags can be replaced canonically. Otherwise the tags may be the
				// only classification evidence, so fail the whole migration rather
				// than silently retaining an unclassifiable historical row.
				kind, sensitive = historicalSensitiveFindingKind(scanner.Finding{
					RuleID: row.ruleID, Category: row.category,
				})
				if !sensitive {
					kind, sensitive = historicalSensitiveRuleIDKind(row.ruleID, row.scanner)
				}
				if !sensitive {
					return fmt.Errorf("audit: decode historical scan finding tags at rowid %d: %w", row.rowID, tagsErr)
				}
			} else {
				kind, sensitive = historicalSensitiveFindingKind(finding)
			}
			if !sensitive {
				continue
			}
			historicalRedactFinding(&finding, row.scanner, kind)
			tags := encodeHistoricalStringSlice(finding.Tags)
			dataAxis := encodeHistoricalStringSlice(finding.DataAxis)
			decisionPath := string(finding.DecisionPath)
			if finding.RuleID == row.ruleID && finding.Category == row.category &&
				finding.Title == row.title && finding.Description == row.description &&
				finding.EvidenceSummary == row.evidence && finding.Location == row.location &&
				finding.Remediation == row.remediation && tags == row.tags &&
				dataAxis == row.dataAxis && finding.ToolCapabilityClass == row.toolCapability &&
				finding.ContentFingerprint == row.fingerprint &&
				finding.ExternalEndpoint == row.endpoint && decisionPath == row.decisionPath {
				continue
			}
			if _, updateErr := ex.Exec(`
				UPDATE scan_findings
				SET rule_id=?, category=?, title=?, description=?, evidence_summary=?, location=?,
				    remediation=?, tags=?, data_axis=?, tool_capability_class=?,
				    content_fingerprint=?, external_endpoint=?, decision_path=?
				WHERE rowid=?`,
				nullStr(finding.RuleID), nullStr(finding.Category), nullStr(finding.Title),
				nullStr(finding.Description), nullStr(finding.EvidenceSummary), nullStr(finding.Location),
				nullStr(finding.Remediation), nullStr(tags), nullStr(dataAxis),
				nullStr(finding.ToolCapabilityClass), nullStr(finding.ContentFingerprint),
				nullStr(finding.ExternalEndpoint), nullStr(decisionPath), row.rowID,
			); updateErr != nil {
				return fmt.Errorf("audit: repair historical scan finding: %w", updateErr)
			}
		}
	}
}

type historicalScanResultRow struct {
	rowID          int64
	raw            string
	knownSensitive bool
}

func scrubHistoricalScanResultRows(ex dbExecer) error {
	present, err := tableExists(ex, "scan_results")
	if err != nil || !present {
		return err
	}
	exists, err := hasColumnDB(ex, "scan_results", "raw_json")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("audit: scan_results.raw_json is missing before historical evidence repair")
	}

	var cursor int64
	for {
		rows, queryErr := ex.Query(`
			SELECT rowid, COALESCE(raw_json,''), EXISTS (
				SELECT 1 FROM scan_findings AS finding
				WHERE finding.scan_id = scan_results.id
				  AND LOWER(COALESCE(finding.category,'')) IN (
					'credential-leak', 'pii-exposure', 'prompt-injection'
				  )
			) FROM scan_results
			WHERE rowid > ? ORDER BY rowid LIMIT ?`, cursor, historicalSensitiveEvidenceBatchSize)
		if queryErr != nil {
			return fmt.Errorf("audit: query historical scan results: %w", queryErr)
		}
		batch := make([]historicalScanResultRow, 0, historicalSensitiveEvidenceBatchSize)
		for rows.Next() {
			var row historicalScanResultRow
			if scanErr := rows.Scan(&row.rowID, &row.raw, &row.knownSensitive); scanErr != nil {
				_ = rows.Close()
				return fmt.Errorf("audit: scan historical scan result: %w", scanErr)
			}
			batch = append(batch, row)
		}
		iterationErr := rows.Err()
		_ = rows.Close()
		if iterationErr != nil {
			return fmt.Errorf("audit: iterate historical scan results: %w", iterationErr)
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			cursor = row.rowID
			trimmed := strings.TrimSpace(row.raw)
			if trimmed == "" {
				continue
			}
			var generic any
			if decodeErr := decodeHistoricalJSON([]byte(trimmed), &generic); decodeErr != nil {
				if row.knownSensitive {
					return fmt.Errorf("audit: decode historical sensitive scan result JSON: %w", decodeErr)
				}
				return fmt.Errorf("audit: decode historical scan result JSON: %w", decodeErr)
			}
			object, objectOK := generic.(map[string]any)
			if !objectOK {
				return fmt.Errorf("audit: historical scan result JSON is not an object")
			}
			if _, carriesFindings := object["findings"]; !carriesFindings {
				continue
			}
			changed, repairErr := scrubHistoricalRawScanResult(object)
			if repairErr != nil {
				return repairErr
			}
			if !changed {
				continue
			}
			encoded, encodeErr := marshalHistoricalJSON(object)
			if encodeErr != nil {
				return fmt.Errorf("audit: encode repaired historical scan result: %w", encodeErr)
			}
			if bytes.Equal(encoded, []byte(row.raw)) {
				continue
			}
			if _, updateErr := ex.Exec(`UPDATE scan_results SET raw_json=? WHERE rowid=?`, string(encoded), row.rowID); updateErr != nil {
				return fmt.Errorf("audit: repair historical scan result JSON: %w", updateErr)
			}
		}
	}
}

type historicalSensitiveNeedle struct {
	value string
	kind  sensitiveFindingKind
}

// scrubHistoricalRawScanResult repairs the generic JSON tree rather than
// round-tripping scanner.ScanResult. Historical producers may have added fields
// that the current wire type does not know. Preserve producer result fields
// unless they repeat known evidence, and preserve finding-owned extension
// shape while redacting every non-empty string once that finding is known to
// be sensitive.
func scrubHistoricalRawScanResult(object map[string]any) (bool, error) {
	rawFindings, carriesFindings := object["findings"]
	if !carriesFindings {
		return false, nil
	}
	if rawFindings == nil {
		return false, nil
	}
	findings, ok := rawFindings.([]any)
	if !ok {
		return false, fmt.Errorf("audit: historical scan result findings is not an array")
	}

	changed := false
	allNeedles := make([]historicalSensitiveNeedle, 0)
	for index, candidate := range findings {
		finding, ok := candidate.(map[string]any)
		if !ok {
			return false, fmt.Errorf("audit: historical scan result finding %d is not an object", index)
		}
		kind, sensitive := historicalSensitiveFlagsFromJSON(finding).kind()
		if !sensitive {
			continue
		}
		before, err := marshalHistoricalJSON(finding)
		if err != nil {
			return false, fmt.Errorf("audit: encode historical scan finding before repair: %w", err)
		}
		needles := historicalSensitiveNeedlesFromFinding(finding, kind)
		allNeedles = append(allNeedles, needles...)

		// The canonical scrubber intentionally drops unrecognized finding-owned
		// fields. Save them first, then restore their shape after recursively
		// replacing every non-empty string. Once the finding is classified as
		// sensitive, an unknown producer key cannot prove its string leaves safe.
		extensions := make(map[string]any)
		for key, value := range finding {
			if !historicalKnownRawFindingKey(key) {
				extensions[key] = value
			}
		}
		historicalScrubFindingJSON(finding, kind)
		for key, value := range extensions {
			repaired, _ := scrubHistoricalSensitiveFindingExtensionValue(value, kind)
			finding[key] = repaired
		}
		after, err := marshalHistoricalJSON(finding)
		if err != nil {
			return false, fmt.Errorf("audit: encode historical scan finding after repair: %w", err)
		}
		changed = changed || !bytes.Equal(before, after)
	}

	// Preserve producer result extensions as well. If an extension duplicated
	// evidence from a finding, redact that value without deleting unrelated
	// booleans, numbers, objects, arrays, or safe strings.
	for key, value := range object {
		if historicalKnownRawScanResultKey(key) {
			continue
		}
		repaired, extensionChanged := scrubHistoricalExtensionValue(value, allNeedles)
		if extensionChanged {
			object[key] = repaired
			changed = true
		}
	}
	return changed, nil
}

func historicalKnownRawScanResultKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "scanner", "target", "timestamp", "findings", "duration", "target_type",
		"verdict", "exit_code", "error", "scan_id":
		return true
	default:
		return false
	}
}

func historicalKnownRawFindingKey(key string) bool {
	canonicalKey := strings.ToLower(strings.TrimSpace(key))
	switch canonicalKey {
	case "id", "finding_occurrence_id", "severity", "title", "description", "evidence",
		"evidence_summary", "location", "remediation", "scanner", "tags", "rule_id",
		"category", "line_number", "confidence", "data_axis", "data_axes",
		"tool_capability_class", "content_fingerprint", "fingerprint", "external_endpoint",
		"turn_id", "decision_path", "details", "structured_json", "target", "finding", "findings",
		"defenseclaw.finding.id", "defenseclaw.finding.rule_id", "defenseclaw.finding.category",
		"defenseclaw.finding.title", "defenseclaw.finding.description",
		"defenseclaw.guardrail.evidence_summary", "defenseclaw.finding.location",
		"defenseclaw.finding.remediation", "defenseclaw.finding.tags",
		"defenseclaw.finding.data_axes", "defenseclaw.finding.tool_capability_class",
		"defenseclaw.finding.content_fingerprint", "defenseclaw.finding.fingerprint",
		"defenseclaw.finding.external_endpoint", "defenseclaw.finding.decision_path":
		return true
	default:
		return historicalSafeFindingMetadataKey(canonicalKey)
	}
}

func historicalSensitiveNeedlesFromFinding(
	finding map[string]any,
	kind sensitiveFindingKind,
) []historicalSensitiveNeedle {
	seen := make(map[string]struct{})
	needles := make([]historicalSensitiveNeedle, 0)
	var collect func(any)
	collect = func(value any) {
		switch typed := value.(type) {
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed == "" || isSensitiveFindingRedactionPlaceholder(trimmed) || isPIIRedactionPlaceholder(trimmed) {
				return
			}
			if _, duplicate := seen[trimmed]; duplicate {
				return
			}
			seen[trimmed] = struct{}{}
			needles = append(needles, historicalSensitiveNeedle{value: trimmed, kind: kind})
		case []any:
			for _, child := range typed {
				collect(child)
			}
		case map[string]any:
			for _, child := range typed {
				collect(child)
			}
		}
	}
	for key, value := range finding {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "id", "rule_id", "title", "description", "evidence", "evidence_summary", "location",
			"remediation", "tags", "data_axis", "data_axes", "tool_capability_class",
			"content_fingerprint", "fingerprint", "external_endpoint", "decision_path", "target",
			"defenseclaw.finding.id", "defenseclaw.finding.rule_id", "defenseclaw.finding.title",
			"defenseclaw.finding.description", "defenseclaw.guardrail.evidence_summary",
			"defenseclaw.finding.location", "defenseclaw.finding.remediation",
			"defenseclaw.finding.tags", "defenseclaw.finding.data_axes",
			"defenseclaw.finding.tool_capability_class", "defenseclaw.finding.content_fingerprint",
			"defenseclaw.finding.fingerprint", "defenseclaw.finding.external_endpoint",
			"defenseclaw.finding.decision_path":
			collect(value)
		}
	}
	return needles
}

func scrubHistoricalExtensionValue(value any, needles []historicalSensitiveNeedle) (any, bool) {
	switch typed := value.(type) {
	case string:
		kind, matched := historicalSensitiveNeedleKind(typed, needles)
		if !matched {
			return value, false
		}
		return historicalRedactedJSONValue(typed, kind), true
	case []any:
		changed := false
		for index, child := range typed {
			repaired, childChanged := scrubHistoricalExtensionValue(child, needles)
			if childChanged {
				typed[index] = repaired
				changed = true
			}
		}
		return typed, changed
	case map[string]any:
		changed := false
		for key, child := range typed {
			repaired, childChanged := scrubHistoricalExtensionValue(child, needles)
			if childChanged {
				typed[key] = repaired
				changed = true
			}
		}
		return typed, changed
	default:
		return value, false
	}
}

func scrubHistoricalSensitiveFindingExtensionValue(
	value any,
	kind sensitiveFindingKind,
) (any, bool) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return value, false
		}
		repaired := historicalRedactedJSONValue(typed, kind)
		return repaired, repaired != typed
	case []any:
		changed := false
		for index, child := range typed {
			repaired, childChanged := scrubHistoricalSensitiveFindingExtensionValue(child, kind)
			if childChanged {
				typed[index] = repaired
				changed = true
			}
		}
		return typed, changed
	case map[string]any:
		changed := false
		for key, child := range typed {
			repaired, childChanged := scrubHistoricalSensitiveFindingExtensionValue(child, kind)
			if childChanged {
				typed[key] = repaired
				changed = true
			}
		}
		return typed, changed
	default:
		return value, false
	}
}

func historicalSensitiveNeedleKind(
	value string,
	needles []historicalSensitiveNeedle,
) (sensitiveFindingKind, bool) {
	trimmed := strings.TrimSpace(value)
	if isSensitiveFindingRedactionPlaceholder(trimmed) || isPIIRedactionPlaceholder(trimmed) {
		return "", false
	}
	matched := sensitiveFindingKind("")
	priority := 0
	for _, needle := range needles {
		if needle.value == "" || !historicalSensitiveNeedleMatches(value, needle.value) {
			continue
		}
		candidatePriority := 1
		if needle.kind == sensitiveFindingKindPII {
			candidatePriority = 2
		} else if needle.kind == sensitiveFindingKindSecret {
			candidatePriority = 3
		}
		if candidatePriority > priority {
			priority = candidatePriority
			matched = needle.kind
		}
	}
	return matched, priority > 0
}

func historicalSensitiveNeedleMatches(value, needle string) bool {
	if utf8.RuneCountInString(needle) >= 6 {
		return strings.Contains(value, needle)
	}

	containsTokenRune := false
	for _, current := range needle {
		if historicalSensitiveTokenRune(current) {
			containsTokenRune = true
			break
		}
	}
	if !containsTokenRune {
		return strings.TrimSpace(value) == needle
	}

	first, _ := utf8.DecodeRuneInString(needle)
	last, _ := utf8.DecodeLastRuneInString(needle)
	for searchStart := 0; searchStart <= len(value)-len(needle); {
		relative := strings.Index(value[searchStart:], needle)
		if relative < 0 {
			return false
		}
		start := searchStart + relative
		end := start + len(needle)
		leftBoundary := true
		if historicalSensitiveTokenRune(first) && start > 0 {
			previous, _ := utf8.DecodeLastRuneInString(value[:start])
			leftBoundary = !historicalSensitiveTokenRune(previous)
		}
		rightBoundary := true
		if historicalSensitiveTokenRune(last) && end < len(value) {
			next, _ := utf8.DecodeRuneInString(value[end:])
			rightBoundary = !historicalSensitiveTokenRune(next)
		}
		if leftBoundary && rightBoundary {
			return true
		}
		_, width := utf8.DecodeRuneInString(value[start:])
		searchStart = start + width
	}
	return false
}

func historicalSensitiveTokenRune(value rune) bool {
	return value == '_' || unicode.IsLetter(value) || unicode.IsNumber(value) || unicode.IsMark(value)
}

type historicalAuditEventRow struct {
	rowID                                   int64
	recordID                                string
	details, structured, payload, projected string
	projectionHash, payloadHMAC, algorithm  string
	integrityKeyID                          string
}

func scrubHistoricalAuditEventRows(ex dbExecer) error {
	present, err := tableExists(ex, "audit_events")
	if err != nil || !present {
		return err
	}
	for _, column := range []string{
		"details", "structured_json", "payload_json", "projected_record_json",
		"projection_hash", "payload_hmac", "integrity_algorithm", "integrity_key_id",
		"action", "event_name", "finding_id",
	} {
		exists, columnErr := hasColumnDB(ex, "audit_events", column)
		if columnErr != nil {
			return columnErr
		}
		if !exists {
			return fmt.Errorf("audit: audit_events.%s is missing before historical evidence repair", column)
		}
	}
	correlationObservationsPresent, err := tableExists(ex, "correlation_observations")
	if err != nil {
		return err
	}
	if correlationObservationsPresent {
		for _, column := range []string{"record_id", "projection_hash"} {
			exists, columnErr := hasColumnDB(ex, "correlation_observations", column)
			if columnErr != nil {
				return columnErr
			}
			if !exists {
				correlationObservationsPresent = false
				break
			}
		}
	}

	var cursor int64
	for {
		rows, queryErr := ex.Query(`
			SELECT rowid, id, COALESCE(details,''), COALESCE(structured_json,''),
			       COALESCE(payload_json,''), COALESCE(projected_record_json,''),
			       COALESCE(projection_hash,''), COALESCE(payload_hmac,''),
			       COALESCE(integrity_algorithm,''), COALESCE(integrity_key_id,'')
			FROM audit_events
			WHERE rowid > ? AND (
				LOWER(COALESCE(action,'')) IN ('scan-finding','scan_finding') OR
				LOWER(COALESCE(event_name,'')) = 'finding.observed' OR
				TRIM(COALESCE(finding_id,'')) <> ''
			)
			ORDER BY rowid LIMIT ?`, cursor, historicalSensitiveEvidenceBatchSize)
		if queryErr != nil {
			return fmt.Errorf("audit: query historical finding events: %w", queryErr)
		}
		batch := make([]historicalAuditEventRow, 0, historicalSensitiveEvidenceBatchSize)
		for rows.Next() {
			var row historicalAuditEventRow
			if scanErr := rows.Scan(
				&row.rowID, &row.recordID, &row.details, &row.structured, &row.payload, &row.projected,
				&row.projectionHash, &row.payloadHMAC, &row.algorithm, &row.integrityKeyID,
			); scanErr != nil {
				_ = rows.Close()
				return fmt.Errorf("audit: scan historical finding event: %w", scanErr)
			}
			batch = append(batch, row)
		}
		iterationErr := rows.Err()
		_ = rows.Close()
		if iterationErr != nil {
			return fmt.Errorf("audit: iterate historical finding events: %w", iterationErr)
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			cursor = row.rowID
			repaired, repairErr := repairHistoricalAuditEvent(row)
			if repairErr != nil {
				return repairErr
			}
			if repaired == nil {
				continue
			}
			if _, updateErr := ex.Exec(`
				UPDATE audit_events
				SET details=?, structured_json=?, payload_json=?, projected_record_json=?,
				    projection_hash=?, payload_hmac=?, integrity_algorithm=?, integrity_key_id=?
				WHERE rowid=?`,
				nullStr(repaired.details), nullStr(repaired.structured), nullStr(repaired.payload),
				nullStr(repaired.projected), nullStr(repaired.projectionHash),
				nullStr(repaired.payloadHMAC), nullStr(repaired.algorithm),
				nullStr(repaired.integrityKeyID), row.rowID,
			); updateErr != nil {
				return fmt.Errorf("audit: repair historical finding event: %w", updateErr)
			}
			if correlationObservationsPresent && repaired.projectionHash != row.projectionHash {
				if _, updateErr := ex.Exec(`
					UPDATE correlation_observations SET projection_hash=? WHERE record_id=?`,
					nullStr(repaired.projectionHash), repaired.recordID,
				); updateErr != nil {
					return fmt.Errorf("audit: repair historical finding correlation hash: %w", updateErr)
				}
			}
		}
	}
}

func repairHistoricalAuditEvent(row historicalAuditEventRow) (*historicalAuditEventRow, error) {
	structured, structuredErr := decodeHistoricalJSONObject(row.structured)
	payload, payloadErr := decodeHistoricalJSONObject(row.payload)
	projected, projectedErr := decodeHistoricalJSONObject(row.projected)
	if structuredErr != nil || payloadErr != nil || projectedErr != nil {
		return nil, fmt.Errorf("audit: decode historical finding event JSON")
	}

	flags := historicalSensitiveFindingFlags{}
	flags.merge(historicalSensitiveFlagsFromJSON(structured))
	flags.merge(historicalSensitiveFlagsFromJSON(payload))
	flags.merge(historicalSensitiveFlagsFromJSON(projected))
	flags.merge(historicalSensitiveFlagsFromDetails(row.details))
	kind, sensitive := flags.kind()
	if !sensitive {
		return nil, nil
	}

	repaired := row
	repaired.details = "sensitive finding evidence redacted"
	if structured != nil {
		historicalScrubFindingJSON(structured, kind)
		encoded, err := marshalHistoricalJSON(structured)
		if err != nil {
			return nil, fmt.Errorf("audit: encode repaired structured finding JSON: %w", err)
		}
		repaired.structured = string(encoded)
	}

	projectionChanged := false
	payloadChanged := false
	if projected != nil {
		body, ok := projected["body"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("audit: historical projected finding record has no object body")
		}
		bodyStats := historicalScrubFindingJSON(body, kind)
		classesRemoved := scrubHistoricalFindingFieldClasses(projected, body)
		if bodyStats.changed() || classesRemoved > 0 {
			projectionChanged = true
			updateHistoricalProjectionMetadata(projected, bodyStats.transformed, bodyStats.removed)
		}
		payloadEncoded, err := marshalHistoricalJSON(body)
		if err != nil {
			return nil, fmt.Errorf("audit: encode repaired projected finding body: %w", err)
		}
		if repaired.payload != string(payloadEncoded) {
			projectionChanged = true
			payloadChanged = true
		}
		repaired.payload = string(payloadEncoded)
		projectedEncoded, err := marshalHistoricalJSON(projected)
		if err != nil {
			return nil, fmt.Errorf("audit: encode repaired projected finding record: %w", err)
		}
		if repaired.projected != string(projectedEncoded) {
			projectionChanged = true
		}
		repaired.projected = string(projectedEncoded)
	} else if payload != nil {
		historicalScrubFindingJSON(payload, kind)
		encoded, err := marshalHistoricalJSON(payload)
		if err != nil {
			return nil, fmt.Errorf("audit: encode repaired finding payload JSON: %w", err)
		}
		payloadChanged = repaired.payload != string(encoded)
		repaired.payload = string(encoded)
	}

	if projectionChanged {
		digest := sha256.Sum256([]byte(repaired.projected))
		repaired.projectionHash = ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
		// Migrations execute before runtime key binding. A changed projection
		// cannot truthfully retain its old signature, so expose it as unsigned.
		repaired.payloadHMAC = ""
		repaired.algorithm = ""
		repaired.integrityKeyID = ""
	} else if payloadChanged {
		// There is no projected record from which to recompute a projection
		// digest. A changed payload cannot truthfully retain either its legacy
		// digest or signature metadata, so expose the repaired row as unsigned.
		repaired.projectionHash = ""
		repaired.payloadHMAC = ""
		repaired.algorithm = ""
		repaired.integrityKeyID = ""
	}
	if repaired == row {
		return nil, nil
	}
	return &repaired, nil
}

func historicalSensitiveFindingKind(finding scanner.Finding) (sensitiveFindingKind, bool) {
	if isLiteralCredentialFinding(finding) {
		return sensitiveFindingKindSecret, true
	}
	if isPIIFinding(finding) {
		return sensitiveFindingKindPII, true
	}
	if isTrustExploitFinding(finding) {
		return sensitiveFindingKindTrust, true
	}
	return "", false
}

func historicalSensitiveRuleIDKind(ruleID, scannerName string) (sensitiveFindingKind, bool) {
	if kind, sensitive := historicalSensitiveFindingKind(scanner.Finding{RuleID: ruleID}); sensitive {
		return kind, true
	}
	trimmed := strings.TrimSpace(ruleID)
	for _, kind := range []sensitiveFindingKind{
		sensitiveFindingKindSecret,
		sensitiveFindingKindPII,
		sensitiveFindingKindTrust,
	} {
		if _, trusted := trustedSensitiveFindingRuleID(trimmed, kind, scannerName, nil); trusted ||
			wellFormedSensitiveOpaqueRuleID(trimmed, kind) {
			return kind, true
		}
	}
	return "", false
}

func historicalRedactFinding(finding *scanner.Finding, scannerName string, kind sensitiveFindingKind) {
	if finding == nil {
		return
	}
	finding.Category = canonicalSensitiveFindingCategory(kind)
	trimmedRuleID := strings.TrimSpace(finding.RuleID)
	if trusted, ok := trustedSensitiveFindingRuleID(trimmedRuleID, kind, scannerName, nil); ok {
		finding.RuleID = trusted
	} else if wellFormedSensitiveOpaqueRuleID(trimmedRuleID, kind) {
		// A migration has no installation key with which to authenticate an
		// opaque ID. Its closed hexadecimal shape cannot carry source evidence,
		// so preserving it is safe even though it is not treated as trusted input
		// by the live persistence boundary.
		finding.RuleID = trimmedRuleID
	} else {
		finding.RuleID = "redacted." + string(kind) + ".unknown"
	}
	finding.ContentFingerprint = ""
	switch kind {
	case sensitiveFindingKindSecret:
		redactPersistedCredentialFinding(finding)
	case sensitiveFindingKindPII:
		redactPersistedPIIFinding(finding)
	case sensitiveFindingKindTrust:
		redactPersistedTrustExploitFinding(finding)
	}
}

type historicalSensitiveFindingFlags struct {
	secret, pii, trust bool
}

func (flags *historicalSensitiveFindingFlags) merge(other historicalSensitiveFindingFlags) {
	flags.secret = flags.secret || other.secret
	flags.pii = flags.pii || other.pii
	flags.trust = flags.trust || other.trust
}

func (flags historicalSensitiveFindingFlags) kind() (sensitiveFindingKind, bool) {
	if flags.secret {
		return sensitiveFindingKindSecret, true
	}
	if flags.pii {
		return sensitiveFindingKindPII, true
	}
	if flags.trust {
		return sensitiveFindingKindTrust, true
	}
	return "", false
}

func historicalSensitiveFlagsFromJSON(value any) historicalSensitiveFindingFlags {
	flags := historicalSensitiveFindingFlags{}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			finding := scanner.Finding{}
			for key, child := range typed {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "rule_id", "defenseclaw.finding.rule_id":
					finding.RuleID, _ = child.(string)
				case "id":
					finding.ID, _ = child.(string)
				case "category", "defenseclaw.finding.category":
					finding.Category, _ = child.(string)
				case "tags", "defenseclaw.finding.tags":
					finding.Tags = historicalStringsFromJSON(child)
				}
			}
			if kind, sensitive := historicalSensitiveFindingKind(finding); sensitive {
				switch kind {
				case sensitiveFindingKindSecret:
					flags.secret = true
				case sensitiveFindingKindPII:
					flags.pii = true
				case sensitiveFindingKindTrust:
					flags.trust = true
				}
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return flags
}

func historicalSensitiveFlagsFromDetails(details string) historicalSensitiveFindingFlags {
	lower := strings.ToLower(details)
	return historicalSensitiveFindingFlags{
		secret: strings.Contains(lower, "rule_id=sec-") || strings.Contains(lower, "rule_id=cs-sec-") ||
			strings.Contains(lower, "category=credential-leak"),
		pii: strings.Contains(lower, "rule_id=pii-") || strings.Contains(lower, "rule_id=cs-pii-") ||
			strings.Contains(lower, "category=pii-exposure"),
		trust: strings.Contains(lower, "rule_id=trust-") || strings.Contains(lower, "rule_id=lp-inj-") ||
			strings.Contains(lower, "category=prompt-injection"),
	}
}

type historicalJSONScrubStats struct {
	transformed int
	removed     int
}

func (stats historicalJSONScrubStats) changed() bool {
	return stats.transformed > 0 || stats.removed > 0
}

func historicalScrubFindingJSON(value any, kind sensitiveFindingKind) historicalJSONScrubStats {
	stats := historicalJSONScrubStats{}
	var walk func(any, bool)
	walk = func(current any, parentFinding bool) {
		switch typed := current.(type) {
		case map[string]any:
			findingLike := parentFinding || historicalJSONMapLooksLikeFinding(typed)
			for key, child := range typed {
				canonicalKey := strings.ToLower(strings.TrimSpace(key))
				if !findingLike {
					walk(child, canonicalKey == "finding" || canonicalKey == "findings")
					continue
				}
				switch canonicalKey {
				case "id":
					if child != "" {
						typed[key] = ""
						stats.transformed++
					}
				case "rule_id", "defenseclaw.finding.rule_id":
					want := historicalSafeRuleID(child, kind)
					if child != want {
						typed[key] = want
						stats.transformed++
					}
				case "category", "defenseclaw.finding.category":
					want := canonicalSensitiveFindingCategory(kind)
					if child != want {
						typed[key] = want
						stats.transformed++
					}
				case "title", "defenseclaw.finding.title":
					want := historicalSensitiveTitle(kind)
					if child != want {
						typed[key] = want
						stats.transformed++
					}
				case "description", "evidence", "evidence_summary", "location", "remediation",
					"external_endpoint", "defenseclaw.finding.description",
					"defenseclaw.guardrail.evidence_summary", "defenseclaw.finding.location",
					"defenseclaw.finding.remediation", "defenseclaw.finding.external_endpoint",
					"details", "structured_json", "target":
					want := historicalRedactedJSONValue(child, kind)
					if child != want {
						typed[key] = want
						stats.transformed++
					}
				case "tags", "defenseclaw.finding.tags":
					want := historicalSensitiveTags(child, kind)
					if !historicalJSONEqual(child, want) {
						typed[key] = want
						stats.transformed++
					}
				case "data_axis", "data_axes", "defenseclaw.finding.data_axes":
					want := historicalCanonicalDataAxes(child)
					if !historicalJSONEqual(child, want) {
						typed[key] = want
						stats.transformed++
					}
				case "tool_capability_class", "defenseclaw.finding.tool_capability_class":
					text, _ := child.(string)
					want := canonicalSensitiveFindingToolCapabilityClass(text)
					if child != want {
						typed[key] = want
						stats.transformed++
					}
				case "content_fingerprint", "fingerprint", "defenseclaw.finding.content_fingerprint",
					"defenseclaw.finding.fingerprint":
					delete(typed, key)
					stats.removed++
				case "decision_path", "defenseclaw.finding.decision_path":
					want := historicalRedactedDecisionValue(child, kind, strings.HasPrefix(canonicalKey, "defenseclaw."))
					if !historicalJSONEqual(child, want) {
						typed[key] = want
						stats.transformed++
					}
				default:
					if canonicalKey == "finding" || canonicalKey == "findings" {
						walk(child, true)
					} else if !historicalSafeFindingMetadataKey(canonicalKey) {
						delete(typed, key)
						stats.removed++
					}
				}
			}
		case []any:
			for _, child := range typed {
				walk(child, parentFinding)
			}
		}
	}
	// Every caller has already classified this as a finding JSON surface. Treat
	// the root as finding-owned so a legacy shape without a rule_id beside each
	// evidence field cannot retain arbitrary producer extensions.
	walk(value, true)
	return stats
}

func historicalSafeFindingMetadataKey(key string) bool {
	switch key {
	case "actor", "action", "severity", "scanner", "line_number", "confidence", "turn_id",
		"finding_occurrence_id", "defenseclaw.finding.id", "defenseclaw.finding.confidence",
		"defenseclaw.finding.line_number", "defenseclaw.finding.target_ref",
		"defenseclaw.approval.id", "defenseclaw.enforcement.id", "defenseclaw.evaluation.id",
		"defenseclaw.policy.id", "defenseclaw.policy.version", "defenseclaw.scan.id",
		"defenseclaw.scan.scanner", "defenseclaw.security.severity":
		return true
	default:
		return false
	}
}

func historicalJSONMapLooksLikeFinding(value map[string]any) bool {
	for key := range value {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "rule_id", "category", "finding_occurrence_id", "defenseclaw.finding.id",
			"defenseclaw.finding.rule_id", "defenseclaw.finding.category":
			return true
		}
	}
	return false
}

func historicalSafeRuleID(value any, kind sensitiveFindingKind) string {
	ruleID, _ := value.(string)
	trimmed := strings.TrimSpace(ruleID)
	if trusted, ok := trustedSensitiveFindingRuleID(trimmed, kind, "", nil); ok {
		return trusted
	}
	if wellFormedSensitiveOpaqueRuleID(trimmed, kind) {
		return trimmed
	}
	return "redacted." + string(kind) + ".unknown"
}

func historicalSensitiveTitle(kind sensitiveFindingKind) string {
	switch kind {
	case sensitiveFindingKindSecret:
		return redactedSecretFindingTitle
	case sensitiveFindingKindPII:
		return redactedPIIFindingTitle
	case sensitiveFindingKindTrust:
		return redactedTrustFindingTitle
	default:
		return "Sensitive finding"
	}
}

func historicalRedactedJSONValue(value any, kind sensitiveFindingKind) string {
	text, ok := value.(string)
	if !ok {
		encoded, err := marshalHistoricalJSON(value)
		if err != nil {
			text = ""
		} else {
			text = string(encoded)
		}
	}
	if kind == sensitiveFindingKindPII {
		return redactPIIFindingValue(text)
	}
	return redactCredentialFindingValue(text)
}

func historicalSensitiveTags(value any, kind sensitiveFindingKind) []any {
	detectionOnly := false
	for _, tag := range historicalStringsFromJSON(value) {
		if strings.EqualFold(strings.TrimSpace(tag), scanner.FindingTagDetectionOnly) {
			detectionOnly = true
		}
	}
	base := "secret"
	if kind == sensitiveFindingKindPII {
		base = "pii"
	} else if kind == sensitiveFindingKindTrust {
		base = "prompt-injection"
	}
	tags := []any{base}
	if detectionOnly {
		tags = append(tags, scanner.FindingTagDetectionOnly)
	}
	tags = append(tags, "redacted")
	return tags
}

func historicalCanonicalDataAxes(value any) []any {
	canonical := canonicalSensitiveFindingDataAxes(historicalStringsFromJSON(value))
	out := make([]any, 0, len(canonical))
	for _, item := range canonical {
		out = append(out, item)
	}
	return out
}

func historicalRedactedDecisionValue(value any, kind sensitiveFindingKind, canonical bool) any {
	encoded, err := marshalHistoricalJSON(value)
	if text, ok := value.(string); ok {
		encoded = []byte(text)
	}
	if err != nil || len(encoded) == 0 {
		encoded = []byte("null")
	}
	prefix := sensitiveFindingRedactionPrefix
	key := sensitiveFindingDecisionPathKey
	if kind == sensitiveFindingKindPII {
		prefix = piiFindingRedactionPrefix
		key = piiFindingDecisionPathKey
	}
	var existing map[string]any
	if decodeHistoricalJSON(encoded, &existing) == nil && len(existing) == 1 {
		if placeholder, ok := existing[key].(string); ok && isFindingRedactionPlaceholder(placeholder, prefix) {
			if !canonical {
				return existing
			}
			serialized, marshalErr := marshalHistoricalJSON(existing)
			if marshalErr == nil {
				return string(serialized)
			}
		}
	}
	placeholder := redactFindingValueWithPrefix(string(encoded), prefix)
	redacted := map[string]any{key: placeholder}
	if !canonical {
		return redacted
	}
	serialized, marshalErr := marshalHistoricalJSON(redacted)
	if marshalErr != nil {
		return ""
	}
	return string(serialized)
}

func scrubHistoricalFindingFieldClasses(projected map[string]any, body map[string]any) int {
	classes, ok := projected["field_classes"].(map[string]any)
	if !ok {
		return 0
	}
	removed := 0
	for pointer := range classes {
		if !historicalJSONPointerResolves(body, pointer) {
			delete(classes, pointer)
			removed++
		}
	}
	return removed
}

func historicalJSONPointerResolves(root any, pointer string) bool {
	if pointer == "" {
		return true
	}
	if !strings.HasPrefix(pointer, "/") {
		return false
	}
	current := root
	for _, rawToken := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[token]
		if !ok {
			return false
		}
	}
	return true
}

func updateHistoricalProjectionMetadata(projected map[string]any, transformed, removed int) {
	metadata, ok := projected["projection"].(map[string]any)
	if !ok || transformed+removed == 0 {
		return
	}
	profile, _ := metadata["redaction_profile"].(string)
	state, _ := metadata["state"].(string)
	if profile == "none" || state == "failed_closed" {
		return
	}
	metadata["state"] = "transformed"
	metadata["transformed_fields"] = historicalJSONInteger(metadata["transformed_fields"]) + int64(transformed)
	metadata["removed_fields"] = historicalJSONInteger(metadata["removed_fields"]) + int64(removed)
}

func historicalJSONInteger(value any) int64 {
	switch typed := value.(type) {
	case json.Number:
		integer, _ := typed.Int64()
		return integer
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	default:
		return 0
	}
}

func decodeHistoricalJSONObject(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var value any
	if err := decodeHistoricalJSON([]byte(raw), &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("historical JSON is not an object")
	}
	return object, nil
}

func decodeHistoricalJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("multiple JSON values")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("multiple JSON values")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func marshalHistoricalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func decodeHistoricalStringSlice(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}

func decodeHistoricalFindingTags(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func encodeHistoricalStringSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	encoded, err := marshalHistoricalJSON(values)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func historicalStringsFromJSON(value any) []string {
	typed, ok := value.([]any)
	if !ok {
		if stringsValue, stringsOK := value.([]string); stringsOK {
			return append([]string(nil), stringsValue...)
		}
		return nil
	}
	out := make([]string, 0, len(typed))
	for _, item := range typed {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func historicalJSONEqual(left, right any) bool {
	leftJSON, leftErr := marshalHistoricalJSON(left)
	rightJSON, rightErr := marshalHistoricalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
