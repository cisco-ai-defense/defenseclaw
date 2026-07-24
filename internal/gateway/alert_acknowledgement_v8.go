// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const alertAcknowledgementV8Path = "/api/v1/alerts/disposition"
const alertAcknowledgementV8Actor = "cli:operator"

const (
	alertSelectionDigestDomain  = "defenseclaw.alert-disposition.selection.v1\x00"
	alertDatabaseIdentityDomain = "defenseclaw.alert-disposition.audit-db.v1\x00"
	alertDigestPrefix           = "sha256:v1:"
	maxAlertSelectorIDs         = 1000
	maxAlertRequestBytes        = 64 * 1024
)

type alertAcknowledgementV8Runtime interface {
	ApplyAlertAcknowledgement(
		context.Context,
		audit.AlertAcknowledgementCommand,
	) (audit.AlertAcknowledgementResult, error)
}

type alertAcknowledgementV8Request struct {
	OperationID     string                         `json:"operation_id"`
	AuditDBIdentity string                         `json:"audit_db_identity"`
	Disposition     string                         `json:"disposition"`
	Selector        alertAcknowledgementV8Selector `json:"selector"`
	Preview         bool                           `json:"preview"`
	SelectionDigest string                         `json:"selection_digest,omitempty"`
}

type alertAcknowledgementV8Selector struct {
	IDs       []string `json:"ids,omitempty"`
	Connector string   `json:"connector,omitempty"`
	Target    string   `json:"target,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Since     string   `json:"since,omitempty"`
	Before    string   `json:"before,omitempty"`
}

type alertAcknowledgementV8Target struct {
	ID                string `json:"id"`
	ProjectionVersion int64  `json:"projection_version"`
}

type alertAcknowledgementV8Failure struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

type alertAcknowledgementV8Response struct {
	Matched         int                             `json:"matched"`
	Applied         int                             `json:"applied"`
	NoChange        int                             `json:"no_change"`
	Rejected        int                             `json:"rejected"`
	Failed          int                             `json:"failed"`
	SelectionDigest string                          `json:"selection_digest,omitempty"`
	Targets         []alertAcknowledgementV8Target  `json:"targets,omitempty"`
	Failures        []alertAcknowledgementV8Failure `json:"failures,omitempty"`
	Drift           bool                            `json:"drift,omitempty"`
	Error           string                          `json:"error,omitempty"`
}

func (a *APIServer) handleAlertAcknowledgementV8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.store == nil {
		http.Error(w, `{"error":"canonical alert runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	request, err := decodeAlertAcknowledgementV8Request(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid alert disposition request"}`, http.StatusBadRequest)
		return
	}
	expectedIdentity, err := alertAuditDatabaseIdentity(a.store.DatabasePath())
	if err != nil {
		http.Error(w, `{"error":"canonical alert runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.AuditDBIdentity), []byte(expectedIdentity)) != 1 {
		a.writeJSON(w, http.StatusConflict, alertAcknowledgementV8Response{
			Error: "audit database identity mismatch",
		})
		return
	}
	storeSelector := auditAlertAcknowledgementSelector(request.Selector)
	targets, err := a.store.SelectAlertAcknowledgementTargets(r.Context(), storeSelector)
	if err != nil {
		http.Error(w, `{"error":"alert disposition unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	digest, err := alertSelectionDigest(request.Selector, targets)
	if err != nil {
		http.Error(w, `{"error":"alert disposition unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	response := alertAcknowledgementV8Response{
		Matched: len(targets), SelectionDigest: digest,
	}
	for _, target := range targets {
		response.Targets = append(response.Targets, alertAcknowledgementV8Target{
			ID: target.AlertID, ProjectionVersion: target.ProjectionVersion,
		})
	}
	if len(request.Selector.IDs) > 0 && len(targets) != len(request.Selector.IDs) {
		response.Error = "one or more exact alert IDs are unavailable"
		a.writeJSON(w, http.StatusConflict, response)
		return
	}
	if request.Preview {
		a.writeJSON(w, http.StatusOK, response)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.SelectionDigest), []byte(digest)) != 1 {
		response.Drift = true
		response.Error = "alert selection changed after preview"
		a.writeJSON(w, http.StatusConflict, response)
		return
	}
	canonicalRuntime, ok := a.observabilityV8RuntimeEmitter().(alertAcknowledgementV8Runtime)
	if !ok || canonicalRuntime == nil {
		response.Failed = response.Matched
		response.Error = "canonical alert runtime unavailable"
		a.writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}
	disposition := audit.AlertDisposition(request.Disposition)
	response = applyAlertAcknowledgementV8Targets(
		r.Context(), canonicalRuntime, request, targets, response, disposition,
	)
	response.Targets = nil
	status := alertAcknowledgementV8Status(response)
	if response.Failed > 0 {
		response.Error = "one or more alert dispositions failed"
	} else if response.Rejected > 0 {
		response.Error = "one or more alert dispositions were rejected"
	}
	a.writeJSON(w, status, response)
}

func applyAlertAcknowledgementV8Targets(
	ctx context.Context,
	runtime alertAcknowledgementV8Runtime,
	request alertAcknowledgementV8Request,
	targets []audit.AlertAcknowledgementTarget,
	response alertAcknowledgementV8Response,
	disposition audit.AlertDisposition,
) alertAcknowledgementV8Response {
	for _, target := range targets {
		result, applyErr := runtime.ApplyAlertAcknowledgement(ctx, audit.AlertAcknowledgementCommand{
			OperationID: derivedAlertOperationID(request.OperationID, target.AlertID),
			AlertID:     target.AlertID, Actor: alertAcknowledgementV8Actor, Disposition: disposition,
			ExpectedProjectionVersion: target.ProjectionVersion,
		})
		if applyErr != nil {
			response.Failed++
			response.Failures = append(response.Failures, alertAcknowledgementV8Failure{
				ID: target.AlertID, Code: "unavailable",
			})
			continue
		}
		switch result.Outcome {
		case audit.AlertAcknowledgementApplied:
			response.Applied++
		case audit.AlertAcknowledgementNoChange:
			response.NoChange++
		case audit.AlertAcknowledgementRejected:
			response.Rejected++
			code := string(result.RejectionReason)
			if code == "" {
				code = "rejected"
			}
			response.Failures = append(response.Failures, alertAcknowledgementV8Failure{
				ID: target.AlertID, Code: code,
			})
		default:
			response.Failed++
			response.Failures = append(response.Failures, alertAcknowledgementV8Failure{
				ID: target.AlertID, Code: "invalid_outcome",
			})
		}
	}
	return response
}

func alertAcknowledgementV8Status(response alertAcknowledgementV8Response) int {
	if response.Failed > 0 {
		return http.StatusServiceUnavailable
	}
	if response.Rejected > 0 {
		return http.StatusConflict
	}
	return http.StatusOK
}

func decodeAlertAcknowledgementV8Request(body io.Reader) (alertAcknowledgementV8Request, error) {
	if body == nil {
		return alertAcknowledgementV8Request{}, errors.New("missing body")
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxAlertRequestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxAlertRequestBytes || !cliObservabilityV8JSONHasUniqueKeys(raw) {
		return alertAcknowledgementV8Request{}, errors.New("invalid body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request alertAcknowledgementV8Request
	if err := decoder.Decode(&request); err != nil {
		return alertAcknowledgementV8Request{}, errors.New("invalid body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return alertAcknowledgementV8Request{}, errors.New("trailing body")
	}
	if !observability.IsStableToken(request.OperationID) || len(request.OperationID) > 192 {
		return alertAcknowledgementV8Request{}, errors.New("invalid identifiers")
	}
	if request.Disposition != string(audit.AlertDispositionAcknowledged) &&
		request.Disposition != string(audit.AlertDispositionDismissed) {
		return alertAcknowledgementV8Request{}, errors.New("invalid disposition")
	}
	if !validAlertDigest(request.AuditDBIdentity) {
		return alertAcknowledgementV8Request{}, errors.New("invalid database identity")
	}
	if request.Preview {
		if request.SelectionDigest != "" {
			return alertAcknowledgementV8Request{}, errors.New("preview includes digest")
		}
	} else if !validAlertDigest(request.SelectionDigest) {
		return alertAcknowledgementV8Request{}, errors.New("invalid selection digest")
	}
	normalized, err := normalizeAlertAcknowledgementV8Selector(request.Selector)
	if err != nil {
		return alertAcknowledgementV8Request{}, err
	}
	request.Selector = normalized
	return request, nil
}

func normalizeAlertAcknowledgementV8Selector(
	selector alertAcknowledgementV8Selector,
) (alertAcknowledgementV8Selector, error) {
	if len(selector.IDs) > maxAlertSelectorIDs {
		return alertAcknowledgementV8Selector{}, errors.New("too many alert IDs")
	}
	ids := make([]string, 0, len(selector.IDs))
	for _, rawID := range selector.IDs {
		alertID := strings.TrimSpace(rawID)
		if !observability.IsStableToken(alertID) || len(alertID) > 192 {
			return alertAcknowledgementV8Selector{}, errors.New("invalid alert ID")
		}
		ids = append(ids, alertID)
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		deduplicated := ids[:0]
		for _, alertID := range ids {
			if len(deduplicated) == 0 || deduplicated[len(deduplicated)-1] != alertID {
				deduplicated = append(deduplicated, alertID)
			}
		}
		ids = deduplicated
	}
	connector := strings.ToLower(strings.TrimSpace(selector.Connector))
	target := strings.TrimSpace(selector.Target)
	severity := strings.ToUpper(strings.TrimSpace(selector.Severity))
	if severity == "ALL" {
		severity = ""
	}
	if !validAlertSelectorText(connector, 128) || !validAlertSelectorText(target, 1024) {
		return alertAcknowledgementV8Selector{}, errors.New("invalid selector text")
	}
	switch severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "INFO":
	default:
		return alertAcknowledgementV8Selector{}, errors.New("invalid severity")
	}
	since, sinceValue, err := normalizeAlertSelectorTime(selector.Since)
	if err != nil {
		return alertAcknowledgementV8Selector{}, err
	}
	before, beforeValue, err := normalizeAlertSelectorTime(selector.Before)
	if err != nil {
		return alertAcknowledgementV8Selector{}, err
	}
	if !sinceValue.IsZero() && !beforeValue.IsZero() && !sinceValue.Before(beforeValue) {
		return alertAcknowledgementV8Selector{}, errors.New("invalid time range")
	}
	if len(ids) > 0 && (connector != "" || target != "" || severity != "" || since != "" || before != "") {
		return alertAcknowledgementV8Selector{}, errors.New("exact IDs cannot be combined with broad selectors")
	}
	return alertAcknowledgementV8Selector{
		IDs: ids, Connector: connector, Target: target, Severity: severity,
		Since: since, Before: before,
	}, nil
}

func normalizeAlertSelectorTime(value string) (string, time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", time.Time{}, errors.New("invalid selector timestamp")
	}
	parsed = parsed.UTC()
	return parsed.Format(time.RFC3339Nano), parsed, nil
}

func validAlertSelectorText(value string, maximum int) bool {
	if !utf8.ValidString(value) || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func auditAlertAcknowledgementSelector(selector alertAcknowledgementV8Selector) audit.AlertAcknowledgementSelector {
	result := audit.AlertAcknowledgementSelector{
		AlertIDs: selector.IDs, Connector: selector.Connector,
		Target: selector.Target, Severity: selector.Severity,
	}
	if selector.Since != "" {
		result.Since, _ = time.Parse(time.RFC3339Nano, selector.Since)
	}
	if selector.Before != "" {
		result.Before, _ = time.Parse(time.RFC3339Nano, selector.Before)
	}
	return result
}

func alertSelectionDigest(
	selector alertAcknowledgementV8Selector,
	targets []audit.AlertAcknowledgementTarget,
) (string, error) {
	material := struct {
		Selector alertAcknowledgementV8Selector `json:"selector"`
		Targets  []alertAcknowledgementV8Target `json:"targets"`
	}{Selector: selector}
	for _, target := range targets {
		material.Targets = append(material.Targets, alertAcknowledgementV8Target{
			ID: target.AlertID, ProjectionVersion: target.ProjectionVersion,
		})
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(alertSelectionDigestDomain))
	_, _ = digest.Write(encoded)
	return alertDigestPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}

func alertAuditDatabaseIdentity(path string) (string, error) {
	normalized, err := normalizeAlertAuditDatabasePath(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(alertDatabaseIdentityDomain))
	_, _ = digest.Write([]byte(normalized))
	return alertDigestPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}

func normalizeAlertAuditDatabasePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty audit database path")
	}
	normalized := ":memory:"
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		resolved, resolveErr := filepath.EvalSymlinks(absolute)
		if resolveErr == nil {
			absolute = resolved
		} else if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		normalized = filepath.ToSlash(filepath.Clean(absolute))
		if runtime.GOOS == "windows" {
			normalized = strings.ToLower(normalized)
		}
	}
	return normalized, nil
}

func validAlertDigest(value string) bool {
	if !strings.HasPrefix(value, alertDigestPrefix) || len(value) != len(alertDigestPrefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, alertDigestPrefix))
	return err == nil
}

func derivedAlertOperationID(base, alertID string) string {
	digest := sha256.Sum256([]byte(alertID))
	return base + "-" + hex.EncodeToString(digest[:8])
}
