// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// CodeEndpointHealthDegraded warns that the gateway's last endpoint health
// report is degraded or unhealthy, or is stale. Status only; it never makes a
// result fail.
const CodeEndpointHealthDegraded = "endpoint_health_degraded"

// Health report read errors: bounded codes, never raw error text.
const (
	// HealthReportUnreadable: the file is not a regular file (a link, a
	// directory), is larger than the read limit, or could not be read.
	HealthReportUnreadable = "unreadable"
	// HealthReportAccessDenied: the account running status cannot read it.
	HealthReportAccessDenied = "access_denied"
	// HealthReportInvalid: not JSON, another schema version, or a required
	// report field missing or out of range.
	HealthReportInvalid = "invalid"
)

// healthReportMaxBytes bounds the read; the writer caps the file at
// diagnostics.MaxFileBytes.
const healthReportMaxBytes = 512 << 10

// healthReportStaleIntervals is how many report intervals may pass after the
// last report before status calls it stale.
const healthReportStaleIntervals = 3

// healthReportDefaultInterval is used when the report names no interval: the
// managed reporter never reports less often than this.
const healthReportDefaultInterval = 30 * time.Minute

// healthReportMaxReasonCodes bounds reason_codes.
const healthReportMaxReasonCodes = 32

var (
	healthReasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	healthTriggerPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	healthClassPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// HealthReportState is the status "health_report" block: a summary of the
// last endpoint health report the managed gateway built and wrote to
// <data_dir>/diagnostics/health_report_last.json. Codes, enums, counts and
// times only. Error is set, and every other field empty, when the file exists
// but cannot be used.
type HealthReportState struct {
	// Status: healthy, degraded, unhealthy or starting.
	Status string `json:"status,omitempty"`
	// ObservedAt is when the report was built (RFC 3339 UTC).
	ObservedAt string `json:"observed_at,omitempty"`
	Sequence   uint64 `json:"sequence,omitempty"`
	// Trigger: startup, scheduled or config_reload.
	Trigger string `json:"trigger,omitempty"`
	// ReasonCodes are the report's distinct reason codes, in report order.
	ReasonCodes []string `json:"reason_codes,omitempty"`
	// BuiltAt is when the gateway wrote the file (RFC 3339 UTC).
	BuiltAt  string                `json:"built_at,omitempty"`
	Delivery *HealthReportDelivery `json:"delivery,omitempty"`
	// Stale is true when more than three report intervals have passed since
	// ObservedAt: the gateway has stopped reporting.
	Stale bool   `json:"stale"`
	Error string `json:"error,omitempty"`
}

// HealthReportDelivery is how the gateway handed the report to Cisco AI
// Defense: result queued, not_routed or failed, with a failure class code.
type HealthReportDelivery struct {
	Result       string `json:"result"`
	At           string `json:"at,omitempty"`
	FailureClass string `json:"failure_class,omitempty"`
	CloudState   string `json:"cloud_state,omitempty"`
}

// healthReportBody is the part of the report body status reads.
type healthReportBody struct {
	Status          *string `json:"defenseclaw.health.status"`
	ObservedAt      *string `json:"defenseclaw.health.observed_at"`
	Sequence        uint64  `json:"defenseclaw.health.sequence"`
	Trigger         string  `json:"defenseclaw.health.trigger"`
	ReportIntervalS int64   `json:"defenseclaw.health.report_interval_s"`
	Reasons         []struct {
		Code string `json:"code"`
	} `json:"defenseclaw.health.reasons"`
}

// ReadHealthReport reads the last endpoint health report under dataDir. It
// returns nil when there is no report (the reporter is not active on this
// deployment, or has not reported yet). A report that exists but cannot be
// used is returned with Error set. It never follows a link, never reads more
// than 512 KiB, and never fails the caller.
func ReadHealthReport(dataDir string, now time.Time) *HealthReportState {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	path := diagnostics.Path(dataDir, diagnostics.HealthReportFile)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	data, err := safefile.ReadRegularFileBounded(path, healthReportMaxBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case errors.Is(err, fs.ErrPermission):
		return &HealthReportState{Error: HealthReportAccessDenied}
	case err != nil:
		return &HealthReportState{Error: HealthReportUnreadable}
	}
	return parseHealthReport(data, now)
}

func parseHealthReport(data []byte, now time.Time) *HealthReportState {
	invalid := &HealthReportState{Error: HealthReportInvalid}
	var content diagnostics.HealthReportFileContent
	if err := json.Unmarshal(data, &content); err != nil || content.SchemaVersion != diagnostics.HealthReportFileVersion {
		return invalid
	}
	var body healthReportBody
	if len(content.Report) == 0 || json.Unmarshal(content.Report, &body) != nil {
		return invalid
	}
	if body.Status == nil || body.ObservedAt == nil {
		return invalid
	}
	switch *body.Status {
	case "healthy", "degraded", "unhealthy", "starting":
	default:
		return invalid
	}
	observed, ok := healthReportTime(*body.ObservedAt)
	if !ok {
		return invalid
	}
	state := &HealthReportState{
		Status:     *body.Status,
		ObservedAt: observed.Format(time.RFC3339),
		Sequence:   body.Sequence,
	}
	if healthTriggerPattern.MatchString(body.Trigger) {
		state.Trigger = body.Trigger
	}
	for _, reason := range body.Reasons {
		if len(state.ReasonCodes) == healthReportMaxReasonCodes {
			break
		}
		if healthReasonCodePattern.MatchString(reason.Code) && !slices.Contains(state.ReasonCodes, reason.Code) {
			state.ReasonCodes = append(state.ReasonCodes, reason.Code)
		}
	}
	if built, ok := healthReportTime(content.BuiltAt); ok {
		state.BuiltAt = built.Format(time.RFC3339)
	}
	state.Delivery = healthReportDelivery(content.Delivery)

	interval := time.Duration(body.ReportIntervalS) * time.Second
	if body.ReportIntervalS <= 0 || body.ReportIntervalS > int64(365*24*time.Hour/time.Second) {
		interval = healthReportDefaultInterval
	}
	state.Stale = now.Sub(observed) > healthReportStaleIntervals*interval
	return state
}

func healthReportDelivery(delivery diagnostics.HealthDelivery) *HealthReportDelivery {
	switch delivery.Result {
	case "queued", "not_routed", "failed":
	default:
		return nil
	}
	out := &HealthReportDelivery{Result: delivery.Result}
	if at, ok := healthReportTime(delivery.At); ok {
		out.At = at.Format(time.RFC3339)
	}
	if healthClassPattern.MatchString(delivery.FailureClass) {
		out.FailureClass = delivery.FailureClass
	}
	if healthClassPattern.MatchString(delivery.CloudState) {
		out.CloudState = delivery.CloudState
	}
	return out
}

func healthReportTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

// NeedsAttention reports whether the report is degraded, unhealthy or stale.
// A report that could not be read (Error) is reported in the block only.
func (s *HealthReportState) NeedsAttention() bool {
	if s == nil || s.Error != "" {
		return false
	}
	return s.Stale || s.Status == "degraded" || s.Status == "unhealthy" || s.deliveryFailed()
}

// deliveryFailed reports a last report that did not reach the managed
// destination.
func (s *HealthReportState) deliveryFailed() bool {
	return s != nil && s.Delivery != nil && (s.Delivery.Result == "failed" || s.Delivery.Result == "not_routed")
}

// Summary is the one-line text form, such as
// "degraded (HOOKS_PARTIAL) at 2026-11-12T10:00:00Z, delivery queued";
// "" for nil.
func (s *HealthReportState) Summary() string {
	if s == nil {
		return ""
	}
	if s.Error != "" {
		return s.Error
	}
	line := s.Status
	if len(s.ReasonCodes) > 0 {
		line += " (" + strings.Join(s.ReasonCodes, ", ") + ")"
	}
	line += " at " + s.ObservedAt
	if s.Delivery != nil {
		line += ", delivery " + s.Delivery.Result
		if s.Delivery.FailureClass != "" {
			line += " (" + s.Delivery.FailureClass + ")"
		}
	}
	if s.Stale {
		line += ", stale"
	}
	return line
}

// SetHealthReport puts state in the result's health_report block and, when
// it is degraded, unhealthy or stale, adds one endpoint_health_degraded
// warning naming its status and reason codes. It never adds an error, so OK
// and the exit code do not change. nil leaves the result as it is.
func (r *Result) SetHealthReport(state *HealthReportState) {
	if r == nil || state == nil {
		return
	}
	r.HealthReport = state
	if !state.NeedsAttention() {
		return
	}
	message := "the last endpoint health report is " + state.Status
	if len(state.ReasonCodes) > 0 {
		message += " (" + strings.Join(state.ReasonCodes, ", ") + ")"
	}
	if state.Stale {
		message += " and stale: the gateway has not reported for more than three report intervals"
	}
	if state.deliveryFailed() {
		message += "; it was not delivered to Cisco AI Defense (" + state.Delivery.Result + ")"
	}
	r.AddWarning(CodeEndpointHealthDegraded, message)
}
