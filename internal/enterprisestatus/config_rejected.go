// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A lifecycle run that was given a config and failed (Windows Setup /ensure
// CONFIG=, ensure, install or upgrade with --config) rolls the deployment
// back to the config it ran before. Its own result says so, but the next
// status and verify read only the deployment, which matches its record, so
// they reported ok and coverage_complete as if the requested config were
// applied (rel-1-0-10 GAP-1027). The failed run therefore records the
// rejection, and status warns and verify fails with config_rejected while
// the deployment still runs the config it ran when the request failed. Linux
// and macOS report an in-place edit the same way from the kept
// rejected-config.yaml (internal/enterpriseunix/committed_config.go); this
// file is the Windows record and the rule shared by every platform.
//
// The record holds digests, closed codes and a time, never config bytes,
// messages or account names: the full result of the failed run is in the
// lifecycle log. It lives beside deployment.json with its access control,
// so only the lifecycle can write it; a record another writer planted could
// only make status stricter.

// CodeConfigRejected is the status warning and verify error of a requested
// config that is not applied. Linux and macOS use the same code.
const CodeConfigRejected = "config_rejected"

// ConfigRejectedFileName is the record, next to deployment.json.
const ConfigRejectedFileName = "config-rejected.json"

// ConfigRejectedMaxBytes bounds a read of the record.
const ConfigRejectedMaxBytes = 16 << 10

const (
	configRejectedSchema   = 1
	maxConfigRejectedCodes = 8
)

// The closed causes of a rejected config.
const (
	// ConfigRejectedCauseRouteConfigDrift: the hook guardian did not render
	// the route-only hooks the requested config asks for, so the run could
	// not verify coverage and rolled back.
	ConfigRejectedCauseRouteConfigDrift = "route_config_drift"
	// ConfigRejectedCauseRefused: the run refused the config before it
	// changed anything.
	ConfigRejectedCauseRefused = "config_refused"
	// ConfigRejectedCauseTransactionFailed: any other failure of the run
	// that applied the config; the transaction rolled back.
	ConfigRejectedCauseTransactionFailed = "transaction_failed"
)

var (
	configRejectedSHA  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	configRejectedCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// ConfigRejectedRecord is config-rejected.json.
type ConfigRejectedRecord struct {
	SchemaVersion int `json:"schema_version"`
	// Action is the lifecycle action that failed: ensure, install, upgrade
	// or repair.
	Action string `json:"action"`
	// RejectedAt is RFC 3339 UTC.
	RejectedAt string `json:"rejected_at"`
	ExitCode   int    `json:"exit_code"`
	Cause      string `json:"cause"`
	// ErrorCodes are the codes of the failed run's errors, in order, at most
	// eight; the lifecycle log has their messages.
	ErrorCodes            []string `json:"error_codes"`
	RequestedConfigSHA256 string   `json:"requested_config_sha256"`
	// InstalledConfigSHA256 is the config.yaml the deployment ran before and
	// after the failed run. The record is current only while config.yaml
	// still has these bytes.
	InstalledConfigSHA256 string `json:"installed_config_sha256"`
}

// ConfigRejectedDecision is what a finished lifecycle run does with the
// record.
type ConfigRejectedDecision int

const (
	// ConfigRejectedKeep leaves the record as it is.
	ConfigRejectedKeep ConfigRejectedDecision = iota
	// ConfigRejectedWrite records this run's rejection.
	ConfigRejectedWrite
	// ConfigRejectedClear removes the record: the run applied or confirmed
	// the config it was given.
	ConfigRejectedClear
)

// DecideConfigRejected is the rule for a finished run that was given a
// config with digest requested (empty: no config, nothing changes).
// atStart and now are the installed config.yaml digests before and after
// the run ("" when unreadable). failureExit is the platform's generic
// failure code (1603 on Windows, 1 on Linux and macOS): a busy or
// invalid-arguments result, a pending transaction and a run that left
// nothing installed keep the record as it is. A failed run records only
// when config.yaml is what it was at the start and is not the requested
// config, so a run that failed after it applied the config records nothing.
func DecideConfigRejected(r *Result, requested, atStart, now string, failureExit int) ConfigRejectedDecision {
	if r == nil || requested == "" || !r.Installed || r.TransactionPending {
		return ConfigRejectedKeep
	}
	if len(r.Errors) == 0 && r.ExitCode == ExitOK {
		return ConfigRejectedClear
	}
	if r.ExitCode != failureExit || atStart == "" || now == "" || now != atStart || requested == now {
		return ConfigRejectedKeep
	}
	return ConfigRejectedWrite
}

// NewConfigRejectedRecord is the record of the failed run r.
func NewConfigRejectedRecord(r *Result, requested, installed string, at time.Time) ConfigRejectedRecord {
	record := ConfigRejectedRecord{
		SchemaVersion:         configRejectedSchema,
		Action:                r.Action,
		RejectedAt:            at.UTC().Format(time.RFC3339),
		ExitCode:              r.ExitCode,
		Cause:                 configRejectedCause(r),
		ErrorCodes:            []string{},
		RequestedConfigSHA256: requested,
		InstalledConfigSHA256: installed,
	}
	for _, message := range r.Errors {
		if len(record.ErrorCodes) == maxConfigRejectedCodes {
			break
		}
		if configRejectedCode.MatchString(message.Code) && !containsCode(record.ErrorCodes, message.Code) {
			record.ErrorCodes = append(record.ErrorCodes, message.Code)
		}
	}
	return record
}

func containsCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

// configRejectedCause picks the closed cause of a failed run.
func configRejectedCause(r *Result) string {
	for _, message := range r.Errors {
		if message.Code == ConfigRejectedCauseRouteConfigDrift || strings.Contains(message.Message, ConfigRejectedCauseRouteConfigDrift+":") {
			return ConfigRejectedCauseRouteConfigDrift
		}
	}
	if r.ConfigRefused {
		return ConfigRejectedCauseRefused
	}
	return ConfigRejectedCauseTransactionFailed
}

// Marshal is the record file's bytes.
func (c ConfigRejectedRecord) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseConfigRejectedRecord decodes and checks a record.
func ParseConfigRejectedRecord(raw []byte) (*ConfigRejectedRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record ConfigRejectedRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ConfigRejectedFileName, err)
	}
	switch {
	case record.SchemaVersion != configRejectedSchema:
		return nil, fmt.Errorf("%s has schema_version %d, want %d", ConfigRejectedFileName, record.SchemaVersion, configRejectedSchema)
	case !configRejectedSHA.MatchString(record.RequestedConfigSHA256) || !configRejectedSHA.MatchString(record.InstalledConfigSHA256):
		return nil, errors.New(ConfigRejectedFileName + " does not hold two sha256 config digests")
	case record.Cause != ConfigRejectedCauseRouteConfigDrift && record.Cause != ConfigRejectedCauseRefused && record.Cause != ConfigRejectedCauseTransactionFailed:
		return nil, errors.New(ConfigRejectedFileName + " names an unknown cause")
	case !configRejectedCode.MatchString(record.Action):
		return nil, errors.New(ConfigRejectedFileName + " names no action")
	}
	if _, err := time.Parse(time.RFC3339, record.RejectedAt); err != nil {
		return nil, fmt.Errorf("%s has no valid rejected_at: %w", ConfigRejectedFileName, err)
	}
	if len(record.ErrorCodes) > maxConfigRejectedCodes {
		return nil, errors.New(ConfigRejectedFileName + " lists too many error codes")
	}
	for _, code := range record.ErrorCodes {
		if !configRejectedCode.MatchString(code) {
			return nil, errors.New(ConfigRejectedFileName + " lists an invalid error code")
		}
	}
	return &record, nil
}

// Current reports whether the deployment still runs the config it ran when
// the request failed: installed is the digest of config.yaml now.
func (c *ConfigRejectedRecord) Current(installed string) bool {
	return c != nil && installed != "" && installed == c.InstalledConfigSHA256
}

// configRejectedFix is the next step for each cause; retry is the command
// that applies the config again.
func configRejectedFix(cause, retry string) string {
	switch cause {
	case ConfigRejectedCauseRouteConfigDrift:
		return "the hook guardian did not render the route-only hooks the config asks for, so the run could not verify coverage and rolled back; the gateway log says why the route epoch was not published. Fix that, then run " + retry
	case ConfigRejectedCauseRefused:
		return "the run refused the config before it changed anything; its errors name the setting. Correct the config, then run " + retry
	}
	return "the lifecycle transaction failed and rolled back; its first error says why. Fix that, then run " + retry
}

func shortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// Message is the config_rejected text. retry is the command that applies
// the config again; logPath is where the failed run's full result is.
func (c *ConfigRejectedRecord) Message(retry, logPath string) string {
	codes := "none recorded"
	if len(c.ErrorCodes) > 0 {
		codes = strings.Join(c.ErrorCodes, ", ")
	}
	message := fmt.Sprintf("the config requested at %s (sha256 %s) is not applied: the %s that applied it failed (cause %s; errors %s; exit %d), so the deployment runs the previous config (sha256 %s). Fix: %s",
		c.RejectedAt, shortDigest(c.RequestedConfigSHA256), c.Action, c.Cause, codes, c.ExitCode, shortDigest(c.InstalledConfigSHA256), configRejectedFix(c.Cause, retry))
	if logPath != "" {
		message += ". The lifecycle log " + logPath + " has the full result of that run"
	}
	return message
}

// ApplyConfigRejected reports a current record on a status or verify
// result: status warns, verify fails, and coverage_complete (with
// security_complete) is false either way, because the coverage the
// requested config asks for is not in place. installed is the config.yaml
// digest now. A record that cannot be read is the stricter outcome too: it
// is reported, with how to settle it, instead of being taken as absent.
func (r *Result) ApplyConfigRejected(raw []byte, installed, retry, logPath string) {
	if r == nil || raw == nil || (r.Action != "status" && r.Action != "verify") {
		return
	}
	record, err := ParseConfigRejectedRecord(raw)
	var message string
	switch {
	case err != nil:
		message = "a record of a rejected config cannot be read (" + err.Error() + "), so the last requested config may not be applied; run " + retry + " to apply it again and settle the record"
	case !record.Current(installed):
		return
	default:
		message = record.Message(retry, logPath)
	}
	if r.Action == "verify" {
		r.AddError(CodeConfigRejected, message)
	} else {
		r.AddWarning(CodeConfigRejected, message)
	}
	r.MarkCoverageIncomplete(CodeConfigRejected)
}
