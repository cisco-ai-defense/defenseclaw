// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
	"time"
)

const (
	gap1027Requested = "1111111111111111111111111111111111111111111111111111111111111111"
	gap1027Baseline  = "2222222222222222222222222222222222222222222222222222222222222222"
	gap1027Other     = "3333333333333333333333333333333333333333333333333333333333333333"
)

// gap1027FailedEnsure is the rel-1-0-10 GAP-1027 run: Setup /ensure with a
// routing config ended 1603 route_config_drift and rolled back.
func gap1027FailedEnsure() *Result {
	r := New("ensure", "standalone", "windows", "1.0.10")
	r.Installed = true
	r.AddError("lifecycle_error", `guardian SCM process is running but protected target coverage is not verified: claudecode@HOST\dcw-std1 (S-1-5-21-1-2-3-1017): enterprise hooks: route_config_drift: claudecode route-only is expected for this account but not rendered`)
	r.AddError("lifecycle_error", "a second error with the same code")
	r.Finish("windows", 0)
	return r
}

func TestGAP1027DecideConfigRejected(t *testing.T) {
	ok := New("ensure", "standalone", "windows", "1.0.10")
	ok.Installed = true
	ok.Finish("windows", 0)
	busy := New("ensure", "standalone", "windows", "1.0.10")
	busy.Installed = true
	busy.AddError("lifecycle_busy", "another run holds the lock")
	busy.Finish("windows", WindowsExitBusy)
	pending := gap1027FailedEnsure()
	pending.TransactionPending = true
	gone := gap1027FailedEnsure()
	gone.Installed = false
	for _, tc := range []struct {
		name                    string
		r                       *Result
		requested, atStart, now string
		want                    ConfigRejectedDecision
	}{
		{"rolled back to the baseline records", gap1027FailedEnsure(), gap1027Requested, gap1027Baseline, gap1027Baseline, ConfigRejectedWrite},
		{"success clears", ok, gap1027Requested, gap1027Baseline, gap1027Requested, ConfigRejectedClear},
		{"no config supplied keeps", gap1027FailedEnsure(), "", gap1027Baseline, gap1027Baseline, ConfigRejectedKeep},
		{"failed after it applied the config keeps", gap1027FailedEnsure(), gap1027Requested, gap1027Baseline, gap1027Other, ConfigRejectedKeep},
		{"requested config is the running one keeps", gap1027FailedEnsure(), gap1027Baseline, gap1027Baseline, gap1027Baseline, ConfigRejectedKeep},
		{"unreadable config keeps", gap1027FailedEnsure(), gap1027Requested, "", "", ConfigRejectedKeep},
		{"busy keeps", busy, gap1027Requested, gap1027Baseline, gap1027Baseline, ConfigRejectedKeep},
		{"pending transaction keeps", pending, gap1027Requested, gap1027Baseline, gap1027Baseline, ConfigRejectedKeep},
		{"nothing installed keeps", gone, gap1027Requested, gap1027Baseline, gap1027Baseline, ConfigRejectedKeep},
	} {
		if got := DecideConfigRejected(tc.r, tc.requested, tc.atStart, tc.now); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestGAP1027ConfigRejectedRecordHasNoAccountsAndAClosedCause(t *testing.T) {
	at := time.Date(2026, 11, 16, 8, 57, 48, 0, time.UTC)
	record := NewConfigRejectedRecord(gap1027FailedEnsure(), gap1027Requested, gap1027Baseline, at)
	if record.Cause != ConfigRejectedCauseRouteConfigDrift || record.ExitCode != WindowsExitFailure ||
		strings.Join(record.ErrorCodes, ",") != "lifecycle_error" || record.RejectedAt != "2026-11-16T08:57:48Z" {
		t.Fatalf("record = %+v", record)
	}
	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"dcw-std1", "S-1-5-21", "HOST", "guardian SCM"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("record carries %q: %s", leak, raw)
		}
	}
	parsed, err := ParseConfigRejectedRecord(raw)
	if err != nil || parsed.Cause != record.Cause || !parsed.Current(gap1027Baseline) || parsed.Current(gap1027Requested) || parsed.Current("") {
		t.Fatalf("parse = %+v, %v", parsed, err)
	}

	refused := New("ensure", "standalone", "windows", "1.0.10")
	refused.Installed, refused.ConfigRefused = true, true
	refused.AddError("preflight_failed", "the gateway cannot load the config")
	if got := NewConfigRejectedRecord(refused, gap1027Requested, gap1027Baseline, at).Cause; got != ConfigRejectedCauseRefused {
		t.Errorf("refused cause = %q", got)
	}
	other := New("ensure", "standalone", "windows", "1.0.10")
	other.Installed = true
	other.AddError("Bad Code!", "x")
	other.AddError("gateway_start_failed", "x")
	got := NewConfigRejectedRecord(other, gap1027Requested, gap1027Baseline, at)
	if got.Cause != ConfigRejectedCauseTransactionFailed || strings.Join(got.ErrorCodes, ",") != "gateway_start_failed" {
		t.Errorf("other = %+v", got)
	}

	for name, bad := range map[string]string{
		"unknown field": strings.Replace(string(raw), `"cause"`, `"extra": 1, "cause"`, 1),
		"unknown cause": strings.Replace(string(raw), ConfigRejectedCauseRouteConfigDrift, "anything", 1),
		"short digest":  strings.Replace(string(raw), gap1027Requested, "11", 1),
		"schema":        strings.Replace(string(raw), `"schema_version": 1`, `"schema_version": 2`, 1),
		"time":          strings.Replace(string(raw), "2026-11-16T08:57:48Z", "yesterday", 1),
	} {
		if _, err := ParseConfigRejectedRecord([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func gap1027Record(t *testing.T) []byte {
	t.Helper()
	raw, err := NewConfigRejectedRecord(gap1027FailedEnsure(), gap1027Requested, gap1027Baseline, time.Date(2026, 11, 16, 8, 57, 48, 0, time.UTC)).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gap1027Status(action string) *Result {
	r := New(action, "standalone", "windows", "1.0.10")
	r.Installed = true
	r.ResetCompleteness()
	return r
}

func TestGAP1027StatusWarnsAndVerifyFailsAfterARolledBackEnsure(t *testing.T) {
	const retry = "Setup /ensure CONFIG=<path>"
	status := gap1027Status("status")
	status.ApplyConfigRejected(gap1027Record(t), gap1027Baseline, retry, `C:\Windows\Logs\DefenseClaw\enterprise-lifecycle.log`)
	if code := status.Finish("windows", 0); code != ExitOK || !status.OK {
		t.Fatalf("status exit %d ok %v", code, status.OK)
	}
	if status.CoverageComplete || status.SecurityComplete {
		t.Fatalf("status coverage %v security %v, want both false", status.CoverageComplete, status.SecurityComplete)
	}
	var warning, coverage string
	for _, w := range status.Warnings {
		switch w.Code {
		case CodeConfigRejected:
			warning = w.Message
		case CodeCoverageIncomplete:
			coverage = w.Message
		}
	}
	for _, want := range []string{"is not applied", "cause route_config_drift", "errors lifecycle_error", "exit 1603", "sha256 111111111111", "sha256 222222222222", "2026-11-16T08:57:48Z", "Fix:", retry, "enterprise-lifecycle.log"} {
		if !strings.Contains(warning, want) {
			t.Errorf("status warning lacks %q: %s", want, warning)
		}
	}
	if !strings.Contains(coverage, CodeConfigRejected) {
		t.Errorf("coverage_incomplete does not name config_rejected: %q", coverage)
	}

	verify := gap1027Status("verify")
	verify.ApplyConfigRejected(gap1027Record(t), gap1027Baseline, retry, "")
	if code := verify.Finish("windows", 0); code != WindowsExitFailure || verify.OK || len(verify.Errors) != 1 || verify.Errors[0].Code != CodeConfigRejected {
		t.Fatalf("verify exit %d ok %v errors %+v", code, verify.OK, verify.Errors)
	}
	linux := New("verify", "standalone", "linux", "1.0.10")
	linux.Installed = true
	linux.ResetCompleteness()
	linux.ApplyConfigRejected(gap1027Record(t), gap1027Baseline, "ensure --config <file>", "")
	if code := linux.Finish("linux", 0); code != UnixExitFailure {
		t.Fatalf("linux verify exit %d", code)
	}
}

func TestGAP1027ConfigRejectedIsSettledOrStrict(t *testing.T) {
	stale := gap1027Status("status")
	stale.ApplyConfigRejected(gap1027Record(t), gap1027Other, "retry", "")
	none := gap1027Status("status")
	none.ApplyConfigRejected(nil, gap1027Baseline, "retry", "")
	change := New("ensure", "standalone", "windows", "1.0.10")
	change.Installed = true
	change.ResetCompleteness()
	change.ApplyConfigRejected(gap1027Record(t), gap1027Baseline, "retry", "")
	for name, r := range map[string]*Result{"config changed since": stale, "no record": none, "a change action": change} {
		if len(r.Warnings) != 0 || len(r.Errors) != 0 || !r.CoverageComplete {
			t.Errorf("%s: warnings %+v errors %+v coverage %v", name, r.Warnings, r.Errors, r.CoverageComplete)
		}
	}
	corrupt := gap1027Status("verify")
	corrupt.ApplyConfigRejected([]byte("{not json"), gap1027Baseline, "retry", "")
	if len(corrupt.Errors) != 1 || corrupt.Errors[0].Code != CodeConfigRejected || corrupt.CoverageComplete ||
		!strings.Contains(corrupt.Errors[0].Message, "cannot be read") {
		t.Fatalf("corrupt record: %+v coverage %v", corrupt.Errors, corrupt.CoverageComplete)
	}
}

// rel-1-0-10 GAP-1038: a supplied config the Windows preflight refuses is
// invalid arguments (1639) and is recorded with cause config_refused; other
// invalid arguments are not.
func TestGAP1038PreflightRefusedConfigIsRecorded(t *testing.T) {
	refusal := func(configRefused bool) *Result {
		r := New("ensure", "standalone", "windows", "1.0.10")
		r.Installed = true
		r.ConfigRefused = configRefused
		r.AddError("invalid_arguments", "rule pack strict-x is not installed")
		r.Finish("windows", WindowsExitInvalidArgs)
		return r
	}
	refused := refusal(true)
	if got := DecideConfigRejected(refused, gap1027Requested, gap1027Baseline, gap1027Baseline); got != ConfigRejectedWrite {
		t.Fatalf("preflight refusal: got %d, want write", got)
	}
	if got := NewConfigRejectedRecord(refused, gap1027Requested, gap1027Baseline, time.Now()); got.Cause != ConfigRejectedCauseRefused || got.ExitCode != WindowsExitInvalidArgs {
		t.Fatalf("record = %+v", got)
	}
	for name, tc := range map[string]struct {
		r                       *Result
		requested, atStart, now string
	}{
		"invalid arguments not about the config": {refusal(false), gap1027Requested, gap1027Baseline, gap1027Baseline},
		"refused config is the running one":      {refusal(true), gap1027Baseline, gap1027Baseline, gap1027Baseline},
		"config.yaml changed during the run":     {refusal(true), gap1027Requested, gap1027Baseline, gap1027Other},
	} {
		if got := DecideConfigRejected(tc.r, tc.requested, tc.atStart, tc.now); got != ConfigRejectedKeep {
			t.Errorf("%s: got %d, want keep", name, got)
		}
	}
}
