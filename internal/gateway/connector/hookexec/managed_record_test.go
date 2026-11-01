// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type managedDecisionRecord struct {
	source, marker, line string
}

var managedRecorderTestMu sync.Mutex

// captureManagedHookDecisions replaces the durable recorder for one test and
// returns the records it received.
func captureManagedHookDecisions(t *testing.T) *[]managedDecisionRecord {
	t.Helper()
	managedRecorderTestMu.Lock()
	records := &[]managedDecisionRecord{}
	previous := managedHookDecisionRecorder
	managedHookDecisionRecorder = func(source, marker, line string) {
		*records = append(*records, managedDecisionRecord{source: source, marker: marker, line: line})
	}
	t.Cleanup(func() {
		managedHookDecisionRecorder = previous
		managedRecorderTestMu.Unlock()
	})
	return records
}

func requireOneManagedRecord(t *testing.T, records []managedDecisionRecord, marker string, want ...string) {
	t.Helper()
	if len(records) != 1 {
		t.Fatalf("durable records = %+v, want exactly one", records)
	}
	record := records[0]
	if record.marker != marker || !strings.HasPrefix(record.line, marker+" ") {
		t.Fatalf("record marker = %q line = %q, want %q", record.marker, record.line, marker)
	}
	if record.source == "" {
		t.Fatalf("record has no event source: %+v", record)
	}
	for _, field := range want {
		if !strings.Contains(record.line, field) {
			t.Fatalf("record %q lacks %q", record.line, field)
		}
	}
	for _, secret := range []string{"private-payload-marker", "private-response-marker", "tkn", "authenticated-token"} {
		if strings.Contains(record.line, secret) {
			t.Fatalf("record leaked %q: %q", secret, record.line)
		}
	}
}

func runManagedResolverFailure(t *testing.T, reason, failMode string, strict bool) (int, string) {
	t.Helper()
	return runManagedResolverFailureFor(t, reason, failMode, strict, true)
}

// runManagedResolverFailureFor runs a managed resolver failure under the
// Secure Client profile (secureClient) or the standalone one.
func runManagedResolverFailureFor(t *testing.T, reason, failMode string, strict, secureClient bool) (int, string) {
	t.Helper()
	rt := ok(`{"action":"allow"}`)
	var out, errb bytes.Buffer
	home := t.TempDir()
	code := Run(context.Background(), Options{
		Connector:             "claudecode",
		Event:                 "PreToolUse",
		APIAddr:               "127.0.0.1:1",
		Home:                  home,
		HookDir:               filepath.Join(home, "hooks"),
		FailMode:              failMode,
		StrictAvailability:    strict,
		ManagedEnterprise:     true,
		SecureClient:          secureClient,
		ManagedRuntimeFailure: reason,
		Stdin:                 strings.NewReader(`{"tool_input":{"command":"private-payload-marker"}}`),
		Stdout:                &out,
		Stderr:                &errb,
		HTTPClient:            &http.Client{Transport: rt},
	})
	if rt.requests != 0 {
		t.Fatalf("gateway called %d times, want 0", rt.requests)
	}
	return code, errb.String()
}

// Drifted runtime state follows a Secure Client hook's configured fail mode,
// and every decision leaves one durable degraded record, including the
// fail-open one.
func TestManagedRuntimeDriftFollowsFailModeWithDurableRecord(t *testing.T) {
	for _, tc := range []struct {
		failMode     string
		strict       bool
		wantCode     int
		wantDecision string
	}{
		{failMode: "open", wantCode: 0, wantDecision: `decision="allow"`},
		{failMode: "closed", wantCode: blockExit, wantDecision: `decision="block"`},
		{failMode: "open", strict: true, wantCode: blockExit, wantDecision: `decision="block"`},
	} {
		t.Run(tc.failMode+"/strict="+map[bool]string{true: "1", false: "0"}[tc.strict], func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			code, stderr := runManagedResolverFailure(t, ManagedRuntimeDriftReason, tc.failMode, tc.strict)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d; stderr=%q", code, tc.wantCode, stderr)
			}
			requireOneManagedRecord(t, *records, managed.MarkerDegraded,
				`connector="claudecode"`,
				`event="PreToolUse"`,
				`reason="`+ManagedRuntimeDriftReason+`"`,
				`fail_mode="`+tc.failMode+`"`,
				tc.wantDecision,
			)
			if tc.wantCode == 0 && !strings.Contains(stderr, "WARNING hook fail-open") {
				t.Fatalf("fail-open drift did not warn: %q", stderr)
			}
		})
	}
}

// The standalone profile keeps drifted runtime state closed in every fail
// mode, and still records the decision.
func TestManagedRuntimeDriftStaysClosedForStandalone(t *testing.T) {
	records := captureManagedHookDecisions(t)
	code, stderr := runManagedResolverFailureFor(t, ManagedRuntimeDriftReason, "open", false, false)
	if code != blockExit {
		t.Fatalf("code = %d, want %d; stderr=%q", code, blockExit, stderr)
	}
	requireOneManagedRecord(t, *records, managed.MarkerDegraded,
		`reason="`+ManagedRuntimeDriftReason+`"`,
		`fail_mode="closed"`,
		`decision="block"`,
	)
}

// A boundary resolver failure blocks under an open fail mode and records the
// boundary.
func TestManagedRuntimeBoundaryStaysClosedWithBoundaryRecord(t *testing.T) {
	records := captureManagedHookDecisions(t)
	code, stderr := runManagedResolverFailure(t, managedRuntimeStateInvalidReason, "open", false)
	if code != blockExit {
		t.Fatalf("code = %d, want %d; stderr=%q", code, blockExit, stderr)
	}
	requireOneManagedRecord(t, *records, managed.MarkerBoundary,
		`reason="`+managedRuntimeStateInvalidReason+`"`,
		`fail_mode="closed"`,
		`decision="block"`,
	)
}

// The disable sentinel and a missing Home stay closed for a managed hook.
func TestManagedSentinelAndMissingHomeStayClosedWithBoundaryRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		home   func(t *testing.T) string
		reason string
	}{
		{name: "missing", home: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, reason: managedRuntimeHomeMissingReason},
		{name: "disabled", home: func(t *testing.T) string {
			home := t.TempDir()
			writeTestFile(t, filepath.Join(home, ".disabled"), "")
			return home
		}, reason: managedRuntimeDisableSentinelReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			home := tc.home(t)
			token := "authenticated-token"
			rt := ok(`{"action":"allow"}`)
			code := Run(context.Background(), Options{
				Connector:                 "codex",
				APIAddr:                   "127.0.0.1:1",
				Home:                      home,
				HookDir:                   filepath.Join(home, "hooks"),
				FailMode:                  "open",
				ManagedEnterprise:         true,
				AuthenticatedManagedToken: &token,
				Stdin:                     strings.NewReader("{}"),
				Stdout:                    &bytes.Buffer{},
				Stderr:                    &bytes.Buffer{},
				HTTPClient:                &http.Client{Transport: rt},
			})
			if code != blockExit || rt.requests != 0 {
				t.Fatalf("code = %d requests = %d, want closed before contact", code, rt.requests)
			}
			requireOneManagedRecord(t, *records, managed.MarkerBoundary, `reason="`+tc.reason+`"`, `decision="block"`)
		})
	}
}

// An oversized payload is a deterministic bypass under an open fail mode, so
// a managed hook blocks it and records the boundary; an unmanaged hook keeps
// following its fail mode and writes no platform record.
func TestOversizedPayloadManagedForcesClosed(t *testing.T) {
	for _, managedHook := range []bool{true, false} {
		t.Run(map[bool]string{true: "managed", false: "unmanaged"}[managedHook], func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			r := run(t, "codex", ok(`{"action":"allow"}`), func(opts *Options) {
				opts.FailMode = "open"
				opts.MaxBody = 4
				opts.ManagedEnterprise = managedHook
				opts.SecureClient = managedHook
				if managedHook {
					token := "authenticated-token"
					opts.AuthenticatedManagedToken = &token
				}
				opts.Stdin = strings.NewReader(`{"tool_input":"private-payload-marker"}`)
			})
			if r.rt.requests != 0 {
				t.Fatalf("oversized payload reached the gateway")
			}
			if !managedHook {
				if r.code != 0 || len(*records) != 0 {
					t.Fatalf("unmanaged oversized: code = %d records = %+v", r.code, *records)
				}
				return
			}
			if !strings.Contains(r.stdout, `"deny"`) {
				t.Fatalf("managed oversized code = %d stdout = %q, want Codex's deny", r.code, r.stdout)
			}
			requireOneManagedRecord(t, *records, managed.MarkerBoundary,
				`reason="`+managedHookOversizedReason+`"`,
				`fail_mode="closed"`,
				`decision="block"`,
			)
		})
	}
}

// A 2xx body with neither an action nor a hook output is no verdict: a
// Secure Client hook follows its fail mode instead of reading it as an
// allow. Every other profile refuses it closed.
func TestHookEchoMissingActionAndOutputFollowsFailMode(t *testing.T) {
	for _, connector := range []string{"cursor", "copilot", "antigravity", "devin", "kiro"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(connector+"/"+mode, func(t *testing.T) {
				records := captureManagedHookDecisions(t)
				r := run(t, connector, ok(`{"verdict":"private-response-marker"}`), func(opts *Options) {
					opts.FailMode = mode
					opts.ManagedEnterprise = true
					opts.SecureClient = true
					token := "authenticated-token"
					opts.AuthenticatedManagedToken = &token
				})
				if !strings.Contains(r.stderr, "missing action and hook output") {
					t.Fatalf("stderr = %q, want the response failure", r.stderr)
				}
				if mode == "open" && !strings.Contains(r.stderr, "WARNING hook fail-open") {
					t.Fatalf("fail-open response failure did not warn: %q", r.stderr)
				}
				sp, _ := specFor(connector)
				if sp.failOpenOnly {
					return
				}
				want := `decision="allow"`
				if mode == "closed" {
					want = `decision="block"`
				}
				requireOneManagedRecord(t, *records, managed.MarkerDegraded, `category="response"`, want)
			})
		}
	}
	// A valid action without a hook output stays a verdict.
	if r := run(t, "cursor", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.FailMode = "closed"
		opts.SecureClient = true
	}); r.code != 0 || strings.Contains(r.stderr, "missing action") {
		t.Fatalf("cursor allow without hook_output: code = %d stdout = %q stderr = %q", r.code, r.stdout, r.stderr)
	}
	// Outside Secure Client the same body is refused closed in every mode.
	if r := run(t, "cursor", ok(`{"verdict":"private-response-marker"}`), nil); !strings.Contains(r.stderr, "invalid or missing action") ||
		strings.Contains(r.stderr, "WARNING hook fail-open") {
		t.Fatalf("per-user missing action: code = %d stdout = %q stderr = %q", r.code, r.stdout, r.stderr)
	}
}

// A refused credential is recorded as a boundary; the decision still follows
// the fail mode.
func TestManagedGatewayAuthFailureRecordsBoundary(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			r := run(t, "claudecode", &stubRT{status: status, body: "private-response-marker"}, func(opts *Options) {
				opts.FailMode = "open"
				opts.ManagedEnterprise = true
				opts.SecureClient = true
				token := "authenticated-token"
				opts.AuthenticatedManagedToken = &token
			})
			if r.code != 0 {
				t.Fatalf("code = %d, want the open fail mode", r.code)
			}
			requireOneManagedRecord(t, *records, managed.MarkerBoundary, `category="response"`, `decision="allow"`)
		})
	}
	records := captureManagedHookDecisions(t)
	if r := run(t, "claudecode", &stubRT{status: 500}, func(opts *Options) {
		opts.ManagedEnterprise = true
		opts.SecureClient = true
		token := "authenticated-token"
		opts.AuthenticatedManagedToken = &token
	}); r.code != 0 {
		t.Fatalf("5xx code = %d", r.code)
	}
	requireOneManagedRecord(t, *records, managed.MarkerDegraded, `reason="gateway returned HTTP 500"`)
}

// Unmanaged hooks keep their existing diagnostics and write no platform
// record.
func TestUnmanagedFailureWritesNoPlatformRecord(t *testing.T) {
	records := captureManagedHookDecisions(t)
	if r := run(t, "codex", &stubRT{status: 500}, nil); r.code != 0 {
		t.Fatalf("code = %d", r.code)
	}
	if len(*records) != 0 {
		t.Fatalf("unmanaged hook wrote platform records: %+v", *records)
	}
}

func TestManagedRecordEventFieldIsBounded(t *testing.T) {
	records := captureManagedHookDecisions(t)
	recordManagedHookDecision(
		Options{Event: strings.Repeat("e", 4096) + "\n" + `forged="1"`},
		spec{connector: "codex", hookName: "codex-hook"},
		ManagedRuntimeDriftReason, "transport", "open", false,
	)
	if len(*records) != 1 || len((*records)[0].line) > 1024 || strings.Contains((*records)[0].line, "\n") {
		t.Fatalf("unbounded or multi-line record: %+v", *records)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// captureStandardLogger redirects the standard logger for one test.
func captureStandardLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buffer
}

// A managed hook decision writes its durable record and nothing else: the
// process stderr carries only the agent contract's own diagnostic lines, and
// the standard logger (the process stderr in a hook) stays empty.
func TestManagedHookDecisionWritesNothingExtraToStderr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reason   string
		failMode string
	}{
		{name: "drift fail-open", reason: ManagedRuntimeDriftReason, failMode: "open"},
		{name: "drift fail-closed", reason: ManagedRuntimeDriftReason, failMode: "closed"},
		{name: "boundary", reason: managedRuntimeStateInvalidReason, failMode: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			logged := captureStandardLogger(t)
			_, stderr := runManagedResolverFailure(t, tc.reason, tc.failMode, false)
			if len(*records) != 1 {
				t.Fatalf("durable records = %+v, want one", *records)
			}
			if logged.Len() != 0 {
				t.Fatalf("decision reached the standard logger: %q", logged.String())
			}
			for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
				if !strings.HasPrefix(line, "defenseclaw: ") {
					t.Fatalf("stderr carries a non-contract line: %q", line)
				}
			}
			for _, marker := range []string{managed.MarkerDegraded, managed.MarkerBoundary} {
				if strings.Contains(stderr, marker) {
					t.Fatalf("stderr carries the resilience record: %q", stderr)
				}
			}
		})
	}
}

// Once a hook entrypoint installs the sinks, resilience events and trust
// advisories raised by managed checks go to the durable recorder only.
func TestInstallManagedHookDiagnosticSinksKeepsManagedChecksOffStderr(t *testing.T) {
	records := captureManagedHookDecisions(t)
	logged := captureStandardLogger(t)
	previousResilience := managed.ReportResilienceEvent
	previousAdvisory := managed.ReportTrustAdvisory
	previousDrift := managed.ReportTrustDrift
	t.Cleanup(func() {
		managed.ReportResilienceEvent = previousResilience
		managed.ReportTrustAdvisory = previousAdvisory
		managed.ReportTrustDrift = previousDrift
	})

	InstallManagedHookDiagnosticSinks()
	managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{"path": `C:\x`, "reason": "drift accepted"})
	managed.EmitTrustDriftAdvisory(`C:\y`, "managed runtime selector", "extra reader")
	if logged.Len() != 0 {
		t.Fatalf("managed check reached the standard logger: %q", logged.String())
	}
	if len(*records) != 2 ||
		!strings.HasPrefix((*records)[0].line, managed.MarkerAccept+" ") ||
		!strings.HasPrefix((*records)[1].line, managed.TrustDriftAdvisoryMarker+" ") {
		t.Fatalf("durable records = %+v", *records)
	}
	for _, record := range *records {
		if record.source != managedHookDecisionRecordDefaultSource {
			t.Fatalf("record source = %q", record.source)
		}
	}
}
