// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A Secure Client hook that panicked records a boundary, fails closed with
// the connector's fail-closed output and prints only the fixed sentence.
func TestHookPanicExitManagedFailsClosedWithBoundaryRecord(t *testing.T) {
	records := captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	code := HookPanicExit(Options{
		Connector:         "claudecode",
		Event:             "PreToolUse",
		ManagedEnterprise: true,
		SecureClient:      true,
		Stdout:            &stdout,
		Stderr:            &stderr,
	}, "runtime error: private-payload-marker")
	if code != blockExit {
		t.Fatalf("code = %d, want %d", code, blockExit)
	}
	requireManagedStderr(t, stderr.String(), true)
	requireOneManagedRecord(t, *records, managed.MarkerBoundary,
		`reason="`+managedHookInternalErrorReason+`"`,
		`fail_mode="closed"`,
		`decision="block"`,
	)
	if strings.Contains((*records)[0].line, "private-payload-marker") {
		t.Fatalf("record carries the panic value: %q", (*records)[0].line)
	}
}

// Cursor's fail-closed body still reaches stdout on a managed panic.
func TestHookPanicExitManagedEmitsConnectorFailClosedBody(t *testing.T) {
	captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	code := HookPanicExit(Options{Connector: "cursor", ManagedEnterprise: true, SecureClient: true, Stdout: &stdout, Stderr: &stderr}, "boom")
	sp, _ := specFor("cursor")
	want := cursorClosedOutput(Options{ManagedEnterprise: true}, sp.unreachableStrict.body)
	if code != sp.unreachableStrict.exit || strings.TrimSpace(stdout.String()) != want {
		t.Fatalf("code = %d stdout = %q, want the fail-closed output %q", code, stdout.String(), want)
	}
	requireManagedStderr(t, stderr.String(), true)
}

// An unknown connector still blocks with the fixed sentence.
func TestHookPanicExitManagedUnknownConnector(t *testing.T) {
	captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	if code := HookPanicExit(Options{ManagedEnterprise: true, SecureClient: true, Stdout: &stdout, Stderr: &stderr}, "boom"); code != blockExit {
		t.Fatalf("code = %d, want %d", code, blockExit)
	}
	requireManagedStderr(t, stderr.String(), true)
}

// GAP-0074: a managed hook that is not a Secure Client hook (the standalone
// profile) answers a panic with DefenseClaw's own sentence, not the Secure
// Client one, and still fails closed with the same record, exit status and
// output as the Secure Client hook.
func TestHookPanicExitManagedStandaloneNamesDefenseClaw(t *testing.T) {
	const want = "DefenseClaw blocked this tool call: the DefenseClaw hook stopped on an internal error before it could finish checking it. Try again; if this continues, contact your administrator.\n"
	for _, connector := range []string{"claudecode", "codex", "cursor", "opencode", ""} {
		t.Run(connector, func(t *testing.T) {
			outputs := map[bool][2]string{}
			codes := map[bool]int{}
			for _, secureClient := range []bool{false, true} {
				t.Run(map[bool]string{false: "standalone", true: "secure-client"}[secureClient], func(t *testing.T) {
					records := captureManagedHookDecisions(t)
					var stdout, stderr bytes.Buffer
					codes[secureClient] = HookPanicExit(Options{
						Connector:         connector,
						Event:             "PreToolUse",
						ManagedEnterprise: true,
						SecureClient:      secureClient,
						Stdout:            &stdout,
						Stderr:            &stderr,
					}, "runtime error: private-payload-marker")
					outputs[secureClient] = [2]string{stdout.String(), stderr.String()}
					if strings.Contains(stderr.String(), "private-payload-marker") {
						t.Fatalf("secure_client=%t: stderr carries the panic value: %q", secureClient, stderr.String())
					}
					if connector != "" {
						requireOneManagedRecord(t, *records, managed.MarkerBoundary,
							`reason="`+managedHookInternalErrorReason+`"`, `fail_mode="closed"`, `decision="block"`)
					}
				})
			}
			if got := outputs[false][1]; got != want {
				t.Fatalf("standalone stderr = %q, want %q", got, want)
			}
			if strings.Contains(outputs[false][1], "Cisco AI Defense") {
				t.Fatalf("standalone stderr names Secure Client: %q", outputs[false][1])
			}
			requireManagedStderr(t, outputs[true][1], true)
			if codes[false] != codes[true] || outputs[false][0] != outputs[true][0] {
				t.Fatalf("standalone answer (%d, %q) differs from Secure Client (%d, %q)",
					codes[false], outputs[false][0], codes[true], outputs[true][0])
			}
		})
	}
}

// An unmanaged hook prints one line, never a stack, and keeps exit 2.
func TestHookPanicExitUnmanagedPrintsOneLine(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := HookPanicExit(Options{Connector: "claudecode", Stdout: &stdout, Stderr: &stderr}, "line one\nline two")
	if code != blockExit {
		t.Fatalf("code = %d, want %d", code, blockExit)
	}
	if got := stderr.String(); strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "defenseclaw: hook internal error: ") {
		t.Fatalf("stderr = %q, want one line", got)
	}
}
