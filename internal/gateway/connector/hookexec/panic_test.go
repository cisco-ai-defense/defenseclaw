// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed hook that panicked records a boundary, fails closed with the
// connector's fail-closed output and prints only the fixed sentence.
func TestHookPanicExitManagedFailsClosedWithBoundaryRecord(t *testing.T) {
	records := captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	code := HookPanicExit(Options{
		Connector:         "claudecode",
		Event:             "PreToolUse",
		ManagedEnterprise: true,
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
	code := HookPanicExit(Options{Connector: "cursor", ManagedEnterprise: true, Stdout: &stdout, Stderr: &stderr}, "boom")
	sp, _ := specFor("cursor")
	if code != sp.unreachableStrict.exit || strings.TrimSpace(stdout.String()) != sp.unreachableStrict.body {
		t.Fatalf("code = %d stdout = %q, want the fail-closed output", code, stdout.String())
	}
}

// An unknown connector still blocks with the fixed sentence.
func TestHookPanicExitManagedUnknownConnector(t *testing.T) {
	captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	if code := HookPanicExit(Options{ManagedEnterprise: true, Stdout: &stdout, Stderr: &stderr}, "boom"); code != blockExit {
		t.Fatalf("code = %d, want %d", code, blockExit)
	}
	requireManagedStderr(t, stderr.String(), true)
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
