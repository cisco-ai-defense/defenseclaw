// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed hook that panicked records a boundary, fails closed with the
// connector's fail-closed output and prints only the fixed sentence: without
// the Secure Client host check, DefenseClaw's own (GAP-0074).
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
	requirePanicStderr(t, stderr.String(), false, "PreToolUse")
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
	want := cursorClosedOutput(Options{ManagedEnterprise: true}, sp.unreachableStrict.body)
	if code != sp.unreachableStrict.exit || strings.TrimSpace(stdout.String()) != want {
		t.Fatalf("code = %d stdout = %q, want the fail-closed output %q", code, stdout.String(), want)
	}
	requirePanicStderr(t, stderr.String(), false, "")
}

// An unknown connector still blocks with the fixed sentence.
func TestHookPanicExitManagedUnknownConnector(t *testing.T) {
	captureManagedHookDecisions(t)
	var stdout, stderr bytes.Buffer
	if code := HookPanicExit(Options{ManagedEnterprise: true, Stdout: &stdout, Stderr: &stderr}, "boom"); code != blockExit {
		t.Fatalf("code = %d, want %d", code, blockExit)
	}
	requirePanicStderr(t, stderr.String(), false, "")
}

// panicTestEvents are the events the panic table replays, including the
// blocking Hermes event and the empty event of a hook that panicked before it
// read its payload.
var panicTestEvents = []string{
	"", "PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "Stop", "PermissionRequest",
	"pre_tool_call", "post_tool_call", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile",
	"afterFileEdit", "tool.execute.before", "tool.execute.after", "Notification", "SubagentStop",
}

// panicAnswerBeforeHostCheck is HookPanicExit's managed answer as it was
// computed before the Secure Client host check was passed in (base
// d37eafc351): the connector's fail-closed transport answer with
// SecureClient unset and the failure diagnostic discarded.
func panicAnswerBeforeHostCheck(opts Options) int {
	opts.SecureClient = false
	opts = withDefaults(opts)
	opts.Stderr = io.Discard
	sp, ok := specFor(opts.Connector)
	if !ok {
		return blockExit
	}
	return failUnreachable(opts, sp, "closed", managedHookInternalErrorReason)
}

func requirePanicStderr(t *testing.T, stderr string, secureClient bool, event string) {
	t.Helper()
	want := "DefenseClaw blocked this " + hookEventSubject(event) +
		": the DefenseClaw hook stopped on an internal error before it could finish checking it." +
		" Try again; if this continues, contact your administrator.\n"
	if secureClient {
		want = ManagedHookBlockMessage + "\n"
	}
	if stderr != want {
		t.Fatalf("panic stderr = %q, want %q", stderr, want)
	}
}

// GAP-0074 (review MF1): the Secure Client host check chooses only the panic
// sentence. For every connector and event, on a standalone and on a Secure
// Client host, the exit status, stdout and durable record equal the answer
// computed without the host check; the Secure Client host keeps the Secure
// Client sentence and a standalone host names DefenseClaw.
func TestHookPanicExitHostCheckChoosesOnlyTheSentence(t *testing.T) {
	connectors := append(SupportedConnectors(), "")
	for _, connector := range connectors {
		for _, event := range panicTestEvents {
			for _, secureClient := range []bool{false, true} {
				name := map[bool]string{false: "standalone", true: "secure-client"}[secureClient]
				t.Run(connector+"|"+event+"|"+name, func(t *testing.T) {
					records := captureManagedHookDecisions(t)
					var refOut, stdout, stderr bytes.Buffer
					refCode := panicAnswerBeforeHostCheck(Options{
						Connector: connector, Event: event, ManagedEnterprise: true, Stdout: &refOut,
					})
					refRecords := append([]managedDecisionRecord(nil), (*records)...)
					code := HookPanicExit(Options{
						Connector:         connector,
						Event:             event,
						ManagedEnterprise: true,
						SecureClient:      secureClient,
						Stdout:            &stdout,
						Stderr:            &stderr,
					}, "runtime error: private-payload-marker")
					got := (*records)[len(refRecords):]
					if code != refCode || stdout.String() != refOut.String() {
						t.Fatalf("answer = (%d, %q), want the answer without the host check (%d, %q)",
							code, stdout.String(), refCode, refOut.String())
					}
					if len(got) != len(refRecords) {
						t.Fatalf("records = %+v, want %+v", got, refRecords)
					}
					for i := range got {
						if got[i] != refRecords[i] {
							t.Fatalf("record %d = %+v, want %+v", i, got[i], refRecords[i])
						}
					}
					if connector != "" && (len(got) != 1 || !strings.Contains(got[0].line, `reason="`+managedHookInternalErrorReason+`"`)) {
						t.Fatalf("records = %+v, want one %q boundary", got, managedHookInternalErrorReason)
					}
					requirePanicStderr(t, stderr.String(), secureClient, event)
				})
			}
		}
	}
}
