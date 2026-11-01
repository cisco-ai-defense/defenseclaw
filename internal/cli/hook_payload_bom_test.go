// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The foreign-hook guard reads the event and the agent session from a
// payload a Windows PowerShell wrapper put a UTF-8 byte order mark ahead of,
// and the hook then reads the payload without it (GAP-2449).
func TestForeignGuardFactsReadAPayloadBehindAUTF8ByteOrderMark(t *testing.T) {
	const payload = `{"conversation_id":"c1","session_id":"s1","hook_event_name":"beforeShellExecution"}`
	opts := hookexec.Options{Connector: "cursor", Stdin: strings.NewReader("\xEF\xBB\xBF" + payload)}
	facts := captureHookPayloadFacts(&opts)
	if facts.event != "beforeShellExecution" || facts.session != "s1" {
		t.Fatalf("facts event=%q session=%q, want beforeShellExecution/s1", facts.event, facts.session)
	}
	rest, err := io.ReadAll(opts.Stdin)
	if err != nil || string(rest) != payload {
		t.Fatalf("hook stdin after the facts = %q (%v), want %q", rest, err, payload)
	}
}
