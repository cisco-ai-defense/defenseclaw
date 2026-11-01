// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// A Windows PowerShell host whose console input code page is UTF-8 writes a
// UTF-8 byte order mark ahead of the JSON it sends to the hook (cursor-agent
// 2026.10.22 sets that code page for its hooks). The hook forwards the JSON
// without it, so the gateway parses the call, and the event still resolves
// from the payload (GAP-2449).
func TestRunForwardsAHookPayloadWithoutAUTF8ByteOrderMark(t *testing.T) {
	const payload = `{"conversation_id":"c1","session_id":"c1","hook_event_name":"beforeShellExecution","command":"echo ok"}` + "\r\n"
	for _, tc := range []struct {
		name  string
		stdin string
	}{
		{name: "with a byte order mark", stdin: "\xEF\xBB\xBF" + payload},
		{name: "without one", stdin: payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			result := run(t, "cursor", rt, func(o *Options) {
				o.Event = ""
				o.Stdin = strings.NewReader(tc.stdin)
			})
			if rt.gotReq == nil {
				t.Fatalf("no gateway request; code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
			if got := string(rt.gotBody); got != payload {
				t.Fatalf("forwarded body = %q, want %q", got, payload)
			}
			if result.code != 0 {
				t.Fatalf("code = %d, want 0 (stdout=%q stderr=%q)", result.code, result.stdout, result.stderr)
			}
		})
	}
}

func TestTrimUTF8BOMRemovesOnlyOneLeadingMark(t *testing.T) {
	for in, want := range map[string]string{
		"\xEF\xBB\xBF{}":             "{}",
		"\xEF\xBB\xBF\xEF\xBB\xBF{}": "\xEF\xBB\xBF{}",
		"{}\xEF\xBB\xBF":             "{}\xEF\xBB\xBF",
		"{}":                         "{}",
		"":                           "",
	} {
		if got := string(TrimUTF8BOM([]byte(in))); got != want {
			t.Errorf("TrimUTF8BOM(%q) = %q, want %q", in, got, want)
		}
	}
}

// A Cursor call whose payload the hook cannot read fails closed with a deny
// in the fields of every Cursor event, not "{}": cursor-agent 2026.10.22 ran
// a tool call on "{}" with exit 2 (GAP-2449).
func TestCursorCallWithAnUnreadablePayloadIsDeniedInEveryEventShape(t *testing.T) {
	for _, stdin := range []string{"not json", "\xEF\xBB\xBF\xEF\xBB\xBF{\"hook_event_name\":\"beforeShellExecution\"}"} {
		rt := &stubRT{status: 400, body: `{"error":"invalid JSON body","reason":"` + MalformedHookPayloadReason + `"}`}
		result := run(t, "cursor", rt, func(o *Options) {
			o.Event = ""
			o.Stdin = strings.NewReader(stdin)
		})
		out := strings.TrimSpace(result.stdout)
		if !strings.Contains(out, `"permission":"deny"`) || !strings.Contains(out, `"continue":false`) {
			t.Fatalf("stdin %q: stdout = %q, want a deny for every Cursor event", stdin, out)
		}
		if result.code == 0 {
			t.Fatalf("stdin %q: exit code 0, want a blocking code", stdin)
		}
	}
}
