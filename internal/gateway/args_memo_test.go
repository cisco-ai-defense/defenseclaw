// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestTrustedTopLevelCommandFieldMemoAnswersTheDecode pins that the remembered
// answer for large tool arguments is the answer of a fresh decode for valid
// arguments and for each way the arguments are refused (a repeated field, a
// non-object, trailing data), on the first read and on every repeat, and that
// an in-place edit of the caller bytes between two reads is answered from the
// new bytes.
func TestTrustedTopLevelCommandFieldMemoAnswersTheDecode(t *testing.T) {
	body := strings.Repeat("ordinary text line\\n", argsMemoMin/16)
	valid := `{"command":"` + body + `","timeout":5}`
	for _, tc := range []struct{ name, raw string }{
		{"valid", valid},
		{"cmd alias", `{"cmd":"` + body + `"}`},
		{"no command", `{"path":"` + body + `"}`},
		{"repeated command", `{"command":"` + body + `","Command":"x"}`},
		{"two command names", `{"command":"x","cmd":"` + body + `"}`},
		{"not an object", `["` + body + `"]`},
		{"trailing data", valid + ` {}`},
		{"truncated", valid[:len(valid)-3]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(tc.raw)
			wantCommand, wantFound, wantValid := decodeTrustedTopLevelCommandField(raw)
			for range 3 {
				command, found, valid := trustedTopLevelCommandField(raw)
				if command != wantCommand || found != wantFound || valid != wantValid {
					t.Fatalf("got (%.30q, %t, %t), want (%.30q, %t, %t)", command, found, valid, wantCommand, wantFound, wantValid)
				}
			}
		})
	}
	t.Run("edited in place", func(t *testing.T) {
		raw := json.RawMessage(`{"command":"A` + body + `"}`)
		before, _, _ := trustedTopLevelCommandField(raw)
		raw[len(`{"command":"`)] = byte(0x42)
		after, found, valid := trustedTopLevelCommandField(raw)
		if !found || !valid || !strings.HasPrefix(before, "A") || !strings.HasPrefix(after, "B") {
			t.Fatalf("an edit of the bytes was answered from the old text: %.10q then %.10q", before, after)
		}
	})
}

// TestGAP0299ArgsMemoReadersAnswerTheDecode pins that each remembered reader
// of large tool arguments (rel-1-0-10:GAP-0299) answers what its own decode
// answers, on the first read and on every repeat, with several readers
// sharing one kept text, and that an in-place edit of the bytes is answered
// from the new bytes.
func TestGAP0299ArgsMemoReadersAnswerTheDecode(t *testing.T) {
	body := strings.Repeat("ordinary text line\\n", argsMemoMin/16)
	for _, raw := range []string{
		`{"command":"` + body + `","timeout":5}`,
		`{"cmd":"` + body + `"}`,
		`{"CommandLine":"` + body + `"}`,
		`{"command":["powershell","-c","` + body + `"]}`,
		`{"command":"","cmd":"` + body + `"}`,
		`{"command":"   ","input":"` + body + `"}`,
		`{"path":"` + body + `"}`,
		`{"command":"x","command":"` + body + `"}`,
		`["` + body + `"]`,
		`{"command":"` + body + `"} {}`,
		`not json ` + body,
		`   ` + body,
	} {
		wantShell := decodeAgentHookConfigRawShellCommand(json.RawMessage(raw))
		wantWindows := decodeWindowsArgsCommand(raw)
		wantField, wantFound, wantValid := decodeTrustedTopLevelCommandField(json.RawMessage(raw))
		for range 3 {
			if got := agentHookConfigRawShellCommand(actionfacts.Input{Args: json.RawMessage(raw)}); got != wantShell {
				t.Fatalf("%.40q: raw shell command %.30q, decode %.30q", raw, got, wantShell)
			}
			for _, tool := range []string{"bash", "powershell", "cmd"} {
				gotCommand, _, gotOK := windowsCommandText(raw, tool)
				wantCommand, wantOK := raw, strings.TrimSpace(raw) != ""
				if wantWindows.object {
					wantCommand, wantOK = wantWindows.command, wantWindows.ok
				}
				if gotCommand != wantCommand || gotOK != wantOK {
					t.Fatalf("%.40q %s: windows command (%.30q, %t), decode (%.30q, %t)", raw, tool, gotCommand, gotOK, wantCommand, wantOK)
				}
			}
			if field, found, valid := trustedTopLevelCommandField(json.RawMessage(raw)); field != wantField || found != wantFound || valid != wantValid {
				t.Fatalf("%.40q: command field (%.30q, %t, %t), decode (%.30q, %t, %t)", raw, field, found, valid, wantField, wantFound, wantValid)
			}
		}
	}
	raw := []byte(`{"command":"A` + body + `"}`)
	before := agentHookConfigRawShellCommand(actionfacts.Input{Args: raw})
	raw[len(`{"command":"`)] = 'B'
	after := agentHookConfigRawShellCommand(actionfacts.Input{Args: raw})
	if !strings.HasPrefix(before, "A") || !strings.HasPrefix(after, "B") {
		t.Fatalf("an edit of the bytes was answered from the old text: %.10q then %.10q", before, after)
	}
}
