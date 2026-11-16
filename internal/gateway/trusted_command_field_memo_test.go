// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTrustedTopLevelCommandFieldMemoAnswersTheDecode pins that the remembered
// answer for large tool arguments is the answer of a fresh decode for valid
// arguments and for each way the arguments are refused (a repeated field, a
// non-object, trailing data), on the first read and on every repeat, and that
// an in-place edit of the caller bytes between two reads is answered from the
// new bytes.
func TestTrustedTopLevelCommandFieldMemoAnswersTheDecode(t *testing.T) {
	body := strings.Repeat("ordinary text line\\n", commandFieldMemoMin/16)
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
