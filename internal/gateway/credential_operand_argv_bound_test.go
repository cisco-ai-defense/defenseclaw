// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestCredentialOperandKeepsItsVerdictPastTheArgvBound is GAP-1069: an
// ordinary command whose operand list ends in, or holds, a credential file
// had the verdict of the short list (PATH-NETRC block for touch and cp, the
// credential finding for cat) only up to the argv words the analysis reads
// (256): at 255 operands and more the statement had no path facts and was
// allowed with no finding, and past the operand bound (1024) only its alert
// was left. The gateway now also judges the statement-bounded reading, so the
// verdict is the short-list one at every count, for both connectors, managed
// and per-user; the ordinary twins keep their verdict (allow, and the bound
// alert past the operand bound).
func TestCredentialOperandKeepsItsVerdictPastTheArgvBound(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const netrc = "~/.netrc"
	rows := []struct{ name, command, want string }{
		{"touch 255 last", "touch " + gap0151Operands(255, "last", netrc), "block"},
		{"touch 1023 middle", "touch " + gap0151Operands(1023, "middle", netrc), "block"},
		{"cp 1024 last", "cp " + gap0151Operands(1024, "last", netrc), "block"},
		{"cat 255 last", "cat " + gap0151Operands(255, "last", netrc), "alert"},
		{"touch 255 ordinary", "touch " + gap0151Operands(256, "none", ""), "allow"},
		{"cp 1024 ordinary", "cp " + gap0151Operands(1025, "none", ""), "alert"},
	}
	payloads := make([][]byte, len(rows))
	for i, r := range rows {
		payloads[i] = f.payload(t, r.command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, r := range rows {
		calls = append(calls, everyMode(r.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		if want := rows[i/4].want; call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}
