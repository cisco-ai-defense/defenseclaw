// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// GAP-0418: the shell expands ~/ from its assigned HOME, including after
// the known-value tracker compacts conditional branches.
func TestGAP0418ReassignedHomeTildeFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	rows := []struct{ name, command, want string }{
		{"protected", "HOME=" + f.project + "; " + hp3r4IfDefaults(10, `echo m >> ~/keylink`), "alert"},
		{"ordinary", "HOME=" + f.project + "; " + hp3r4IfDefaults(10, `echo m >> ~/out.txt`), "allow"},
		{"direct-protected", "HOME=" + f.project + `; echo m >> ~/keylink`, "alert"},
		{"direct-ordinary", "HOME=" + f.project + `; echo m >> ~/out.txt`, "allow"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0418/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}
