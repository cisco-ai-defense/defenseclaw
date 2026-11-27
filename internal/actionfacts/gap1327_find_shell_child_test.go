// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// rel-1-0-10:GAP-1327: a find -exec sh -c child is read by its body, not by
// its program name: a body that only prints and hashes the entries it is
// handed changes none of them; its write twin does. Fail-before: red at
// a64bfdb931 (every shell child with a -c body may change its entries).
func TestGAP1327FindShellChildIsJudgedByItsBody(t *testing.T) {
	find := func(body string) []string {
		return []string{"find", "/home/alice/.defenseclaw/hooks", "-type", "f", "-exec", "sh", "-c", body, "sh", "{}", "+"}
	}
	for _, tc := range []struct {
		body   string
		change bool
	}{
		{`for f do printf "%s " "$f"; sha256sum "$f"; done`, false},
		{`cat "$1"`, false},
		{`for f do : > "$f"; done`, true},
		{`rm -f "$1"`, true},
		{`printf x >> "$1"`, true},
		{`chmod 600 "$1"`, true},
		{`eval "$X"`, true},
		{`python3 -c "$X" "$1"`, true},
		{`cp "$1" /tmp/copy`, true},
	} {
		if got := FindHandedEntries(find(tc.body)).MayChange; got != tc.change {
			t.Errorf("find -exec sh -c %q: MayChange %v, want %v", tc.body, got, tc.change)
		}
	}
}
