// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestGAP1028CommandFieldOfAMidSizeCallIsDecodedOnce: a sandbox hook reads
// the command field of one call's arguments some hundred times
// (trustedBashCommandInput), and arguments under 64 KB were decoded in full
// each time. The answer of arguments from a few hundred bytes is
// remembered; it is the answer of the decode, for valid and invalid
// arguments alike (substrate-1 GAP-1028).
func TestGAP1028CommandFieldOfAMidSizeCallIsDecodedOnce(t *testing.T) {
	command := "for USER in a b; do " + strings.Repeat("f0(){ touch out; }; f0; ", 300) + "done"
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`{"command":` + string(encoded) + `}`,
		`{"command":` + string(encoded) + `,"description":"x"}`,
		`{"description":` + string(encoded) + `}`,
		`{"command":` + string(encoded) + `,"command":"ls"}`,
		`{"command":` + string(encoded) + `,`,
		`[` + string(encoded) + `]`,
		`{"command":` + string(encoded) + `} trailing`,
	}
	for _, raw := range cases {
		wantCommand, wantFound, wantValid := decodeTrustedTopLevelCommandField(json.RawMessage(raw))
		for range 2 {
			command, found, valid := trustedTopLevelCommandField(json.RawMessage(raw))
			if command != wantCommand || found != wantFound || valid != wantValid {
				t.Fatalf("%.40q: remembered answer (%d bytes, %v, %v), decode (%d bytes, %v, %v)", raw, len(command), found, valid, len(wantCommand), wantFound, wantValid)
			}
		}
	}
	raw := json.RawMessage(cases[0])
	trustedTopLevelCommandField(raw)
	if allocs := testing.AllocsPerRun(5, func() { trustedTopLevelCommandField(raw) }); allocs > 0 {
		t.Fatalf("a repeated read of %d bytes of arguments allocates %.0f times: decoded again", len(raw), allocs)
	}
}
