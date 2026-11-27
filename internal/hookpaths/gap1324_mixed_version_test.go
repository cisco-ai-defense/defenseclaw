// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// gateway1010GlobFactPrefixes are the pathname-pattern fact keys a 1.0.10
// gateway (a64bfdb931) checks in Decode; it skips a key no check names.
var gateway1010GlobFactPrefixes = []string{"\x00glob:", "\x00glob-loop-copy:"}

// gateway1010AcceptsGlobFact is the 1.0.10 Decode rule (a64bfdb931,
// internal/hookpaths/hookpaths.go) for a GlobFactPrefix key: a value other
// than "0" or "1" refuses the whole map, so the gateway takes its closed
// TruncatedKey fallback.
func gateway1010AcceptsGlobFact(key, value string) bool {
	return !strings.HasPrefix(key, "\x00glob:") ||
		(value == "0" || value == "1") && filepath.IsAbs(strings.TrimPrefix(key, "\x00glob:"))
}

// GAP-1324, mixed versions: the managed hook client of this version against
// a 1.0.10 gateway. A capped walk sent as a GlobFactPrefix value the old
// gateway does not know ("c") made it refuse the whole answer map and block
// benign calls with its closed default. The capped answer is a key of its own
// (GlobCapFactPrefix) that 1.0.10 skips, so the old gateway reads the map a
// 1.0.10 client sent: no answer for the pattern, its own fallback.
// The gate also feeds this client answer to the real Decode of a64bfdb931.
func TestGAP1324ClientAnswerIsOneA1010GatewayAccepts(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	gap1324Tree(t, filepath.Join(project, "past"), 64)
	gap1324Tree(t, filepath.Join(project, "at"), 63)
	command := "cp a.txt past/b*/c* at/b*/c*"
	facts := actionGlobFacts(command, project, home)
	capped := 0
	for key, value := range facts {
		if !gateway1010AcceptsGlobFact(key, value) {
			t.Errorf("client fact %q=%q: a 1.0.10 gateway refuses the whole map", key, value)
		}
		if strings.HasPrefix(key, GlobCapFactPrefix) {
			capped++
			for _, prefix := range gateway1010GlobFactPrefixes {
				if strings.HasPrefix(key, prefix) {
					t.Errorf("capped key %q is read by a 1.0.10 gateway check (%q)", key, prefix)
				}
			}
		}
	}
	if capped != 1 || facts[GlobFactPrefix+filepath.Join(project, "at", "b*", "c*")] != "0" {
		t.Fatalf("client facts %q: want one capped key and the complete walk's \"0\"", facts)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); !ok {
		t.Errorf("Decode refused the client answer %q", facts)
	}
}
