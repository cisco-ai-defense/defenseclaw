// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
)

// Everything an actor controls is cleaned before it reaches the terminal
// (GAP-0101, GAP-0107).
func TestSubstrateOutputDropsHostileControls(t *testing.T) {
	evil := "run\x1b[2K\x1b[1Aall fine\x1b]52;c;cm0gLXJmIH4=\x07 ‮gnp.exe"
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET asks":           jsonReply(map[string]any{"asks": []map[string]any{{"id": "a1", "actor": "eng-web/x", "summary": evil, "severity": evil}}}),
		"GET actors":         jsonReply(map[string]any{"actors": []map[string]any{{"atespace": "eng-web", "name": "x\x1b[2J", "profile": evil, "connector": evil}}}),
		"GET usage":          jsonReply(map[string]any{"note": evil, evil: map[string]any{"k": evil}}),
		"GET policy/explain": jsonReply(map[string]any{"verdict": evil}),
	}}
	useFakeAdmin(t, f)
	for name, run := range map[string]func() (string, error){
		"approvals": func() (string, error) { o, _, err := runSubstrate(t, newSubstrateApprovalsCmd()); return o, err },
		"list":      func() (string, error) { o, _, err := runSubstrate(t, newSubstrateListCmd()); return o, err },
		"usage":     func() (string, error) { o, _, err := runSubstrate(t, newSubstrateUsageCmd()); return o, err },
		"policy":    func() (string, error) { o, _, err := runSubstrate(t, newSubstratePolicyShowCmd()); return o, err },
	} {
		out, err := run()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.ContainsAny(out, "\x1b\x07\r") || strings.ContainsRune(out, '‮') {
			t.Errorf("%s printed a terminal control: %q", name, out)
		}
	}
}
