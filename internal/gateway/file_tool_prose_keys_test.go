// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

const fileToolBlockPrefix = `{"action":"block"`

// An ordinary Write whose extra prose key (description, note, ...) holds a
// bare DefenseClaw state path allows in the default and permissive profiles;
// a key that names a place, or a prose key holding a structure, stays judged
// as a target in every profile (rel-1-0-6:GAP-0729 review 9 M1).
func TestFileToolProseKeyHoldingStatePathAllowsAndPlaceKeysStayBlocked(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	state := home + "/.defenseclaw/config.yaml"
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, key := range []string{"description", "note", "details", "annotation", "context", "information", "reason", "summary"} {
				input := map[string]any{"file_path": project + "/notes.txt", "content": "x", key: state}
				_, got := postFileToolCell(t, home, project, "Write", input, managed, pack)
				if strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("ordinary Write with prose key %q managed=%t pack=%q: %.200s", key, managed, pack, got)
				}
			}
			for name, extra := range map[string]map[string]any{
				"destination":      {"destination": state},
				"description_file": {"description_file": state},
				"prose list":       {"description": []any{state}},
				"prose object":     {"details": map[string]any{"destinations": []any{state}}},
			} {
				input := map[string]any{"file_path": project + "/notes.txt", "content": "x"}
				for key, value := range extra {
					input[key] = value
				}
				_, got := postFileToolCell(t, home, project, "Write", input, managed, pack)
				if !strings.HasPrefix(got, fileToolBlockPrefix) || !strings.Contains(got, "tamper.detector_state_write") {
					t.Errorf("protected extra key %s managed=%t pack=%q: %.200s", name, managed, pack, got)
				}
			}
		}
	}
}
