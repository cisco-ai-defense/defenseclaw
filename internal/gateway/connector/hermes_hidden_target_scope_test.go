// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"testing"
)

// rel-1-0-6:GAP-0729: a path in a key Hermes does not read is another view
// of the write; one under a key that names a place is judged by every rule,
// the others for DefenseClaw's own state only.
func TestHermesHiddenTargetViewsScope(t *testing.T) {
	const state = "/home/u/.defenseclaw/config.yaml"
	for name, test := range map[string]struct {
		extra string
		self  bool
	}{
		"metadata":         {`"metadata":"` + state + `"`, true},
		"nested note":      {`"meta":{"note":"` + state + `"}`, true},
		"destination":      {`"destination":"` + state + `"`, false},
		"place in prose":   {`"meta":{"output":"` + state + `"}`, false},
		"destinations[]":   {`"destinations":[{"note":"` + state + `"}]`, false},
		"description_file": {`"description_file":"` + state + `"`, false},
	} {
		t.Run(name, func(t *testing.T) {
			views, ok := HermesTrustedWriteViews("write_file", json.RawMessage(`{"path":"/work/a.txt","content":"x",`+test.extra+`}`))
			if !ok {
				t.Fatal("no views")
			}
			var found bool
			for _, view := range views[1:] {
				if view.Path == state {
					found = true
					if view.SelfProtectionOnly != test.self {
						t.Errorf("SelfProtectionOnly = %t, want %t", view.SelfProtectionOnly, test.self)
					}
				}
			}
			if !found {
				t.Errorf("no view of %s in %+v", state, views)
			}
		})
	}
}
