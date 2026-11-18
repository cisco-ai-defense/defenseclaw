//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These are the review's real-shell counterexamples, sent through the real
// hook client and gateway for both connectors and all five policy tiers.
// The controls must remain allowed, including when the gateway cannot search
// the managed user's home.
func TestGAP0377GAP0379Review2FiveTierHookRoute(t *testing.T) {
	for _, tier := range []struct {
		name, pack string
		managed    bool
	}{
		{"default", "default", false},
		{"permissive", "permissive", false},
		{"strict", "strict", false},
		{"managed", "default", true},
		{"managed-strict", "strict", true},
	} {
		t.Run(tier.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			switch tier.pack {
			case "strict":
				f = f.strict(t)
			case "permissive":
				f.packDir = filepath.Join(guardrailPoliciesRoot(t), "permissive")
			}
			for _, name := range []string{"key[9]", "keya"} {
				if err := os.Link(f.keys, filepath.Join(f.project, name)); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"plain[9]", "plaina", "ordinary/x"} {
				if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rows := []struct {
				id, command, want string
			}{
				{"0377-sed-direct", "sed -i -e 'w " + f.keys + "' ordinary/x", "block"},
				{"0377-alt-sed-link", "sed -i -e 'w key[9]' ordinary/x", "block"},
				{"0377-sed-attached-e-link", "sed -i -e'w key[9]' ordinary/x", "block"},
				{"0377-sed-long-e-link", "sed -i --expression='w key[9]' ordinary/x", "block"},
				{"0377-sed-substitute-w-link", "sed -i -e 's/x/y/w key[9]' ordinary/x", "block"},
				{"0377-sed-execute-link", "sed -i -e 'e touch key[9]' ordinary/x", "block"},
				{"0377-control", "sed -i -e 's/a/b/' ordinary/x", "allow"},
				{"0377-text-control", "sed -i -e 'a text; w key[9]' ordinary/x", "allow"},
				{"0379-alt-attached-dd", "dd if=/dev/null of=./key[9]", "block"},
				{"0379-control", "dd if=/dev/null of=./plain[9]", "allow"},
				{"0380-alt-nocase-bracket", "shopt -s nocaseglob; touch KEY[ab]", "block"},
				{"0380-control", "shopt -s nocaseglob; touch PLAIN[ab]", "allow"},
			}
			payloads := make([][]byte, len(rows))
			for i, row := range rows {
				payloads[i] = f.payload(t, row.command)
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			for i, row := range rows {
				for _, call := range everyMode(row.id, payloads[i], headers[i]) {
					if call.managed == tier.managed {
						calls = append(calls, call)
					}
				}
			}
			f.answerCells(t, calls)
			for _, call := range calls {
				id := strings.Fields(call.name)[0]
				for _, row := range rows {
					if row.id == id && call.verdict != row.want {
						t.Errorf("%s/%s/%s: got %s, want %s", tier.name, call.connector, id, call.verdict, row.want)
					}
				}
			}
		})
	}
}
