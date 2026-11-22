//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A statement that changes a modeled glob option (shopt -s nocaseglob) and a
// later word in the same call: the managed gateway's per-command pass reads
// the later statement alone, and the hook client has already read the whole
// call under every reading of that option. The client's answer covers the
// statement, so a benign word stays allowed in the managed tiers as it does
// per-user and on rel (Codex review r1 of s7/hlinkport-r2, row 0380-control:
// four new managed blocks at 7231de882f). The protected word still blocks.
// Rows come from that review; they run through the real hook client and
// gateway for both connectors and all five policy tiers.
func TestGAP0380ManagedStatementKeepsTheCallsGlobReadings(t *testing.T) {
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
				{"0380-alt-nocase-bracket", "shopt -s nocaseglob; touch KEY[ab]", "block"},
				{"0380-control", "shopt -s nocaseglob; touch PLAIN[ab]", "allow"},
				{"0377-sed-direct", "sed -i -e 'w " + f.keys + "' ordinary/x", "block"},
				{"0377-control", "sed -i -e 's/a/b/' ordinary/x", "allow"},
				{"0379-control", "dd if=/dev/null of=./plain[9]", "allow"},
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
