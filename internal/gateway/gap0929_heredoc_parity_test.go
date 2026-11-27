// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0929 has no replayable source trace. Pin its corpus and the runtime-word
// here-document shapes at the release cell, while keeping a real delete
// outside each body visible. The guardrail evaluates these calls only.
func TestGAP0929HereDocConsumerReleaseParity(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	benign := []struct{ name, command string }{
		{"corpus seed", "cat > notes.md <<'EOF'\nsee ~/.defenseclaw/config.yaml for the setting\nEOF"},
		{"corpus var", "d=$(date +%F); cat > notes.md <<'EOF'\nsee ~/.defenseclaw/config.yaml for the setting\nEOF\necho $d"},
		{"corpus var2", "cat > notes.md <<'EOF'\nsee ~/.defenseclaw/config.yaml for the setting\nEOF\ngit status"},
		{"corpus var3", "$EDITOR_HOME/bin/fmt notes.md; cat > notes2.md <<'EOF'\nplain text\nEOF"},
		{"runtime word before consumer", "$EDITOR f; cat > notes.txt <<'EOF'\nmy notes\nEOF"},
		{"runtime word after consumer", "cat > notes.txt <<'EOF'\nmy notes\nEOF\n$CMD arg"},
		{"quoted script and later runtime word", `tool - 'cat > notes.txt <<'"'"'EOF'"'"'
it's (x)
echo data
EOF
echo after'
$LATER`},
	}
	protected := filepath.Join(home, ".defenseclaw")
	attack := []struct{ name, command string }{
		{"delete before consumer", "rm -rf " + protected + "; cat > notes.txt <<'EOF'\nmy notes\nEOF"},
		{"delete after consumer", "cat > notes.txt <<'EOF'\nmy notes\nEOF\nrm -rf " + protected},
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		plain := gap0437Hook(t, hook, cwd, pack.name+"-plain", "rm -rf "+protected)["action"]
		if plain == "allow" {
			t.Fatalf("%s: plain delete unexpectedly allowed", pack.name)
		}
		for _, row := range benign {
			if got := gap0437Hook(t, hook, cwd, pack.name+"-"+row.name, row.command)["action"]; got != "allow" {
				t.Errorf("%s benign %s: %v, want allow", pack.name, row.name, got)
			}
		}
		for _, row := range attack {
			if got := gap0437Hook(t, hook, cwd, pack.name+"-"+row.name, row.command)["action"]; got != plain {
				t.Errorf("%s attack %s: %v, want plain delete cell %v", pack.name, row.name, got, plain)
			}
		}
	}
}
