// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0104: the flow net of the registration reader matched
// every registered name in the whole command text once any part of the call
// could write, so a hash, cmp, a copy out, a tar create, a tar extract to
// standard output, a hash loop, proven-read python code or a diff of a
// process substitution reached the hook config it only reads. The words a
// call only reads are left out of the net; the destinations, redirect
// targets and the calls that hand a name on still reach it.
func TestGAP0104FlowNetLeavesReadOnlyWordsOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home fixture")
	}
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "proj")
	var names []string
	for _, base := range []string{home, cwd} {
		for _, rel := range []string{".claude/settings.json", ".codex/config.toml"} {
			path := filepath.Join(base, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			names = append(names, path)
		}
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	for _, row := range []struct {
		command string
		reach   bool
	}{
		{`sudo -u testuser -H shasum -a 256 ~/.defenseclaw/config.yaml ~/.codex/config.toml; echo done > /tmp/gap0104-log`, false},
		{`cmp -s /tmp/gap0104-before.json ~/.claude/settings.json && echo SAME > /tmp/gap0104-cmp`, false},
		{`mkdir -p /tmp/gap0104-bak; cp -p ~/.claude/settings.json /tmp/gap0104-bak/settings.json; cp -p ~/.codex/config.toml /tmp/gap0104-bak/config.toml`, false},
		{`s=/tmp/gap0104-bak; tar -C ~ -cpf "$s/pre.tar" .defenseclaw/config.yaml .claude/settings.json .codex/config.toml; chmod 600 "$s/pre.tar"`, false},
		{`tar -xOf /tmp/gap0104.tar .codex/config.toml | sha256sum`, false},
		{`for p in .claude/settings.json .codex/config.toml; do shasum -a 256 ~/$p; done >> /tmp/gap0104-loop.txt`, false},
		{"python3 - <<'PY'\nimport json\nfrom pathlib import Path\nprint(json.loads(Path('" + settings + "').read_text()).get('hooks'))\nPY\necho ok > /tmp/gap0104-py", false},
		{`python3 -c 'import json; print(json.load(open("` + settings + `")))' | head`, false},
		{`diff <(cat ~/.codex/config.toml) /tmp/gap0104-bak/config.toml > /tmp/gap0104-diff.txt`, false},
		// Writes, and reads next to a call that hands the name on.
		{`sha256sum ~/.codex/config.toml; echo '{}' > ~/.claude/settings.json`, true},
		{`cp /tmp/gap0104-bak/config.toml ~/.codex/config.toml && sha256sum ~/.codex/config.toml`, true},
		{`ls ~/.claude/settings.json | xargs rm -f; echo gone > /tmp/gap0104-x`, true},
		{`sha256sum ~/.claude/settings.json > /tmp/gap0104-h; cut -d' ' -f3 /tmp/gap0104-h | xargs truncate -s0`, true},
		{`for p in ~/.claude/settings.json; do cat "$p"; done; : > "$p"`, true},
		{`cat ~/.claude/settings.json > /dev/null; cp -p ~/.claude/settings.json{.bak,}`, true},
		{`cat ~/.claude/settings.json; cp -r /tmp/gap0104-evil/.claude ~/ && echo ok > /tmp/gap0104-x`, true},
		{`tar -C /tmp/gap0104-evil -cf - .claude/settings.json | tar -C ~ -xf -`, true},
		{`cat ~/.claude/settings.json; cp /dev/null "$(ls ~/.claude/settings.json)"`, true},
		{`cp -l ~/.claude/settings.json /tmp/gap0104-l && echo '{}' > /tmp/gap0104-l`, true},
		{`f=~/.claude/settings.json; sha256sum "$f"; : > "$f"`, true},
		{`while read -r f; do : > "$f"; done <<< "$(ls ~/.claude/settings.json)"`, true},
		{"python3 - <<'PY'\nopen('" + settings + "', 'w').write('')\nPY\necho ok > /tmp/gap0104-py", true},
	} {
		if got := len(RegistrationWriteReached(row.command, cwd, home, names)) > 0; got != row.reach {
			t.Errorf("%q: reaches %v, want %v", row.command, got, row.reach)
		}
	}
}
