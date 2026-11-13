// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0104: the registration reader's flow net counted every
// registered file a call named anywhere once any part of the call could
// write. A name counts only where it can reach a write.
func TestGAP0104RegistrationFlowCountsOnlyWritingParts(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	codex := filepath.Join(home, ".codex", "config.toml")
	for _, name := range []string{settings, codex} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{settings, codex}
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{`sha256sum ~/.claude/settings.json ~/.codex/config.toml > /tmp/h.txt`, nil},
		{`stat ~/.codex/config.toml; echo done > /tmp/log`, nil},
		{`mkdir -p /tmp/b; cp -p ~/.claude/settings.json /tmp/b/settings.json; cp ~/.codex/config.toml /tmp/b/`, nil},
		{`sudo cp ~/.claude/settings.json /var/tmp/b/settings.json; sudo chmod 600 /var/tmp/b/*`, nil},
		{`s=/tmp/b; tar -C ~ -cpf "$s/pre.tar" .claude/settings.json .codex/config.toml; ls "$s"`, nil},
		{`tar -xOf /tmp/a.tar .codex/config.toml | sha256sum; echo ok > /tmp/x`, nil},
		{`for p in .claude/settings.json .codex/config.toml; do shasum ~/$p; done > /tmp/l`, nil},
		{`sudo -n sh -c "shasum ~/.codex/config.toml; ls -ld ~/.codex/config.toml" > /tmp/o`, nil},
		{`sudo -iu u sh -lc "defenseclaw doctor; sha256sum ~/.claude/settings.json" > /tmp/o`, nil},
		{"python3 - <<'PY' > /tmp/o\nimport json\nprint(json.load(open('" + settings + "')))\nPY", nil},
		{`cat ~/.codex/config.toml | head -3 > /tmp/o`, nil},
		{`echo '{}' > ~/.claude/settings.json; sha256sum ~/.codex/config.toml`, []string{settings}},
		{`cp /tmp/b/config.toml ~/.codex/config.toml && sha256sum ~/.codex/config.toml`, []string{codex}},
		{`cp -t ~/.codex /tmp/b/config.toml; echo ok > /tmp/x`, []string{codex}},
		{`echo x | tee -a ~/.codex/config.toml > /dev/null`, []string{codex}},
		{`sha256sum ~/.codex/config.toml; sudo -n sh -c "printf '{}' > ~/.claude/settings.json"`, []string{settings}},
		{`for p in ~/.claude/settings.json; do cp /dev/null "$p"; done`, []string{settings}},
		{`f=~/.codex/config.toml; echo x | xargs -I{} cp /dev/null "$f"`, []string{codex}},
		{`echo ~/.codex/config.toml | xargs rm -f`, []string{codex}},
		{"python3 - <<'PY'\nopen('" + codex + "', 'w').write('')\nPY", []string{codex}},
		{`tar -xf /tmp/a.tar -C ~/.codex config.toml; echo ok > /tmp/x`, []string{codex}},
		{`mv ~/.claude/settings.json /tmp/s.json; echo ok > /tmp/x`, []string{settings}},
		{`eval "cat ~/.claude/settings.json" > /tmp/o`, []string{settings}},
	} {
		got := RegistrationWriteReached(tc.command, cwd, home, names)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: reached %v, want %v", tc.command, got, tc.want)
		}
	}
}
