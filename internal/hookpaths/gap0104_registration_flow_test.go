// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
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
	// A Windows home is spelled with backslashes; the flow net's mention of
	// ~/... does not match it there (rel-1-0-10:GAP-0154).
	posixOnly := map[string]bool{
		`tar -xf /tmp/a.tar -C ~/.codex config.toml; echo ok > /tmp/x`: true,
		`eval "cat ~/.claude/settings.json" > /tmp/o`:                  true,
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
		if posixOnly[tc.command] && runtime.GOOS == "windows" {
			continue
		}
		got := RegistrationWriteReached(tc.command, cwd, home, names)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: reached %v, want %v", tc.command, got, tc.want)
		}
	}
}

// rel-1-0-10:GAP-0269: a find -exec child that is python with inline code is
// handed the found file as an argument. Code that may write reaches it; code
// that provably only reads does not. The two bodies are the existing
// find -exec python rows of the gateway suite.
func TestGAP0269FindExecPythonReachesTheFileItIsHanded(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const (
		writes = `import sys; open(sys.argv[1], "w").write("")`
		reads  = `import sys; print(open(sys.argv[1]).read())`
	)
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{`find ~/.claude -name settings.json -exec python3 -c '` + writes + `' {} \;`, []string{settings}},
		{`find ~/.claude -name settings.json -execdir python3 -c '` + writes + `' {} \;`, []string{settings}},
		{`find ~/.claude -name settings.json -exec python3 -c '` + reads + `' {} \;`, nil},
		{`for f in ~/.claude/settings.json; do python3 -c '` + writes + `' "$f"; done`, []string{settings}},
	} {
		if got := RegistrationWriteReached(tc.command, filepath.Join(home, "proj"), home, []string{settings}); !slices.Equal(got, tc.want) {
			t.Errorf("%q: reached %v, want %v", tc.command, got, tc.want)
		}
	}
}
