// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hp4ReviewRows are the benign neighbours of the five hookparse4 readers
// (review of dc6e12a3d7): ordinary developer commands of the same shape.
// want "allow" is must-allow; "" is a logged probe.
var hp4ReviewRows = []struct{ name, command, want string }{
	// R1 GAP-0311 shape: a pattern in a redirect or an expanded word.
	{"r1-redir-literal-glob", "echo done > build/*.log", "allow"},
	{"r1-redir-var-glob", "f='build/*.log'; echo done >> $f", "allow"},
	{"r1-read-var-glob", "LOG=build/*.log; tail -n 5 $LOG", "allow"},
	{"r1-rm-var-glob", "OBJS='*.o'; rm -f $OBJS", "allow"},
	{"r1-gofmt-var-glob", "files='src/*.go'; gofmt -l $files", "allow"},
	{"r1-for-var-glob", "pat='src/*.go'; for f in $pat; do wc -l $f; done", "allow"},
	{"r1-rm-ext-var", "ext='*.log'; rm -f build/$ext", "allow"},
	{"r1-find-var-glob", "GLOB='*.tmp'; find . -name $GLOB -delete", "allow"},
	{"r1-rm-node-modules-glob", "pat='node_modules/*'; rm -rf $pat", "allow"},
	{"r1-redir-date", "echo x >> logs/$(date +%F).txt", "allow"},
	{"r1-redir-date-var", "d=$(date +%F); echo x >> logs/$d.txt", "allow"},
	{"r1-ordinary-star-var", "cd ordinary && pat='*'; ls -d $pat", "allow"},
	{"r1-project-star-var", "pat='*'; ls -d $pat", "allow"},
	{"r1-project-star-literal", "ls -d *", ""},
	{"r1-home-star-var", "pat=\"$HOME/*\"; du -sh $pat", ""},
	{"r1-home-star-literal", "du -sh ~/*", ""},
	{"r1-home-cache-var", "pat=\"$HOME/.cache/*\"; rm -rf $pat", "allow"},
	// R2 GAP-0312 shape: a redirect target computed at run time.
	{"r2-redir-toplevel", "echo x > $(git rev-parse --show-toplevel)/out.txt", "allow"},
	{"r2-redir-mktemp", "make > \"$(mktemp)\" 2>&1", "allow"},
	{"r2-redir-echo", "echo x > $(echo build/out.txt)", "allow"},
	{"r2-redir-echo-e-var", "f=$(echo -e out/result.txt); echo m >> \"$f\"", "allow"},
	{"r2-redir-printf", "echo m >> $(printf %s out/result.txt)", "allow"},
	{"r2-redir-pwd-var", "OUT=$(pwd)/out.log; make > $OUT 2>&1", "allow"},
	{"r2-redir-echo-brace", "echo x > $(echo build/{out,}.txt)", "allow"},
	{"r2-redir-echo-link-ordinary", "echo x >> $(echo node_modules/.bin/tsc)", "allow"},
	{"r2-redir-dirlink-ordinary", "echo x >> $(echo node_modules/@acme/ui/index.js)", "allow"},
	{"r2-known-hosts", "ssh-keyscan github.com >> ~/.ssh/known_hosts", "allow"},
	{"r2-ssh-config", "echo 'Host gh' >> ~/.ssh/config", "block"},
	{"r2-ssh-config-subst", "echo 'Host gh' >> $(echo ~/.ssh/config)", "block"},
	{"r2-pubkey-copy", "cat ~/.ssh/id_ed25519.pub > pubkey.txt", ""},
	// R3 GAP-0313 shape: a pwsh writer to a project file.
	{"r3-set-content-path", "pwsh -Command \"Set-Content -Path package.json -Value x\"", "allow"},
	{"r3-positional-after-value", "pwsh -c \"Set-Content -Value k package.json\"", "allow"},
	{"r3-colon-path", "pwsh -c \"Set-Content -Path:package.json -Value k\"", "allow"},
	{"r3-value-is-link", "pwsh -c \"Set-Content -Value keylink package.json\"", ""}, // pre-existing per-user block
	{"r3-set-content-pos", "pwsh -Command \"Set-Content README.md x\"", "allow"},
	{"r3-out-file", "pwsh -c \"Get-Date | Out-File build/stamp.txt\"", "allow"},
	{"r3-out-file-append", "pwsh -c \"Get-Process | Out-File -FilePath logs/ps.txt -Append\"", "allow"},
	{"r3-add-content", "pwsh -NoProfile -Command \"Add-Content -Path .gitignore -Value node_modules\"", "allow"},
	{"r3-clear-content", "pwsh -c \"Clear-Content build/app.log\"", "allow"},
	{"r3-file-script", "pwsh -File scripts/build.ps1", "allow"},
	{"r3-literalpath", "powershell -Command \"Set-Content -LiteralPath out.txt -Value x\"", "allow"},
	{"r3-through-file-link", "pwsh -c \"Set-Content -Path node_modules/.bin/tsc -Value x\"", "allow"},
	{"r3-through-dir-link", "pwsh -c \"Set-Content node_modules/@acme/ui/index.js x\"", "allow"},
	{"r3-known-hosts", "pwsh -c \"Add-Content ~/.ssh/known_hosts x\"", "allow"},
	{"r3-split-ordinary", "pwsh -Command Get-ChildItem src \";\" Set-Content out.txt k", "allow"},
	// R4 GAP-0314 shape: rm, unlink, chmod, chown, find -delete with links.
	{"r4-rm-node-modules", "rm -rf node_modules", "allow"},
	{"r4-rm-reinstall", "rm -rf node_modules && npm install", "allow"},
	{"r4-rm-bin-link", "rm -f node_modules/.bin/tsc", "allow"},
	{"r4-rm-dir-link", "rm node_modules/@acme/ui", "allow"},
	{"r4-rm-dir-link-slash", "rm -rf node_modules/@acme/ui/", "allow"},
	{"r4-unlink-current", "unlink current", "allow"},
	{"r4-rm-venv", "rm -rf venv", "allow"},
	{"r4-rm-build", "rm -rf build dist .cache", "allow"},
	{"r4-rm-home-cache", "rm -rf ~/.cache/pip", "allow"},
	{"r4-rm-known-hosts-old", "rm ~/.ssh/known_hosts.old", "allow"},
	{"r4-rm-test-keypair", "rm -f ~/.ssh/id_test ~/.ssh/id_test.pub", "allow"},
	{"r4-rm-sshlink-entry", "rm sshlink", "allow"},
	{"r4-rm-rf-keylink", "rm -rf keylink", ""},
	{"r4-find-pyc", "find . -name '*.pyc' -delete", "allow"},
	{"r4-find-delete-all", "find . -delete", "allow"},
	{"r4-find-md", "find node_modules -name '*.md' -delete", "allow"},
	{"r4-find-links", "find . -type l -delete", "allow"},
	{"r4-find-star-files", "find . -name '*' -type f -delete", "allow"},
	{"r4-find-testdata-keys", "find testdata -name authorized_keys -delete", "allow"},
	{"r4-find-dot-keys", "find . -name authorized_keys -delete", "allow"},
	{"r4-find-ssh-old", "find ~/.ssh -name '*.old' -delete", ""}, // pre-existing block
	{"r4-find-tmp", "find /tmp -name 'npm-*' -delete", "allow"},
	{"r4-find-dirlink-unmatched", "find sshlink/ -name '*.tmp' -delete", ""},
	{"r4-home-find-pyc", "cd ~ && find . -name '*.pyc' -delete", "allow"},
	{"r4-chmod-script", "chmod +x scripts/run.sh", "allow"},
	{"r4-chmod-bin-dir", "chmod -R 755 node_modules/.bin", "allow"},
	{"r4-chmod-bin-link", "chmod 755 node_modules/.bin/tsc", "allow"},
	{"r4-chown-node-modules", "chown -R $(id -u):$(id -g) node_modules", "allow"},
	{"r4-chown-literal", "chown -R alice:alice node_modules", "allow"},
	{"r4-chmod-ssh-config", "chmod 600 ~/.ssh/config", "allow"},
	{"r4-chmod-ssh-key", "chmod 600 ~/.ssh/id_ed25519", "allow"},
	{"r4-chmod-ssh-pub", "chmod 644 ~/.ssh/id_ed25519.pub", "allow"},
	{"r4-chmod-ssh-dir", "chmod 700 ~/.ssh", "allow"},
	{"r4-chmod-keys-600", "chmod 600 ~/.ssh/authorized_keys", ""},
	{"r4-chmod-setup", "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys", ""},
	{"r4-chmod-r-ssh", "chmod -R go-rwx ~/.ssh", ""},
	{"r4-chown-r-ssh", "chown -R alice ~/.ssh", ""},
	{"r4-chmod-sshlink-dir", "chmod 700 sshlink", "allow"},
	{"r4-chmod-ssh-config-400", "chmod 400 ~/.ssh/config", "allow"},
	{"r4-chmod-ssh-config-644", "chmod 644 ~/.ssh/config", "allow"},
	{"r4-chmod-ssh-config-sym", "chmod u=rw,go= ~/.ssh/config", "allow"},
	{"r4-chmod-ssh-config-key", "chmod 600 ~/.ssh/config ~/.ssh/id_ed25519", "allow"},
	{"r4-chmod-ssh-setup-config", "chmod 700 ~/.ssh && chmod 600 ~/.ssh/config", "allow"},
	{"r4-chown-ssh-config", "chown alice ~/.ssh/config", "allow"},
	{"r4-chown-ssh-config-group", "chown alice:alice ~/.ssh/config", "allow"},
	{"r4-chmod-ssh-glob", "chmod 600 ~/.ssh/*", ""},
	{"r4-rm-ssh-config", "rm -f ~/.ssh/config", "allow"},
	{"r4-chmod-666-ssh-config", "chmod 666 ~/.ssh/config", ""},
	{"r5-home-literal-star", "cd ~ && touch *", ""},
	// R5 GAP-0315 shape: a brace word past the 256-field cap.
	{"r5-touch-files", "touch file{1..500}.txt", "allow"},
	{"r5-touch-src", "touch src/{a..z}{0..9}.go", "allow"},
	{"r5-touch-days", "touch logs/day{001..365}.log", "allow"},
	{"r5-touch-date-opt", "touch -d '2 days ago' f{1..300}.txt", "allow"},
	{"r5-mkdir", "mkdir -p dirs/d{1..300}", "allow"},
	{"r5-echo-redirect", "echo {1..1000} > nums.txt", "allow"},
	{"r5-printf", "printf '%s\\n' {1..300}", "allow"},
	{"r5-ordinary-bare", "cd ordinary && touch {1..300}", "allow"},
	{"r5-home-prefixed", "cd ~ && touch tmp{1..300}.txt", "allow"},
	{"r5-home-bare", "cd ~ && touch {1..300}", ""},
	{"r5-project-bare", "touch {1..300}", "allow"},
	{"r5-project-pair", "touch {a..z}{a..z}", ""},
}

// hp4ReviewProject adds an ordinary project tree with links: node_modules
// links, a dir link to a workspace package, a venv link, a release link,
// logs and a testdata keys fixture, plus a few files under the home.
func hp4ReviewProject(t testing.TB, home, project string) {
	t.Helper()
	dirs := []string{"build", "logs", "out", "src", "scripts", "testdata", "dist", ".cache",
		"node_modules/.bin", "node_modules/typescript/bin", "node_modules/@acme", "packages/ui",
		"venv/bin", "releases/v2"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{".cache/pip", "notes"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"build/app.log": "x\n", "src/main.go": "package main\n", "scripts/run.sh": "#!/bin/sh\n",
		"scripts/build.ps1": "1\n", "testdata/authorized_keys": "# fixture\n", "package.json": "{}\n",
		"README.md": "x\n", "node_modules/typescript/bin/tsc": "x\n", "packages/ui/index.js": "x\n",
		"a.o": "x", "b.tmp": "x", "x.pyc": "x",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(project, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{".ssh/config": "Host *\n", ".ssh/known_hosts": "x\n",
		".ssh/known_hosts.old": "x\n", ".ssh/id_ed25519": "x\n", ".ssh/id_ed25519.pub": "x\n"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"node_modules/.bin/tsc": "../typescript/bin/tsc", "node_modules/@acme/ui": "../../packages/ui",
		"venv/bin/python": "/usr/bin/python3", "current": "releases/v2", "sshlink": "../.ssh",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHP4ReviewBenignNeighbours runs hp4ReviewRows in the four cells.
func TestHP4ReviewBenignNeighbours(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	hp4ReviewProject(t, f.home, f.project)
	for _, row := range hp4ReviewRows {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP4REV %s | %s | want %s", call.name, call.verdict, row.want)
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

func TestHP4ReviewProjectPatternTargetsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	hp4ReviewProject(t, f.home, f.project)
	if err := os.Symlink(f.keys, filepath.Join(f.project, "150")); err != nil {
		t.Fatal(err)
	}
	checkHP7ClientRows(t, f, []hp7ClientRow{
		{"HP4/read-only-star", `pat='*'; ls -d $pat`, "allow", "allow"},
		{"HP4/writing-star", `pat='*'; touch $pat`, "block", "block"},
		{"HP4/brace-member-link", `touch {1..300}`, "block", "block"},
	})
}

// BenchmarkHP4ReviewBenignHook times a per-user claudecode hook answer and
// the hook client's header for ordinary commands.
func BenchmarkHP4ReviewBenignHook(b *testing.B) {
	root := b.TempDir()
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "ordinary"), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Setenv("HOME", f.home)
	hp4ReviewProject(b, f.home, f.project)
	for _, bc := range []struct{ name, command string }{
		{"git-status", "git status"},
		{"npm-run-redirect", "npm run build 2>&1 | tail -20"},
		{"go-test-redirect", "go test ./... > build/test.log 2>&1"},
		{"rm-node-modules", "rm -rf node_modules && npm install"},
		{"chmod-find", "chmod +x scripts/run.sh && find . -name '*.pyc' -delete"},
	} {
		payload, err := json.Marshal(map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": f.project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": bc.command, "description": "bench"}})
		if err != nil {
			b.Fatal(err)
		}
		b.Run("gateway/"+bc.name, func(b *testing.B) {
			call := &hookCall{name: bc.name, connector: "claudecode", payload: payload}
			for b.Loop() {
				if v, _ := f.serve(call); v != "allow" {
					b.Fatalf("verdict %s", v)
				}
			}
		})
		b.Run("client/"+bc.name, func(b *testing.B) {
			for b.Loop() {
				_ = hookpaths.Resolve(payload)
			}
		})
	}
}

// BenchmarkHP4ReviewLongOperands times long operand lists: the touch reader
// scans the arguments before each word, and rm resolves every operand.
func BenchmarkHP4ReviewLongOperands(b *testing.B) {
	home := filepath.Join(b.TempDir(), "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			b.Fatal(err)
		}
	}
	b.Setenv("HOME", home)
	for _, n := range []int{500, 2000, 8000} {
		for _, program := range []string{"touch", "rm -f"} {
			command := "cd ordinary && " + program + " " + gap0151Operands(n, "none", "")
			payload, err := json.Marshal(map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": project,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
				"tool_input": map[string]any{"command": command, "description": "bench"}})
			if err != nil {
				b.Fatal(err)
			}
			name := strings.Fields(program)[0] + "-" + strconv.Itoa(n)
			b.Run("decision/"+name, func(b *testing.B) {
				for b.Loop() {
					_ = hookpaths.ActionCommandDecision(command, project, home)
				}
			})
			b.Run("client/"+name, func(b *testing.B) {
				for b.Loop() {
					_ = hookpaths.Resolve(payload)
				}
			})
		}
	}
}
