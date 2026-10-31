// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// globFactsFixture is a home with ~/.ssh/authorized_keys and an ordinary
// project. alias adds a directory alias and a file alias of the key there.
func globFactsFixture(t *testing.T, alias bool) (homes, home, cwd string) {
	t.Helper()
	root := t.TempDir()
	homes = filepath.Join(root, "homes")
	home = filepath.Join(homes, "eng1")
	cwd = filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{keys, filepath.Join(cwd, "src", "pkg"), filepath.Join(cwd, "docs")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(keys, "authorized_keys"), filepath.Join(cwd, "payload"),
		filepath.Join(cwd, "assets.txt"), filepath.Join(cwd, ".gitignore"), filepath.Join(cwd, "src", "a.go"),
		filepath.Join(cwd, "src", "pkg", "b.go"), filepath.Join(cwd, "docs", "readme.md")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if alias {
		if err := os.Symlink(keys, filepath.Join(cwd, "keydir")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(keys, "authorized_keys"), filepath.Join(cwd, "notes")); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	return homes, home, cwd
}

// clientGlobFactsFor is the decoded evidence the user-side hook sends.
func clientGlobFactsFor(t *testing.T, command, cwd string) map[string]string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"session_id": "glob-facts", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := Decode(Resolve(body))
	if !ok {
		t.Fatalf("%s: client evidence does not decode", command)
	}
	return facts
}

// GAP-1460 review (round m loop 2): behind ProtectHome the managed gateway
// cannot list an ordinary project, so `git add */*` lost the ordinary-glob
// exemption and `*` was read as a possible key name. The hook client now
// expands each pattern as the user and sends the answer; a proved ordinary
// expansion allows, a match through a directory or file alias blocks, and
// a pattern with no answer keeps the closed name fallback.
func TestR104GlobFactsDecideBehindHiddenHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission fixture")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged walk")
	}
	ordinary := []string{
		`git add */*`,
		`git add */*/*`,
		`git add src/*/*`,
		`git add [a-z]*/*`,
		`git add .*`,
		`rm -f a*`,
		`chmod -R a+r */`,
		`cp payload */*.md`,
		`git add -- */* && git commit -m wip`,
		`for f in */*; do git add "$f"; done`,
		`cd src && git add */*`,
		`bash -c 'git add */*'`,
		`git add *`,
		`cp payload docs/*`,
	}
	t.Run("ordinary project", func(t *testing.T) {
		homes, home, cwd := globFactsFixture(t, false)
		for _, command := range ordinary {
			// A gateway that sees the project (OSS, or no ProtectHome)
			// lists it itself; a matched file has no entries to list.
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Errorf("%s: visible gateway = %q, want allow", command, got)
			}
			facts := clientGlobFactsFor(t, command, cwd)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts); got != "" {
				t.Errorf("%s: hidden gateway with client answers = %q, want allow", command, got)
			}
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	})
	// The same patterns through an alias of the key directory or of the
	// key: the client's walk reaches the key, so the hidden gateway blocks,
	// as one that can see the home does. `cp payload *` and `git add *`
	// were allowed behind ProtectHome before (the GAP-1460 residual).
	aliased := []string{
		`cp payload */*`,
		`git add */*`,
		`cp payload *`,
		`git add *`,
		`cp payload n*`,
		`cp payload keyd*/authorized_keys`,
		`cp payload k*/*`,
		`cd docs && cp payload ../*/authorized_keys`,
		`bash -c 'cp payload */*'`,
		`for f in */*; do cp payload "$f"; done`,
	}
	t.Run("alias project", func(t *testing.T) {
		homes, home, cwd := globFactsFixture(t, true)
		for _, command := range aliased {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Errorf("%s: visible gateway = %q, want protected-target", command, got)
			}
			facts := clientGlobFactsFor(t, command, cwd)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts); got != "protected-target" {
				t.Errorf("%s: hidden gateway with client answers = %q, want protected-target", command, got)
			}
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	})
	// No client answer (an old client, a dropped header, a pattern past
	// the bound): the closed name fallback stays.
	t.Run("no answer stays closed", func(t *testing.T) {
		homes, home, cwd := globFactsFixture(t, false)
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{`git add */*`, `git add .*`, `rm -f a*`, `cp payload keyd*/authorized_keys`} {
			if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, map[string]string{}); got != "protected-target" {
				t.Errorf("%s: hidden gateway without answers = %q, want protected-target", command, got)
			}
		}
	})
	// A gateway that can expand the pattern itself judges by its own walk;
	// a client answer never overrides it, nor a walk past its bound.
	t.Run("own walk wins", func(t *testing.T) {
		_, home, cwd := globFactsFixture(t, true)
		forged := map[string]string{
			GlobFactPrefix + filepath.Join(cwd, "keyd*", "authorized_keys"): "0",
			GlobFactPrefix + filepath.Join(cwd, "*", "*"):                   "0",
			GlobFactPrefix + filepath.Join(cwd, "many", "*", "*"):           "0",
		}
		many := filepath.Join(cwd, "many")
		for i := 0; i <= actionGlobMaxReads; i++ {
			if err := os.MkdirAll(filepath.Join(many, fmt.Sprintf("d%d", i)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, command := range []string{`cp payload keyd*/authorized_keys`, `cp payload */*`, `cp payload many/*/*`} {
			if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, forged); got != "protected-target" {
				t.Errorf("%s: visible gateway with a forged answer = %q, want protected-target", command, got)
			}
		}
	})
}

// The client bounds its answers, and Decode accepts only "0" and "1" for an
// absolute pattern.
func TestR104GlobFactsAreBounded(t *testing.T) {
	if !hookWriteEvidenceHost() {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	_, home, cwd := globFactsFixture(t, false)
	var words []string
	for i := 0; i < 2*maxGlobFacts; i++ {
		words = append(words, fmt.Sprintf("d%d*/*", i))
	}
	command := "git add " + strings.Join(words, " ")
	if got := len(actionGlobFacts(command, cwd, home)); got != maxGlobFacts {
		t.Fatalf("recorded %d answers, want %d", got, maxGlobFacts)
	}
	facts := clientGlobFactsFor(t, command, cwd)
	answers := 0
	for key, value := range facts {
		if strings.HasPrefix(key, GlobFactPrefix) {
			answers++
			if value != "0" {
				t.Errorf("%q = %q, want 0", key, value)
			}
		}
	}
	if answers != maxGlobFacts {
		t.Fatalf("evidence carries %d answers, want %d", answers, maxGlobFacts)
	}
	for _, bad := range []map[string]string{
		{GlobFactPrefix + filepath.Join(cwd, "*"): "2"},
		{GlobFactPrefix + "rel/*": "0"},
		{GlobFactPrefix + filepath.Join(cwd, "*"): ""},
	} {
		encoded, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); ok {
			t.Errorf("Decode accepted %v", bad)
		}
	}
}
