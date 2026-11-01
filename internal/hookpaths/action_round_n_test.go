// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// GAP-1481 (round n): a directory the walk cannot read, or a bound, used to
// make actionExpandGlob drop every match it had already found, so cp
// payload */keyl* through a file alias of the key was allowed on the hook
// client and on the gateway. A found match now always counts, and a walk
// that stopped early is unproved: protected-named in action.
func TestR104RoundNUnreadableSiblingKeepsGlobMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission fixture")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged walk")
	}
	homes, home, cwd := globFactsFixture(t, false)
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{"a", "b", "c"} {
		if err := os.MkdirAll(filepath.Join(cwd, "tree", dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(key, filepath.Join(cwd, "tree", "a", "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "tree", "c", "notes.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(cwd, "tree", "b")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	blocked := []string{
		`cd tree && cp payload */keyl*`,
		`cp payload tree/*/keyl*`,
		`cp payload tree/*/k*`,
		`cat payload >> tree/[ab]/keyl*`,
		`for f in tree/*/keyl*; do cp payload "$f"; done`,
	}
	for _, command := range blocked {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: ActionCommandDecision = %q, want protected-target", command, got)
		}
		if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, map[string]string{}); got != "protected-target" {
			t.Errorf("%s: with client evidence = %q, want protected-target", command, got)
		}
	}
	// GAP-1739: b is unreadable to the user as well, so the user's shell
	// expands nothing there and no match reaches a protected file.
	if got := ActionCommandDecision(`cp payload tree/*/*.md`, cwd, home); got != "" {
		t.Errorf("cp payload tree/*/*.md: ActionCommandDecision = %q, want allow", got)
	}
	// The hook client (the same walk, as the user) answers 1 for the match
	// it found beside the unreadable directory, so a gateway behind
	// ProtectHome blocks too.
	command := `cp payload tree/*/keyl*`
	facts := clientGlobFactsFor(t, command, cwd)
	if got := facts[GlobFactPrefix+filepath.Join(cwd, "tree", "*", "keyl*")]; got != "1" {
		t.Fatalf("client answer = %q, want 1 (facts %v)", got, facts)
	}
	if err := os.Chmod(homes, 0); err != nil {
		t.Fatal(err)
	}
	if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts); got != "protected-target" {
		t.Errorf("hidden home with client answer: %q, want protected-target", got)
	}
	// A client that sent evidence but no answer for this pattern could
	// not prove it: closed.
	if got := ActionCommandDecisionWithGlobFacts(`cp payload tree/*/n*`, cwd, home, map[string]string{CWDKey: cwd}); got != "protected-target" {
		t.Errorf("hidden home, client without answer: %q, want protected-target", got)
	}
	if err := os.Chmod(homes, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`cp payload tree/*/*.md`, `cd tree && git add */*.md`, `rm -f tree/*/*.log`} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("readable %s: ActionCommandDecision = %q, want allow", command, got)
		}
	}
}

// GAP-1481, the bound form of the same class: a match past the directory
// read bound was dropped and the name fallback (keyl* names no key)
// allowed the write.
func TestR104RoundNGlobPastReadBoundIsUnproved(t *testing.T) {
	_, home, cwd := globFactsFixture(t, false)
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for i := 0; i <= actionGlobMaxReads+4; i++ {
		if err := os.MkdirAll(filepath.Join(cwd, "many", fmt.Sprintf("d%03d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(key, filepath.Join(cwd, "many", fmt.Sprintf("d%03d", actionGlobMaxReads+4), "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`cp payload many/*/keyl*`, `cd many && cp payload */keyl*`} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: ActionCommandDecision = %q, want protected-target", command, got)
		}
	}
	// Within the bound an ordinary pattern stays allowed.
	if got := posixShellDecision(`cp payload src/*/*.go docs/`, cwd, home); got != "" {
		t.Errorf("ordinary bounded glob: %q, want allow", got)
	}
}

// GAP-0781 / GAP-1106 (round n): an apply_patch envelope is judged by the
// files its own headers name. Shell text before the heredoc that only had a
// backslash or $( inside single quotes (printf 'a\n') made every envelope
// unknown, and an unknown envelope may write the key, so ordinary Codex
// patches were blocked in action. Single-quoted text is literal; a body
// that mentions authorized_keys is still only data.
func TestR104RoundNApplyPatchAfterQuotedText(t *testing.T) {
	_, home, cwd := globFactsFixture(t, false)
	envelope := func(header string) string {
		return "apply_patch <<'PATCH'\n*** Begin Patch\n" + header + "\n+line\n*** End Patch\nPATCH"
	}
	allowed := map[string][]string{
		`.venv/bin/python -m build --wheel --outdir dist && printf 'INFO Started\nNOTICE Café prêt\nERROR Failed\n' > sample.log && printf '%s\n' '--- installed CLI output ---' && .venv-wheel/bin/log-summary sample.log && ` +
			"apply_patch <<'PATCH'\n*** Begin Patch\n*** Delete File: sample.log\n*** End Patch\nPATCH\n" +
			`git add .gitignore README.md && git commit -m 'Package library' && printf '\n--- final status ---\n' && git status --short --branch && git log -1 --format='%h %an <%ae> %s'`: {"sample.log"},
		`printf '%s\n' start; ` + envelope("*** Update File: race.txt"):                               {"race.txt"},
		`grep -q 'done$' race.txt || ` + envelope("*** Add File: race.txt"):                           {"race.txt"},
		`echo 'see $(date) and ${HOME} and \` + "`x`" + `' && ` + envelope("*** Add File: notes.txt"): {"notes.txt"},
		`printf 'x\n' >/dev/null` + "\n" + envelope("*** Add File: src/c.go"):                         {filepath.Join("src", "c.go")},
		"apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: README.md\n@@\n+Append your key: cat key.pub >> ~/.ssh/authorized_keys\n+cp key.pub ~/.ssh/authorized_keys\n*** End Patch\nPATCH": {"README.md"},
	}
	for command, want := range allowed {
		targets, known := ApplyPatchWriteTargets("Bash", nil, command, cwd, home)
		if !known {
			t.Errorf("%q: envelope unknown", command)
			continue
		}
		for _, name := range want {
			if !slices.Contains(targets, filepath.Join(cwd, name)) {
				t.Errorf("%q: targets %v miss %s", command, targets, name)
			}
		}
		if got := posixShellAuditReason(command, cwd, home); got != "" {
			t.Errorf("%q: actionCommandDecision = %q, want allow", command, got)
		}
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("%q: ActionCommandDecision = %q, want allow", command, got)
		}
	}
	// A patch that names the key still blocks, after the same quoted text,
	// through a directory alias, and with a body that looks benign.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "keydir")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`printf '%s\n' start; ` + envelope("*** Add File: "+filepath.Join(home, ".ssh", "authorized_keys")),
		`printf 'a\n'; ` + envelope("*** Update File: ~/.ssh/authorized_keys"),
		`echo 'x' && ` + envelope("*** Add File: keydir/authorized_keys"),
		`echo 'x' && ` + envelope("*** Delete File: ../project/keydir/authorized_keys2"),
	} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%q: ActionCommandDecision = %q, want protected-target", command, got)
		}
	}
	// Body text is skipped only for an envelope apply_patch reads: fed to
	// a shell, with an expanding feed, a changed PATH or an apply_patch
	// function, the body is still scanned.
	body := "*** Begin Patch\n*** Add File: notes.txt\n+cp payload ~/.ssh/authorized_keys\n*** End Patch\n"
	for _, command := range []string{
		"cat <<'EOF' | sh\n" + body + "EOF",
		"sh <<'EOF'\n" + body + "EOF",
		"PATH=.:$PATH apply_patch <<'PATCH'\n" + body + "PATCH",
		"export PATH=\"$PWD:$PATH\"\napply_patch <<'PATCH'\n" + body + "PATCH",
		"apply_patch() { sh; }; apply_patch <<'PATCH'\n" + body + "PATCH",
		"apply_patch <<PATCH\n*** Begin Patch\n*** Add File: notes.txt\n+cp $HOME/x ~/.ssh/authorized_keys\n*** End Patch\nPATCH",
	} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%q: ActionCommandDecision = %q, want protected-target", command, got)
		}
	}
	// Text whose quoting the scan cannot follow keeps the envelope unknown.
	for _, prefix := range []string{
		`echo $'a\'' && `,
		`echo "a\" && `,
		`printf x "$(cat list)" && `,
		"echo `cat list` && ",
		`echo 'open && `,
	} {
		command := prefix + envelope("*** Add File: notes.txt")
		if _, known := ApplyPatchWriteTargets("Bash", nil, command, cwd, home); known {
			t.Errorf("%q: envelope known, want unknown", command)
		}
		if got := posixShellAuditReason(command, cwd, home); got == "" {
			t.Errorf("%q: actionCommandDecision allows, want an unproved class", command)
		}
	}
}
