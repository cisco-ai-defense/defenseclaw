// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lateOrdinaryProject is a project in a user's home with a link, a hard link
// and a plain file; HOME points at the home (the scan reads it).
func lateOrdinaryProject(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "-keylink")); err != nil {
		t.Fatal(err)
	}
	// A link with a one-letter name and one with a space in its name.
	if err := os.WriteFile(filepath.Join(project, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(project, "plain.txt"), filepath.Join(project, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "key link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return project
}

func lateOrdinaryPayload(t *testing.T, project string, command any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": "Bash",
		"tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestGAP0518LateOrdinaryCallFollowsTheOutageMode: a per-user call that its
// verified gateway took and did not answer by the deadline is no longer
// denied when it plainly names nothing protected, in the tier whose outage
// mode is open, with the visible warning and a fail_open row; the strict tier
// stays closed. A call that names the keys file, a link or a hard link to it,
// in a short or a 2000-operand list, stays closed in every tier (the
// verified-gateway-without-status control of the psna-rb review).
func TestGAP0518LateOrdinaryCallFollowsTheOutageMode(t *testing.T) {
	project := lateOrdinaryProject(t)
	// A folder whose link is not in the project (round 4: a cd must move the
	// folder every later word is looked up in).
	sub := filepath.Join(project, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(project), ".ssh", "authorized_keys"), filepath.Join(sub, "childlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shortAnswerBudget(t, 400*time.Millisecond)
	addr := hungGateway(t)
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	words := make([]string, 2000)
	for i := range words {
		words[i] = fmt.Sprintf("lo%d.txt", i)
	}
	long := "touch " + strings.Join(words, " ")
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tc := range []struct {
			name    string
			command any
			mode    string
			blocks  bool
		}{
			{"echo, open tier", "echo hi", "open", false},
			{"build with a redirect and a filter, open tier", "go test ./... 2>&1 | tail -5", "open", false},
			{"2000 operands, open tier", long, "open", false},
			{"ordinary words that read like a name, open tier", "echo claw defense", "open", false},
			{"short flags, open tier", "ls -la", "open", false},
			{"echo, strict tier", "echo hi", "closed", true},
			{"2000 operands, strict tier", long, "closed", true},
			{"direct keys path, open tier", "cat ../.ssh/authorized_keys", "open", true},
			{"link to keys, open tier", "cat keylink", "open", true},
			{"hard link to keys, open tier", "cat hardlink", "open", true},
			{"2000 operands with the link last, open tier", long + " keylink", "open", true},
			{"2000 operands with the link first, open tier", "touch keylink " + strings.Join(words, " "), "open", true},
			{"attached output option to the link, open tier", "curl -okeylink http://example.invalid/x", "open", true},
			{"bundled attached output option, open tier", "curl -sSokeylink http://example.invalid/x", "open", true},
			{"key=value operand to the link, open tier", "d" + "d if=plain.txt of=keylink", "open", true},
			{"redirect to a dash-named link, open tier", "echo x > -keylink", "open", true},
			{"known value, open tier", "cat $HOME/.ssh/authorized_keys", "open", true},
			// Round 3: a word is told by what its program does with it.
			{"echo of a state folder word, open tier", "echo openclaw", "open", false},
			{"echo flag next to a one-letter link, open tier", "echo -l", "open", false},
			{"ls flag next to a one-letter link, open tier", "ls -l", "open", false},
			{"sed print, open tier", "sed -n 1,5p plain.txt", "open", false},
			{"argv with a plain file, open tier", []string{"cat", "plain.txt"}, "open", false},
			{"sed write command to the link, open tier", `sed -n -e "w keylink" plain.txt`, "open", true},
			{"sed write flag to the link, open tier", `sed -n "s/a/b/w keylink" plain.txt`, "open", true},
			{"argv with a link that has a space, open tier", []string{"cat", "key link"}, "open", true},
			{"quoted link that has a space, open tier", `cat "key link"`, "open", true},
			// Round 4: a cd moves the folder, a direct link stays closed as
			// text, and ordinary scripts and patterns stay open.
			{"cd then a plain file, open tier", "cd sub && cat plain.txt", "open", false},
			{"cd then a link of that folder, open tier", "cd sub && cat childlink", "open", true},
			{"cd then a redirect to a link of that folder, open tier", "cd sub && echo x > childlink", "open", true},
			{"cd then a link after a semicolon, open tier", "cd sub; cat childlink", "open", true},
			{"echo of a direct link, open tier", "echo keylink", "open", true},
			{"echo of a quoted link with a space, open tier", "echo 'key link'", "open", true},
			{"printf of a direct link, open tier", "printf %s keylink", "open", true},
			{"sed two prints, open tier", `sed -n '1p;2p' plain.txt`, "open", false},
			{"sed two substitutions, open tier", `sed -e 's/a/b/;s/c/d/' plain.txt`, "open", false},
			{"sed print and write to the link, open tier", `sed -n '1p;w keylink' plain.txt`, "open", true},
			{"grep pattern option, open tier", "grep -e openclaw plain.txt", "open", false},
			{"grep first operand pattern, open tier", "grep openclaw plain.txt", "open", false},
			{"grep pattern file link, open tier", "grep -f keylink plain.txt", "open", true},
			{"ls ignore pattern, open tier", "ls -Iopenclaw plain.txt", "open", false},
			{"ls ignore pattern then a link, open tier", "ls -Iopenclaw keylink", "open", true},
			// Round 5: a link to an ordinary file is as ordinary as the file,
			// a cd chain, grep option values and sed scripts are read as the
			// program reads them; the protected twins stay closed.
			{"echo of a link to a plain file, open tier", "echo l", "open", false},
			{"grep pattern that is a link to a plain file, open tier", "grep -e l plain.txt", "open", false},
			{"cd and back, open tier", "cd sub && cd .. && cat plain.txt", "open", false},
			{"cd and back, then the link, open tier", "cd sub && cd .. && cat keylink", "open", true},
			{"grep after-context, open tier", "grep -A 3 openclaw plain.txt", "open", false},
			{"grep max count, open tier", "grep -m 3 openclaw plain.txt", "open", false},
			{"grep include glob, open tier", "grep -r --include=openclaw x sub", "open", false},
			{"grep exclude glob, open tier", "grep -r --exclude=openclaw x sub", "open", false},
			{"grep after-context then the link, open tier", "grep -A 3 x keylink", "open", true},
			{"sed trailing separator, open tier", `sed -n '1p;2p;' plain.txt`, "open", false},
			{"sed spaced separator, open tier", `sed -n '1p ; 2p' plain.txt`, "open", false},
			{"sed regexp holding a semicolon, open tier", `sed -n '/a;b/p' plain.txt`, "open", false},
			{"sed write after a trailing separator, open tier", `sed -n '1p;w keylink;' plain.txt`, "open", true},
			{"echo of a link to a plain file, strict tier", "echo l", "closed", true},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				result, _ := runAgainstGateway(t, connector, addr, func(opts *Options) {
					opts.HTTPClient = client
					opts.FailMode = "open"
					opts.OutageFailModeNow = func() string { return tc.mode }
					opts.Stdin = strings.NewReader(lateOrdinaryPayload(t, project, tc.command))
				})
				if got := blocked(result); got != tc.blocks {
					t.Fatalf("blocks=%v, want %v: code=%d stdout=%.300q stderr=%.300q", got, tc.blocks, result.code, result.stdout, result.stderr)
				}
				if !tc.blocks && !strings.Contains(result.stdout+result.stderr, "did not answer in time") {
					t.Fatalf("no visible warning: stdout=%.300q stderr=%.300q", result.stdout, result.stderr)
				}
			})
		}
	}
}
