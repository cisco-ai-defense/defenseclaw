// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0622Row is a Claude Code Bash row of the GUEST-RES4 review. want is
// "exact" (the laptop's exact answer), "laptop" (never weaker than the
// laptop, which blocks, and naming its rules) or "floor" (the laptop blocks
// or alerts; the actor is the laptop's verdict or at least the unknown tier
// of the pack with the evaluation-limit finding, never a clean allow).
type gap0622Row struct {
	name, command, want string
}

// gap0622Layout adds to the J19 layout a folder sub of app with its own
// link to DefenseClaw state and a plain notes file, and an app notes link to
// the key: cd sub && echo x >> dc-link writes the state, cd sub && cat notes
// reads the plain file.
func gap0622Layout(t *testing.T, home, app string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(app, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../.defenseclaw/config.yaml", filepath.Join(app, "sub", "dc-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "sub", "notes"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(app, "notes")); err != nil {
		t.Fatal(err)
	}
	// One spelling, two folders, two places: a/lk and svc1/py, svc2/py are
	// benign, b/lk is DefenseClaw state (GUEST-RES5 review).
	for link, target := range map[string]string{
		"a/lk": "../README.md", "b/lk": "../../.defenseclaw/config.yaml",
		"svc1/py": "../README.md", "svc2/py": "../docs/README.md",
	} {
		if err := os.MkdirAll(filepath.Join(app, filepath.Dir(link)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(app, link)); err != nil {
			t.Fatal(err)
		}
	}
}

func gap0622Rows() []gap0622Row {
	words := func(n int, format string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(format, i)
		}
		return strings.Join(parts, " ")
	}
	// 40 distinct spellings of one link: more command-word facts than the
	// kit sends (32).
	links := make([]string, 40)
	for i := range links {
		links[i] = strings.Repeat("./", i+1) + "readme-link"
	}
	return []gap0622Row{
		// GAP-0622: a write through a link past the word bound and past the
		// fact cap.
		{"past-word-bound", "true " + words(2100, "a%d") + "; echo x >> dc-link", "floor"},
		{"past-fact-cap", "cat " + strings.Join(links, " ") + " > /dev/null; echo x > claude-dir/settings.json", "floor"},
		{"past-fact-cap-state", "cat " + strings.Join(links, " ") + " > /dev/null; echo x >> dc-link", "floor"},
		// GAP-0623: the word is read in the folder the cd chain gives.
		{"cd-sub-write", "cd sub && echo x >> dc-link", "laptop"},
		{"cd-sub-semicolon-write", "cd sub; echo x >> dc-link", "laptop"},
		{"eval-cd-sub-write", `eval "cd sub && echo x >> dc-link"`, "laptop"},
		{"sh-c-cd-sub-write", `bash -c 'cd sub && echo x >> dc-link'`, "laptop"},
		{"dd-of-link", "dd if=/dev/zero of=dc-link count=1", "laptop"},
		{"cd-sub-dd-of-link", "cd sub && dd if=/dev/zero of=dc-link count=1", "laptop"},
		{"two-places-state-second", "cd a && echo x >> lk && cd ../b && echo x >> lk", "laptop"},
		{"two-places-state-first", "cd b && echo x >> lk && cd ../a && echo x >> lk", "laptop"},
		{"two-places-benign", "cd svc1 && cat py && cd ../svc2 && cat py", "exact"},
		// Benign: the laptop's exact answer.
		{"cd-sub-cat-notes", "cd sub && cat notes", "exact"},
		{"eval-cd-sub-cat-notes", `eval "cd sub && cat notes"`, "exact"},
		{"dd-plain-of", "dd if=README.md of=gap0622-copy bs=1k", "exact"},
		{"cd-sub-ls", "cd sub && ls -l", "exact"},
		{"git-add-70", "git add " + words(70, "f%d.txt"), "exact"},
		{"dd-plain", "dd if=README.md of=/tmp/gap0622-copy bs=1k", "exact"},
		{"cd-docs-cat", "cd docs-link && cat README.md", "exact"},
	}
}

// TestGAP0622GAP0623ActorClaimsCutAndFoldersKeepLaptopVerdict: in a Claude
// Code actor, a write through a link to DefenseClaw state or a hook config
// after more path words than the kit reads (true a0 ... a599; echo x >>
// dc-link) or after more link words than the kit sends was a clean allow
// where the laptop, which follows the link, blocks or alerts (substrate-1
// GAP-0622): it is the pack's unknown tier now (ACTION-COMPOUND-LIMIT, an
// alert in these packs). cd sub && echo x >> dc-link placed the word in the
// start folder and was allowed (GAP-0623): the word is read in the folder the
// cd chain gives now, an eval body's too, and dd of=dc-link is a word. The
// exact rows get the laptop's exact answer, in every pack, with the kit's
// honest facts. That answer is not always allow: cd sub && cat notes is a
// PATH-SSH-KEY block on the laptop too, as at 1.0.10, because the laptop's
// private-key reader keeps the start folder as a candidate after a relative
// cd (actionPosixPrivateKeyRead). This layout has dc-link in the start folder
// as well, so its write rows hold however the word is placed; the start-folder
// placement shows only in TestGAP0623ActorLiveLayoutKeepsLaptopVerdict.
func TestGAP0622GAP0623ActorClaimsCutAndFoldersKeepLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, "claudecode", pack)
			gap0622Layout(t, home, app)
			if err := os.Symlink("README.md", filepath.Join(app, "readme-link")); err != nil && !os.IsExist(err) {
				t.Fatal(err)
			}
			for _, row := range gap0622Rows() {
				body := func(cwd string) []byte {
					raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0622", "cwd": cwd,
						"tool_name": "Bash", "tool_input": map[string]any{"command": row.command}, "tool_use_id": "gap0622"})
					return raw
				}
				host, guest := body(app), body(sandboxauth.SandboxHome+"/app")
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
				gap0622Check(t, row, la, lr, ca, cr)
			}
		})
	}
}

// gap0622Check compares the actor's verdict ca, cr with the laptop's la, lr
// as row.want asks.
func gap0622Check(t *testing.T, row gap0622Row, la string, lr []string, ca string, cr []string) {
	t.Helper()
	switch row.want {
	case "exact":
		if ca != la || !slices.Equal(cr, lr) {
			t.Errorf("%s: actor %s %v, laptop %s %v, want the laptop's exact answer", row.name, ca, cr, la, lr)
		}
	case "laptop":
		if gap0545Rank(la, lr) < 2 {
			t.Errorf("%s: laptop %s %v, want an alert or a block (the test layout is wrong)", row.name, la, lr)
		}
		if gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
			t.Errorf("%s: actor %s %v is weaker than the laptop's %s %v", row.name, ca, cr, la, lr)
		}
		for _, rule := range lr {
			if !slices.Contains(cr, rule) {
				t.Errorf("%s: actor %s %v does not name the laptop's %s", row.name, ca, cr, rule)
			}
		}
	case "floor":
		if gap0545Rank(la, lr) < 2 {
			t.Errorf("%s: laptop %s %v, want an alert or a block (the test layout is wrong)", row.name, la, lr)
		}
		if gap0545Rank(ca, cr) < gap0545Rank(la, lr) && (gap0545Rank(ca, cr) < 2 || !slices.Contains(cr, evaluationLimitRuleID)) {
			t.Errorf("%s: actor %s %v, want the laptop's %s %v or the unknown tier", row.name, ca, cr, la, lr)
		}
	}
}

// TestGAP0623ActorLiveLayoutKeepsLaptopVerdict is the live layout of the
// PREVER-T6A3 rows (substrate-1 GAP-0623): the call starts in a work folder
// outside the home, /work/w3, whose notes links to the SSH key; its folder
// sub holds a plain notes file and the only dc-link, a link to DefenseClaw
// state. No dc-link in the start folder, so a write placed in the start folder
// misses the link: cd sub && echo x >> dc-link, its eval and -c bodies and dd
// of=dc-link after the cd were a clean allow in the actor where the laptop
// alerts or blocks, and eval "cd sub && cat ../notes" an alert where the
// laptop blocks. A key read through the cd chain stays the laptop's block,
// and every other row gets the laptop's exact answer, whatever it is:
// cd sub && cat notes is the laptop's PATH-SSH-KEY block (its private-key
// reader keeps the start folder as a candidate after a relative cd, as at
// 1.0.10), cat sub/notes and cd sub && ls -l its allow.
func TestGAP0623ActorLiveLayoutKeepsLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	rows := []gap0622Row{
		{"cd-sub-write", "cd sub && echo x >> dc-link", "laptop"},
		{"cd-sub-semicolon-write", "cd sub; echo x >> dc-link", "laptop"},
		{"eval-cd-sub-write", `eval "cd sub && echo x >> dc-link"`, "laptop"},
		{"bash-c-cd-sub-write", `bash -c 'cd sub && echo x >> dc-link'`, "laptop"},
		{"cd-sub-dd-of-link", "cd sub && dd if=/dev/zero of=dc-link count=1", "laptop"},
		{"dd-of-sub-link", "dd if=/dev/zero of=sub/dc-link count=1", "laptop"},
		{"cat-key-link", "cat notes", "laptop"},
		{"cd-sub-cat-up-key-link", "cd sub && cat ../notes", "laptop"},
		{"eval-cd-sub-cat-up-key-link", `eval "cd sub && cat ../notes"`, "laptop"},
		{"sh-c-cd-sub-cat-up-key-link", `sh -c "cd sub && cat ../notes"`, "laptop"},
		{"cd-sub-cd-up-cat-key-link", "cd sub && cd .. && cat notes", "laptop"},
		{"cd-sub-cat-notes", "cd sub && cat notes", "exact"},
		{"cd-sub-semicolon-cat-notes", "cd sub; cat notes", "exact"},
		{"sh-c-cd-sub-cat-notes", `sh -c "cd sub && cat notes"`, "exact"},
		{"eval-cd-sub-cat-notes", `eval "cd sub && cat notes"`, "exact"},
		{"cat-sub-notes", "cat sub/notes", "exact"},
		{"cd-sub-ls", "cd sub && ls -l", "exact"},
		{"cd-sub-wc-notes", "cd sub && wc -l notes", "exact"},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, _ := gap0545API(t, "claudecode", pack)
			work := filepath.Join(filepath.Dir(filepath.Dir(home)), "work")
			start := filepath.Join(work, "w3")
			if err := os.MkdirAll(filepath.Join(start, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(start, "sub", "notes"), []byte("notes\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for link, target := range map[string]string{
				"notes":       filepath.Join(home, ".ssh", "id_ed25519"),
				"sub/dc-link": filepath.Join(home, ".defenseclaw", "config.yaml"),
			} {
				if err := os.Symlink(target, filepath.Join(start, link)); err != nil {
					t.Fatal(err)
				}
			}
			for _, row := range rows {
				body := func(cwd string) []byte {
					raw, _ := json.Marshal(map[string]any{"session_id": "gap0623", "transcript_path": "", "cwd": cwd,
						"permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
						"tool_input": map[string]any{"command": row.command}, "tool_use_id": "toolu_gap0623"})
					return raw
				}
				host, guest := body(start), body("/work/w3")
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				// The kit runs in the actor, where the work folder is /work
				// and the home /sandbox.
				facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
				if facts != nil {
					raw, err := json.Marshal(facts)
					if err != nil {
						t.Fatal(err)
					}
					facts = &SubstrateFacts{}
					if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), work, "/work")), facts); err != nil {
						t.Fatal(err)
					}
				}
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
				gap0622Check(t, row, la, lr, ca, cr)
			}
		})
	}
}

// TestGAP0622LargePatchOfPlainFilesKeepsLaptopAnswer: a Codex apply_patch
// that adds 40 plain files passes the kit's 32 path facts with no link
// dropped: the actor gives the laptop's answer, not the unknown tier (the
// GUEST-RES5 review of the cut rule), in every pack.
func TestGAP0622LargePatchOfPlainFilesKeepsLaptopAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	codex := gap0545FileShapes()[5]
	for _, pack := range []string{"default", "strict"} {
		api, actor, home, app := gap0545API(t, "codex", pack)
		var patch strings.Builder
		patch.WriteString("*** Begin Patch\n")
		for i := range 40 {
			fmt.Fprintf(&patch, "*** Add File: src/f%d.txt\n+line %d\n", i, i)
		}
		patch.WriteString("*** End Patch\n")
		body := func(cwd string) []byte {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "turn_id": "t", "cwd": cwd,
				"tool_name": "apply_patch", "tool_input": map[string]any{"command": patch.String()}})
			return raw
		}
		host, guest := body(app), body(sandboxauth.SandboxHome+"/app")
		la, lr := gap0545Verdict(t, api, context.Background(), codex, host)
		facts := gap0545KitFacts(t, "codex", "PreToolUse", host, home)
		ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, "codex", "PreToolUse", guest, facts), codex, guest)
		if facts == nil || !facts.Truncated {
			t.Errorf("%s: facts %+v, want the 32-fact cut", pack, facts)
		}
		if ca != la || !slices.Equal(cr, lr) {
			t.Errorf("%s: 40-file patch: actor %s %v, laptop %s %v", pack, ca, cr, la, lr)
		}
	}
}
