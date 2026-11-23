// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1983: a second DefenseClaw handler in config.toml (a copy of the
// script from another account or a dotfiles repo, in any of its path forms)
// made Setup fail "multiple DefenseClaw handlers require manual repair", so a
// gateway restart failed and left every connector down. Setup now removes a
// copy that has a matcher group of its own. A copy inside a group of other
// handlers is refused before Setup changes anything, with the exact step.

const gap1983CopyBinding = "codex-hook.sh --event PostToolUse --hook-contract codex-hooks-v4"

var gap1983CopyForms = map[string]string{
	"posix":                    "/Users/fx1983peer/.defenseclaw/hooks/",
	"drive, forward slashes":   "C:/Users/fx1983peer/.defenseclaw/hooks/",
	`drive, backslashes`:       `C:\Users\fx1983peer\.defenseclaw\hooks\`,
	"edited data dir, matcher": "/Users/fx1983peer/.defenseclaw-old/hooks/",
}

// gap1983Group renders one [[hooks.PostToolUse]] group with these commands.
func gap1983Group(matcher string, commands ...string) string {
	var b strings.Builder
	b.WriteString("\n[[hooks.PostToolUse]]\n")
	if matcher != "" {
		b.WriteString("matcher = '" + matcher + "'\n")
	}
	for _, command := range commands {
		b.WriteString("\n[[hooks.PostToolUse.hooks]]\ncommand = '" + command + "'\ntimeout = 30\ntype = 'command'\n")
	}
	return b.String()
}

func gap1983Setup(t *testing.T) (*CodexConnector, SetupOpts, string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	path := filepath.Join(root, "agent", "config.toml")
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = previous })
	opts := gap1923SetupOpts(root)
	codex := NewCodexConnector()
	if err := codex.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	if !strings.Contains(readHookFileForTest(t, path), "[[hooks.PostToolUse]]") {
		t.Fatal("fixture: Setup registered no PostToolUse hook")
	}
	return codex, opts, path
}

// gap1983OwnedPostToolUse counts the DefenseClaw handlers of PostToolUse.
func gap1983OwnedPostToolUse(t *testing.T, path, hooksDir string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	count := 0
	groups, _ := hooks["PostToolUse"].([]interface{})
	for _, rawGroup := range groups {
		group, _ := rawGroup.(map[string]interface{})
		handlers, _ := group["hooks"].([]interface{})
		for _, handler := range handlers {
			if isOwnedCodexHookHandler(handler, hooksDir) {
				count++
			}
		}
	}
	return count
}

func TestGAP1983CodexSetupRemovesASecondDefenseClawHandler(t *testing.T) {
	const userHook = "/opt/fx1983keep/bin/review-hook"
	for _, name := range gap1923Names(gap1983CopyForms) {
		copied := gap1983CopyForms[name] + gap1983CopyBinding
		matcher := ""
		if strings.Contains(name, "matcher") {
			matcher = "Bash"
		}
		for _, place := range []string{"last", "before a user group"} {
			t.Run(name+", "+place, func(t *testing.T) {
				codex, opts, path := gap1983Setup(t)
				base := readHookFileForTest(t, path)
				seeded := base + gap1983Group(matcher, copied)
				if place != "last" {
					seeded += gap1983Group("*", userHook)
				}
				gap1923WriteFile(t, path, seeded)
				if err := codex.Setup(context.Background(), opts); err != nil {
					t.Fatalf("Setup with a second DefenseClaw handler: %v", err)
				}
				text := readHookFileForTest(t, path)
				if strings.Contains(strings.ToLower(text), "fx1983peer") {
					t.Errorf("Setup kept the copied DefenseClaw handler %q:\n%s", copied, text)
				}
				if place != "last" && strings.Count(text, "fx1983keep") != 1 {
					t.Errorf("Setup lost the user's hook:\n%s", text)
				}
				if got := gap1983OwnedPostToolUse(t, path, filepath.Join(opts.DataDir, "hooks")); got != 1 {
					t.Errorf("PostToolUse has %d DefenseClaw handlers after Setup, want 1:\n%s", got, text)
				}
			})
		}
	}
}

func TestGAP1983CodexSetupRefusesASharedGroupCopyBeforeAnyChange(t *testing.T) {
	const userHook = "/opt/fx1983keep/bin/review-hook"
	for _, name := range gap1923Names(gap1983CopyForms) {
		copied := gap1983CopyForms[name] + gap1983CopyBinding
		t.Run(name, func(t *testing.T) {
			codex, opts, path := gap1983Setup(t)
			seeded := readHookFileForTest(t, path) + gap1983Group("*", userHook, copied)
			gap1923WriteFile(t, path, seeded)
			err := codex.Setup(context.Background(), opts)
			if !errors.Is(err, ErrAgentConfigRefusal) || !errors.Is(err, ErrSetupRefusedUnchanged) {
				t.Fatalf("Setup error = %v, want a refusal before any change (ErrAgentConfigRefusal)", err)
			}
			for _, want := range []string{copied, path, "PostToolUse", "then run: defenseclaw setup codex"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not name %q: %v", want, err)
				}
			}
			if got := readHookFileForTest(t, path); got != seeded {
				t.Errorf("a refused Setup changed config.toml:\n%s", got)
			}
			// setup asks this before it restarts the gateway (GAP-0615).
			if check := CheckAgentSettings(codex, opts); !errors.Is(check, ErrAgentConfigRefusal) || check.Error() != err.Error() {
				t.Errorf("CheckAgentSettings = %v, want the Setup refusal %v", check, err)
			}
		})
	}
}

// GAP-2007: the user's own PostToolUse group existed before DefenseClaw's
// first Setup, so DefenseClaw's group follows it, and a copy of DefenseClaw's
// handler sits inside the user's group. Under the generated matcher Setup
// takes the copy's slot and drops its own later group; under the user's own
// matcher the copy is the second handler, refused before any change with the
// exact delete step, so `defenseclaw setup` stops before it restarts the
// gateway.
func TestGAP1983CodexSetupCopyInsideAnEarlierUserGroup(t *testing.T) {
	const userHook = "/opt/fx2007keep/bin/review-hook"
	forms := []string{"posix", "drive, forward slashes", `drive, backslashes`}
	for _, matcher := range []string{"Bash", "*"} {
		for _, name := range forms {
			copied := gap1983CopyForms[name] + gap1983CopyBinding
			t.Run("matcher "+matcher+", "+name, func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				path := filepath.Join(root, "agent", "config.toml")
				previous := CodexConfigPathOverride
				CodexConfigPathOverride = path
				t.Cleanup(func() { CodexConfigPathOverride = previous })
				opts := gap1923SetupOpts(root)
				gap1923WriteFile(t, path, gap1983Group(matcher, userHook))
				codex := NewCodexConnector()
				if err := codex.Setup(context.Background(), opts); err != nil {
					t.Fatalf("first Setup: %v", err)
				}
				text := readHookFileForTest(t, path)
				first := strings.Index(text, "[[hooks.PostToolUse]]")
				second := -1
				if first >= 0 {
					if i := strings.Index(text[first+1:], "[[hooks.PostToolUse]]"); i >= 0 {
						second = first + 1 + i
					}
				}
				if first < 0 || second < 0 || !strings.Contains(text[first:second], "fx2007keep") {
					t.Fatalf("fixture: want the user's group first, then DefenseClaw's:\n%s", text)
				}
				block := "[[hooks.PostToolUse.hooks]]\ncommand = '" + copied + "'\ntimeout = 30\ntype = 'command'\n\n"
				seeded := text[:second] + block + text[second:]
				gap1923WriteFile(t, path, seeded)
				check := CheckAgentSettings(codex, opts)
				err := codex.Setup(context.Background(), opts)
				after := readHookFileForTest(t, path)
				if matcher == "*" {
					if check != nil || err != nil {
						t.Fatalf("CheckAgentSettings = %v, Setup = %v; want the copy repaired", check, err)
					}
					if strings.Contains(strings.ToLower(after), "fx1983peer") {
						t.Errorf("Setup kept the copied DefenseClaw handler %q:\n%s", copied, after)
					}
					if strings.Count(after, "fx2007keep") != 1 {
						t.Errorf("Setup lost the user's hook:\n%s", after)
					}
					if got := gap1983OwnedPostToolUse(t, path, filepath.Join(opts.DataDir, "hooks")); got != 1 {
						t.Errorf("PostToolUse has %d DefenseClaw handlers after Setup, want 1:\n%s", got, after)
					}
					return
				}
				if !errors.Is(err, ErrAgentConfigRefusal) || !errors.Is(err, ErrSetupRefusedUnchanged) {
					t.Fatalf("Setup error = %v, want a refusal before any change (ErrAgentConfigRefusal)", err)
				}
				for _, want := range []string{copied, path, "PostToolUse", "matcher group 1", "then run: defenseclaw setup codex"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal does not name %q: %v", want, err)
					}
				}
				if after != seeded {
					t.Errorf("a refused Setup changed config.toml:\n%s", after)
				}
				// setup asks this before it restarts the gateway (GAP-0615).
				if !errors.Is(check, ErrAgentConfigRefusal) || check.Error() != err.Error() {
					t.Errorf("CheckAgentSettings = %v, want the Setup refusal %v", check, err)
				}
			})
		}
	}
}

// GAP-2007: DefenseClaw's own handler in a group of the user's handlers whose
// matcher the user changed is not Setup's to rewrite either. It was a plain
// Setup error, so `defenseclaw setup` restarted the gateway and the start
// failed; it is now refused before any change and names the entry.
func TestGAP1983CodexSetupRefusesAnEditedSharedGroupBeforeAnyChange(t *testing.T) {
	const userHook = "/opt/fx2007keep/bin/review-hook"
	codex, opts, path := gap1983Setup(t)
	text := readHookFileForTest(t, path)
	cfg := map[string]interface{}{}
	if err := parseCodexTOML([]byte(text), &cfg); err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	groups, _ := hooks["PostToolUse"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("fixture: PostToolUse groups = %d, want 1:\n%s", len(groups), text)
	}
	group, _ := groups[0].(map[string]interface{})
	handlers, _ := group["hooks"].([]interface{})
	if len(handlers) != 1 {
		t.Fatalf("fixture: PostToolUse handlers = %d, want 1:\n%s", len(handlers), text)
	}
	own, _ := handlers[0].(map[string]interface{})["command"].(string)
	group["matcher"] = "Bash"
	group["hooks"] = append(handlers, map[string]interface{}{"command": userHook, "timeout": int64(30), "type": "command"})
	edited, err := editCodexOwnedTOML([]byte(text), map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	seeded := string(edited)
	gap1923WriteFile(t, path, seeded)
	check := CheckAgentSettings(codex, opts)
	err = codex.Setup(context.Background(), opts)
	if !errors.Is(err, ErrAgentConfigRefusal) || !errors.Is(err, ErrSetupRefusedUnchanged) {
		t.Fatalf("Setup error = %v, want a refusal before any change (ErrAgentConfigRefusal)", err)
	}
	for _, want := range []string{path, "PostToolUse", "matcher group 1", "Bash", own, "then run: defenseclaw setup codex"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	if got := readHookFileForTest(t, path); got != seeded {
		t.Errorf("a refused Setup changed config.toml:\n%s", got)
	}
	if !errors.Is(check, ErrAgentConfigRefusal) || check.Error() != err.Error() {
		t.Errorf("CheckAgentSettings = %v, want the Setup refusal %v", check, err)
	}
}
