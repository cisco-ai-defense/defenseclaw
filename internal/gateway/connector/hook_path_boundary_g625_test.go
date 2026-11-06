package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These commands name user paths after path cleaning. They do not name a
// file inside the managed hooks directory.
func TestGAP0625PathBoundaryBenignPathCleanupHermes(t *testing.T) {
	for _, form := range []struct {
		name string
		make func(string) string
	}{
		{"parent", func(hooks string) string { return hooks + "/../user-hook.sh" }},
		{"nested parent", func(hooks string) string { return hooks + "/sub/../../user-hook.sh" }},
		{"prefixed path", func(hooks string) string { return "/elsewhere" + hooks + "/hookX" }},
		{"home parent", func(hooks string) string { return "$HOME/.defenseclaw/hooks/../user-hook.sh" }},
	} {
		t.Run(form.name, func(t *testing.T) {
			conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
			command := form.make(filepath.Join(opts.DataDir, "hooks"))
			gap0625SetHermesCommand(t, configPath, command)
			verifyErr := conn.VerifyClean(opts)
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if verifyErr != nil {
				t.Errorf("ordinary command marked managed by VerifyClean: %v", verifyErr)
			}
			if len(commands) != 2 || commands[0] != command || commands[1] != userHook {
				t.Errorf("ordinary command removed: %q", commands)
			}
		})
	}
}

func TestGAP0625PathBoundaryProtectedLinkPunctuationHermes(t *testing.T) {
	for _, name := range []string{"owned link", "owned,link", "owned=link"} {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
			hooks := filepath.Join(opts.DataDir, "hooks")
			if err := os.MkdirAll(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			owned := filepath.Join(hooks, "owned-file")
			if err := os.WriteFile(owned, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(filepath.Dir(opts.DataDir), name)
			if err := os.Symlink(owned, link); err != nil {
				t.Fatal(err)
			}
			command := shellWord(link)
			gap0625SetHermesCommand(t, configPath, command)
			verifyErr := conn.VerifyClean(opts)
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if verifyErr == nil {
				t.Error("VerifyClean accepted link into managed hooks directory")
			}
			if len(commands) != 1 || commands[0] != userHook {
				t.Errorf("managed link entry remains: %q", commands)
			}
		})
	}
}

func TestGAP0625PathBoundaryBenignPathCleanupDevinCursor(t *testing.T) {
	for _, kind := range []string{"devin", "cursor"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "hooks", kind+"-hook.sh")
			command := filepath.Join(root, "hooks") + "/../user-hook.sh"
			if kind == "devin" {
				path, user := gap0625DevinConfig(t, command)
				present, readErr := devinConfigReferencesHook(path, script)
				if err := removeDevinHookReferences(path, script); err != nil {
					t.Fatal(err)
				}
				got := devinConfigCommands(t, path)
				if readErr != nil || present {
					t.Errorf("ordinary command marked managed: present=%v err=%v", present, readErr)
				}
				if strings.Join(got, "\n") != "PreToolUse="+command+"\nPreToolUse="+user {
					t.Errorf("ordinary command removed: %q", got)
				}
				return
			}
			path, user := gap0625CursorConfig(t, command)
			previous := CursorHooksPathOverride
			CursorHooksPathOverride = path
			t.Cleanup(func() { CursorHooksPathOverride = previous })
			verifyErr := NewCursorConnector().VerifyClean(SetupOpts{DataDir: root})
			if err := removeCursorHookReferencesProfile(path, false, script); err != nil {
				t.Fatal(err)
			}
			cfg, err := readJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			entries, _ := cfg["hooks"].(map[string]interface{})[cursorHookEvents[0]].([]interface{})
			if verifyErr != nil {
				t.Errorf("ordinary command marked managed: %v", verifyErr)
			}
			if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != command || entries[1].(map[string]interface{})["command"] != user {
				t.Errorf("ordinary command removed: %v", entries)
			}
		})
	}
}

func TestGAP0625PathBoundaryProtectedNamedPathVariants(t *testing.T) {
	for _, form := range []struct {
		name string
		make func(string) string
	}{
		{"quote fragments", func(p string) string { return "'" + p[:len(p)-5] + "'" + p[len(p)-5:] }},
		{"parent then hooks", func(p string) string { return filepath.Dir(p) + "/other/../hookX" }},
		{"repeated separators", func(p string) string { return strings.Replace(p, "/hooks/", "//hooks/./", 1) }},
		{"known value", func(p string) string { return "HOOK=" + p + "; eval \"$HOOK\"" }},
		{"function body", func(p string) string { return "f() { " + p + "; }; f" }},
	} {
		t.Run(form.name, func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			command := form.make(renamed)
			gap0625SetHermesCommand(t, configPath, command)
			if err := conn.VerifyClean(opts); err == nil {
				t.Error("VerifyClean accepted protected entry")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if len(commands) != 1 || commands[0] != userHook {
				t.Errorf("protected entry remains: %q", commands)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Errorf("VerifyClean after teardown: %v", err)
			}
		})
	}
}

func TestGAP0625PathBoundaryProtectedLinkPunctuationDevinCursor(t *testing.T) {
	for _, kind := range []string{"devin", "cursor"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			hooks := filepath.Join(root, "hooks")
			if err := os.MkdirAll(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			owned := filepath.Join(hooks, "owned-file")
			if err := os.WriteFile(owned, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "owned link")
			if err := os.Symlink(owned, link); err != nil {
				t.Fatal(err)
			}
			command := shellWord(link)
			script := filepath.Join(hooks, kind+"-hook.sh")
			if kind == "devin" {
				path, user := gap0625DevinConfig(t, command)
				present, readErr := devinConfigReferencesHook(path, script)
				if err := removeDevinHookReferences(path, script); err != nil {
					t.Fatal(err)
				}
				got := devinConfigCommands(t, path)
				if readErr != nil || !present {
					t.Errorf("managed link missed: present=%v err=%v", present, readErr)
				}
				if len(got) != 1 || got[0] != "PreToolUse="+user {
					t.Errorf("managed link entry remains: %q", got)
				}
				return
			}
			path, user := gap0625CursorConfig(t, command)
			previous := CursorHooksPathOverride
			CursorHooksPathOverride = path
			t.Cleanup(func() { CursorHooksPathOverride = previous })
			verifyErr := NewCursorConnector().VerifyClean(SetupOpts{DataDir: root})
			if err := removeCursorHookReferencesProfile(path, false, script); err != nil {
				t.Fatal(err)
			}
			cfg, err := readJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			entries, _ := cfg["hooks"].(map[string]interface{})[cursorHookEvents[0]].([]interface{})
			if verifyErr == nil {
				t.Error("VerifyClean accepted managed link")
			}
			if len(entries) != 1 || entries[0].(map[string]interface{})["command"] != user {
				t.Errorf("managed link entry remains: %v", entries)
			}
		})
	}
}

// The ownership rule reads path words from command text. A word names the
// managed directory only after cleaning, and a complete file name with a
// space, comma or equals sign stays one word.
func TestGAP0625PathBoundaryText(t *testing.T) {
	root := t.TempDir()
	hooks := filepath.Join(root, ".defenseclaw", "hooks")
	script := filepath.Join(hooks, "hook.sh")
	for _, form := range []struct {
		name    string
		command string
		want    bool
	}{
		{"quoted name with space", "bash '" + hooks + "/my hook.sh' --event x", true},
		{"assignment", "X=" + hooks + "/a", true},
		{"list entry", "cd /usr:" + hooks, true},
		{"parent step", hooks + "/../user.sh", false},
		{"sibling directory", hooks + "2/x", false},
		{"longer prefix", "/elsewhere" + hooks + "/x", false},
		{"path with equals", "/elsewhere/a=" + hooks + "/x", false},
		{"user hook", filepath.Join(root, "bin", "user.sh"), false},
	} {
		if got := hookCommandNamesHookDir(form.command, script); got != form.want {
			t.Errorf("%s: hookCommandNamesHookDir(%q) = %v, want %v", form.name, form.command, got, form.want)
		}
	}
}
