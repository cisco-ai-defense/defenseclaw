package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDirectoryStackTildeCopyIsNotAKeysWrite is the GAP-2552 proof: after
// pushd or cd, a copy or archive whose source is a bash directory-stack
// tilde (~1, ~-, ~+2) naming the project directory is not read as a copy
// that may keep an unknown link, so it does not raise
// persistence.ssh_authorized_keys_command. A directory-stack word that names
// ~/.ssh still blocks a key read or write, and a copy into the keys file
// still blocks.
func TestDirectoryStackTildeCopyIsNotAKeysWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory stack")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), filepath.Join(cwd, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"pushd src && cp ~1/a.txt .", false},
		{"pushd src && cp ~1/a.txt b.txt", false},
		{"cd src && cp ~-/a.txt b.txt", false},
		{"pushd /tmp && tar czf out.tgz ~1", false},
		{"pushd src && tar czf out.tgz ~1", false},
		{"pushd src; pushd ..; cp ~1/../a.txt c.txt", false},
		// A recursive copy keeps links; the walk reads the directory the
		// stack word names and finds none there (GAP-2586).
		{"pushd src && cp -r ~1/src src-copy", false},
		{"pushd ~/.ssh && pushd /tmp && cp ~1/id_ed25519 /tmp/k", true},
		{"pushd ~/.ssh; dirs -c; ls ~1", false},
		{"pushd ~/.ssh; dirs -v", false},
		{"pushd ~/.ssh; dirs -c; cat id_ed25519", true},
		{"pushd ~/.ssh && pushd /tmp && cp a.txt ~1/authorized_keys", true},
		{"pushd src && cp a.txt ~/.ssh/authorized_keys", true},
		{"pushd ~/.defenseclaw && pushd /tmp && cp a.txt ~1/config.yaml", true},
	}
	for _, mode := range []string{"action"} {
		for _, row := range rows {
			api := activeClaudeCodeTestAPI()
			api.scannerCfg.Guardrail.Mode = mode
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap2552", CWD: cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": row.command},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if blocked := resp.Action == "block"; blocked != row.block {
				t.Errorf("%s %q: block=%t, want %t: %v", mode, row.command, blocked, row.block, resp.Findings)
			}
		}
	}
}
