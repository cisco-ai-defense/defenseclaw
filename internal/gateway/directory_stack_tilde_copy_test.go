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
		// stack word names after a static pushd like any source (GAP-2586).
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

// A copy after a static pushd runs in the directory the pushd names, as
// after cd, and a plain popd returns to the directory the pushd left. The
// link reading placed copies only after cd, so pushd src && cp -r
// ../ordinary x and pushd src && rsync -a ../ordinary/ out/ read their
// sources in the starting directory, where the missing source counted as a
// possible link and made the write unknown: a benign copy was blocked as an
// SSH authorized_keys write (GAP-2586). A pushd into the home that writes
// the keys file or through a copied link still blocks.
func TestPushdRecursiveCopyReadsSourcesInTheNewDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory stack")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), filepath.Join(cwd, "src"),
		filepath.Join(cwd, "ordinary"), filepath.Join(home, "linked")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "ordinary", "n.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, "linked", "lnk")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"pushd src && cp -r ../ordinary ord4", false},
		{"pushd src && rsync -a ../ordinary/ out/", false},
		{"pushd src && cp -a ../ordinary ord5 && popd", false},
		{"pushd src && popd && cp -r ordinary ord6", false},
		{"pushd src; pushd ..; popd; cp -r ../ordinary ord7", false},
		{"( pushd src && cp -r ../ordinary ord8 ) && cp -r ordinary ord9", false},
		{"pushd ~ && cp project/a.txt .ssh/authorized_keys", true},
		{"pushd ~ && cp -r project/a.txt .defenseclaw/config.yaml", true},
		{"pushd ~ && cp -a linked linked-bak && echo k >> linked-bak/lnk", true},
		{"pushd src && cp -r ~1/ordinary ord10", false},
		{"pushd src && rsync -a ~1/ordinary/ out/", false},
		{"pushd src && cp -r ~+1/ordinary ord11 && cp -r ~-0/ordinary ord12", false},
		{"pushd src && tar czf o.tgz ~1/ordinary", false},
		{"pushd src && cp -a ~1/../linked lb && echo k >> lb/lnk", true},
		{"pushd src && rsync -a ~1/../linked/ lb2/ && echo k >> lb2/lnk", true},
		{"pushd src && dirs -c && cp -r ~1/ordinary ord13", true},
		{"pushd src && cp -r ~2/ordinary ord14", true},
		{"pushd ~/.ssh && popd && pushd ~ && cp project/a.txt .ssh/authorized_keys", true},
		{"pushd /tmp && popd && cp a.txt ~/.ssh/authorized_keys", true},
	}
	for _, mode := range []string{"action"} {
		for _, row := range rows {
			api := activeClaudeCodeTestAPI()
			api.scannerCfg.Guardrail.Mode = mode
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap2586", CWD: cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": row.command},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if blocked := resp.Action == "block"; blocked != row.block {
				t.Errorf("%s %q: block=%t, want %t: %v", mode, row.command, blocked, row.block, resp.Findings)
			}
		}
	}
}
