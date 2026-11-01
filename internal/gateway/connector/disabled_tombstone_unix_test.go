//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1978: a teardown runs as the account; a hook folder that account
// cannot search (root-owned ~/.defenseclaw/hooks after sudo with HOME kept)
// holds no script its agents can run, so the disabled tombstone is not a
// failure and the folder is left as it is. A fail-closed rollback still
// reports the error.
func TestDisabledHookTombstoneSkipsAHookFolderTheAccountCannotSearch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can search every folder")
	}
	dataDir := t.TempDir()
	hooks := filepath.Join(dataDir, "hooks")
	script := filepath.Join(hooks, "hermes-hook.sh")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho real hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hooks, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })

	if err := writeDisabledHookTombstone(SetupOpts{DataDir: dataDir}, "hermes-hook.sh", "hermes"); err != nil {
		t.Fatalf("writeDisabledHookTombstone = %v; want nil for a folder the account cannot search", err)
	}
	if err := writeDisabledHookTombstone(SetupOpts{DataDir: dataDir, FailedSetupFailClosed: true}, "claude-code-hook.sh", "Claude Code"); err == nil {
		t.Fatal("fail-closed rollback placeholder: want the permission error, got nil")
	}
	if err := os.Chmod(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(script)
	if err != nil || string(body) != "#!/bin/sh\necho real hook\n" {
		t.Fatalf("the unreachable script was changed: %q, %v", body, err)
	}
}

// The ordinary teardown still writes the tombstone.
func TestDisabledHookTombstoneWritesInAReadableHookFolder(t *testing.T) {
	dataDir := t.TempDir()
	if err := writeDisabledHookTombstone(SetupOpts{DataDir: dataDir}, "hermes-hook.sh", "hermes"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dataDir, "hooks", "hermes-hook.sh"))
	if err != nil || string(body) != disabledHookTombstone("hermes") {
		t.Fatalf("tombstone = %q, %v", body, err)
	}
}
