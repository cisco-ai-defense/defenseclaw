package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func antigravityTeardownFixture(t *testing.T) (Connector, SetupOpts) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	prev := AntigravityHooksPathOverride
	AntigravityHooksPathOverride = cfgPath
	t.Cleanup(func() { AntigravityHooksPathOverride = prev })
	return NewAntigravityConnector(), SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
}

// GAP-2335: setup remove antigravity (and guardrail disable) leaves no
// antigravity-hook.sh behind, not even the inert stub.
func TestAntigravityTeardownRemovesItsHookScript(t *testing.T) {
	conn, opts := antigravityTeardownFixture(t)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	hookPath := filepath.Join(opts.DataDir, "hooks", "antigravity-hook.sh")
	if _, err := os.Stat(hookPath); err != nil {
		t.Fatalf("hook script missing after Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Lstat(hookPath); !errors.Is(err, os.ErrNotExist) {
		body, _ := os.ReadFile(hookPath)
		t.Fatalf("antigravity-hook.sh still there after Teardown (err=%v):\n%s", err, body)
	}
	// A second teardown (nothing left) is not an error.
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// A file at the hook path without the DefenseClaw marker is not deleted:
// teardown replaces it with the disabled tombstone, as before.
func TestAntigravityTeardownDoesNotDeleteAForeignHookFile(t *testing.T) {
	conn, opts := antigravityTeardownFixture(t)
	hookPath := filepath.Join(opts.DataDir, "hooks", "antigravity-hook.sh")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho operator\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	body, err := os.ReadFile(hookPath)
	if err != nil || string(body) != disabledHookTombstone("antigravity") {
		t.Fatalf("foreign hook file = %q, %v; want the disabled tombstone", body, err)
	}
}
