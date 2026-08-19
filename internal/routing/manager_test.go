package routing

import (
	"context"
	"os"
	"testing"
)

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func TestManager_NewManager(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	if mgr.dataDir != tmpDir {
		t.Errorf("NewManager() dataDir = %q, want %q", mgr.dataDir, tmpDir)
	}
}

func TestManager_IsInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Just check it returns a bool without panic
	result := mgr.IsInstalled()
	t.Logf("IsInstalled() = %v", result)
}

func TestManager_InstalledVersion_NotInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// When vllm-sr is not installed, should return empty string
	version := mgr.InstalledVersion()
	t.Logf("InstalledVersion() = %q (expected empty when not installed)", version)
}

func TestManager_DockerAvailable(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Just verify it returns a bool without panic
	result := mgr.DockerAvailable()
	t.Logf("DockerAvailable() = %v", result)
}

func TestManager_EnsureInstalled_AlreadyInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Skip if not actually installed
	if !mgr.IsInstalled() {
		t.Skip("vllm-sr not installed, skipping test")
	}

	ctx := testContext(t)
	err := mgr.EnsureInstalled(ctx, "")
	if err != nil {
		t.Errorf("EnsureInstalled() unexpected error: %v", err)
	}

	version := mgr.InstalledVersion()
	t.Logf("Installed version: %s", version)
}

func TestManager_EnsureInstalled_WithVersion(t *testing.T) {
	if os.Getenv("RUN_PIP_INSTALL_TESTS") != "1" {
		t.Skip("Skipping pip install test (set RUN_PIP_INSTALL_TESTS=1 to run)")
	}

	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	ctx := testContext(t)
	err := mgr.EnsureInstalled(ctx, defaultSRVersion)
	if err != nil {
		t.Errorf("EnsureInstalled() error: %v", err)
	}

	if !mgr.IsInstalled() {
		t.Error("EnsureInstalled() completed but vllm-sr not found on PATH")
	}
}
