package routing

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func TestBinaryManager_BinaryPath(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	binPath := mgr.BinaryPath()

	expectedExt := ""
	if runtime.GOOS == "windows" {
		expectedExt = ".exe"
	}
	expectedPath := filepath.Join(tmpDir, "bin", "semantic-router"+expectedExt)

	if binPath != expectedPath {
		t.Errorf("BinaryPath() = %q, want %q", binPath, expectedPath)
	}
}

func TestBinaryManager_NeedsDownload_Missing(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// No binary exists
	if !mgr.NeedsDownload("0.3.0") {
		t.Error("NeedsDownload() = false, want true when binary is missing")
	}
}

func TestBinaryManager_NeedsDownload_VersionMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// Create bin directory and write version file with old version
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	// Create the binary file
	binPath := mgr.BinaryPath()
	if err := os.WriteFile(binPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	// Write old version
	versionFile := filepath.Join(binDir, ".semantic-router-version")
	if err := os.WriteFile(versionFile, []byte("0.2.0"), 0644); err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	// Check if needs download with newer version
	if !mgr.NeedsDownload("0.3.0") {
		t.Error("NeedsDownload() = false, want true when version mismatches")
	}
}

func TestBinaryManager_NeedsDownload_Current(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// Create bin directory
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	// Create the binary file
	binPath := mgr.BinaryPath()
	if err := os.WriteFile(binPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	// Write current version
	versionFile := filepath.Join(binDir, ".semantic-router-version")
	if err := os.WriteFile(versionFile, []byte("0.3.0"), 0644); err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	// Check if needs download with same version
	if mgr.NeedsDownload("0.3.0") {
		t.Error("NeedsDownload() = true, want false when version matches and binary exists")
	}
}

func TestBinaryManager_InstalledVersion_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// No version file exists
	version := mgr.InstalledVersion()
	if version != "" {
		t.Errorf("InstalledVersion() = %q, want empty string when no version file exists", version)
	}
}

func TestBinaryManager_InstalledVersion_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// Create bin directory and write version file
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	versionFile := filepath.Join(binDir, ".semantic-router-version")
	if err := os.WriteFile(versionFile, []byte("0.3.0\n"), 0644); err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	// Check installed version
	version := mgr.InstalledVersion()
	if version != "0.3.0" {
		t.Errorf("InstalledVersion() = %q, want %q", version, "0.3.0")
	}
}

func TestBinaryManager_EnsureBinary_AlreadyInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// Create bin directory
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	// Create the binary file
	binPath := mgr.BinaryPath()
	if err := os.WriteFile(binPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	// Write current version
	versionFile := filepath.Join(binDir, ".semantic-router-version")
	if err := os.WriteFile(versionFile, []byte("0.3.0"), 0644); err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	// EnsureBinary should return immediately without download
	ctx := testContext(t)
	resultPath, err := mgr.EnsureBinary(ctx, "0.3.0")
	if err != nil {
		t.Errorf("EnsureBinary() unexpected error: %v", err)
	}

	if resultPath != binPath {
		t.Errorf("EnsureBinary() = %q, want %q", resultPath, binPath)
	}

	// Verify binary content unchanged (no download occurred)
	content, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("failed to read binary: %v", err)
	}
	if string(content) != "fake binary" {
		t.Error("EnsureBinary() modified existing binary when it shouldn't")
	}
}

func TestBinaryManager_NeedsDownload_DefaultVersion(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewBinaryManager(tmpDir)

	// Create bin directory
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	// Create the binary file
	binPath := mgr.BinaryPath()
	if err := os.WriteFile(binPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	// Write default version
	versionFile := filepath.Join(binDir, ".semantic-router-version")
	if err := os.WriteFile(versionFile, []byte(defaultSRVersion), 0644); err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	// Check with empty string (should use default)
	if mgr.NeedsDownload("") {
		t.Error("NeedsDownload(\"\") = true, want false when default version matches")
	}
}
