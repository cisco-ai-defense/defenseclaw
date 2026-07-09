package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	srReleaseURLTemplate  = "https://github.com/vllm-project/semantic-router/releases/download/v%s/semantic-router-%s-%s%s"
	srChecksumURLTemplate = "https://github.com/vllm-project/semantic-router/releases/download/v%s/checksums.txt"
	defaultSRVersion      = "0.3.0"
)

// EnvSRBinary allows operators to point at a pre-built SR binary (e.g. from
// a local build of github.com/vllm-project/semantic-router/src/semantic-router).
// When set, the binary manager skips download and uses this path directly.
const EnvSRBinary = "SEMANTIC_ROUTER_BIN"

// BinaryManager handles downloading and verifying the semantic router binary.
type BinaryManager struct {
	dataDir string // ~/.defenseclaw
}

// NewBinaryManager creates a manager for the given data directory.
func NewBinaryManager(dataDir string) *BinaryManager {
	return &BinaryManager{dataDir: dataDir}
}

// BinaryPath returns the expected path of the SR binary.
func (m *BinaryManager) BinaryPath() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return filepath.Join(m.dataDir, "bin", "semantic-router"+ext)
}

// InstalledVersion reads the version of the installed binary.
// Returns "" if not installed.
func (m *BinaryManager) InstalledVersion() string {
	versionFile := filepath.Join(m.dataDir, "bin", ".semantic-router-version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// NeedsDownload returns true if the binary is missing or version doesn't match.
func (m *BinaryManager) NeedsDownload(desiredVersion string) bool {
	if desiredVersion == "" {
		desiredVersion = defaultSRVersion
	}
	binPath := m.BinaryPath()
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return true
	}
	return m.InstalledVersion() != desiredVersion
}

// EnsureBinary downloads the SR binary if needed. Returns the binary path.
func (m *BinaryManager) EnsureBinary(ctx context.Context, version string) (string, error) {
	// Check for pre-built binary override (e.g. local build from source)
	if override := os.Getenv(EnvSRBinary); override != "" {
		if _, err := os.Stat(override); err == nil {
			fmt.Fprintf(os.Stderr, "[routing] using SEMANTIC_ROUTER_BIN=%s\n", override)
			return override, nil
		}
		return "", fmt.Errorf("routing: SEMANTIC_ROUTER_BIN=%s does not exist", override)
	}

	if version == "" {
		version = defaultSRVersion
	}
	if !m.NeedsDownload(version) {
		return m.BinaryPath(), nil
	}

	fmt.Fprintf(os.Stderr, "[routing] downloading semantic-router v%s for %s/%s...\n", version, runtime.GOOS, runtime.GOARCH)

	binDir := filepath.Join(m.dataDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("routing: create bin dir: %w", err)
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	url := fmt.Sprintf(srReleaseURLTemplate, version, runtime.GOOS, runtime.GOARCH, ext)

	binPath := m.BinaryPath()
	tmpPath := binPath + ".download"

	if err := downloadFile(ctx, url, tmpPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("routing: download SR binary: %w", err)
	}

	// Verify checksum if available
	checksumURL := fmt.Sprintf(srChecksumURLTemplate, version)
	if err := verifyChecksum(ctx, tmpPath, checksumURL, runtime.GOOS, runtime.GOARCH, ext); err != nil {
		// Checksum verification is best-effort — log warning but don't fail
		// (the checksums.txt file may not exist for all releases)
		fmt.Fprintf(os.Stderr, "[routing] checksum verification skipped: %v\n", err)
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("routing: chmod binary: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, binPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("routing: install binary: %w", err)
	}

	// Write version file
	versionFile := filepath.Join(binDir, ".semantic-router-version")
	_ = os.WriteFile(versionFile, []byte(version), 0644)

	fmt.Fprintf(os.Stderr, "[routing] semantic-router v%s installed at %s\n", version, binPath)
	return binPath, nil
}

func downloadFile(ctx context.Context, url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, io.LimitReader(resp.Body, 500*1024*1024)) // 500MB cap
	return err
}

func verifyChecksum(ctx context.Context, filePath, checksumURL, goos, goarch, ext string) error {
	// Download checksums.txt
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums.txt not available (HTTP %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}

	// Find matching line: "<hash>  semantic-router-<os>-<arch><ext>"
	expectedName := fmt.Sprintf("semantic-router-%s-%s%s", goos, goarch, ext)
	var expectedHash string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.Contains(parts[1], expectedName) {
			expectedHash = parts[0]
			break
		}
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", expectedName)
	}

	// Compute actual hash
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}
