package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	srCLIName        = "vllm-sr"
	srPipPackage     = "vllm-sr"
	defaultSRVersion = "0.3.0"
	srInstallScript  = "https://vllm-semantic-router.com/install.sh"
)

// Manager handles installation and version management of vllm-sr.
type Manager struct {
	dataDir string
}

func NewManager(dataDir string) *Manager {
	return &Manager{dataDir: dataDir}
}

// IsInstalled checks if vllm-sr CLI is available on PATH.
func (m *Manager) IsInstalled() bool {
	_, err := exec.LookPath(srCLIName)
	return err == nil
}

// InstalledVersion returns the installed vllm-sr version or "".
func (m *Manager) InstalledVersion() string {
	out, err := exec.Command(srCLIName, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// EnsureInstalled installs vllm-sr via pip if not present.
func (m *Manager) EnsureInstalled(ctx context.Context, version string) error {
	if m.IsInstalled() {
		fmt.Fprintf(os.Stderr, "[routing] vllm-sr already installed (%s)\n", m.InstalledVersion())
		return nil
	}

	fmt.Fprintf(os.Stderr, "[routing] installing vllm-sr via pip...\n")

	pkg := srPipPackage
	if version != "" {
		pkg = fmt.Sprintf("%s==%s", srPipPackage, version)
	}

	cmd := exec.CommandContext(ctx, "pip", "install", pkg)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("routing: pip install vllm-sr failed: %w", err)
	}

	if !m.IsInstalled() {
		return fmt.Errorf("routing: vllm-sr not found on PATH after install")
	}

	fmt.Fprintf(os.Stderr, "[routing] vllm-sr installed successfully (%s)\n", m.InstalledVersion())
	return nil
}

// DockerAvailable checks if Docker is running (required by vllm-sr serve).
func (m *Manager) DockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "docker", "info").Run()
	return err == nil
}
