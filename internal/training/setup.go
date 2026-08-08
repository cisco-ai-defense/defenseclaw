// internal/training/setup.go
// Auto-setup for GRPO training dependencies.
// Installs llama.cpp and builds the C engine on first use.
package training

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SetupStatus describes what's installed
type SetupStatus struct {
	LlamaCppInstalled bool
	LlamaCppVersion   string
	EngineBuilt       bool
	EnginePath        string
	Platform          string
	Error             string
}

// CheckSetup verifies all training dependencies are available.
func CheckSetup() SetupStatus {
	status := SetupStatus{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	// Check llama.cpp
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("brew", "list", "llama.cpp", "--versions").Output()
		if err == nil {
			status.LlamaCppInstalled = true
			status.LlamaCppVersion = strings.TrimSpace(string(out))
		}
	case "linux":
		// Check if libllama.so exists in standard paths
		paths := []string{"/usr/lib/libllama.so", "/usr/local/lib/libllama.so"}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				status.LlamaCppInstalled = true
				status.LlamaCppVersion = "system"
				break
			}
		}
	}

	// Check engine library
	enginePaths := []string{
		"pkg/grpo_engine/libgrpo_stream.a",
		filepath.Join(os.Getenv("HOME"), ".defenseclaw/grpo_engine/libgrpo_stream.a"),
	}
	for _, p := range enginePaths {
		if _, err := os.Stat(p); err == nil {
			status.EngineBuilt = true
			status.EnginePath = p
			break
		}
	}

	return status
}

// EnsureSetup installs all required dependencies for training.
// Returns nil if everything is ready, or an error describing what failed.
func EnsureSetup() error {
	status := CheckSetup()

	if status.LlamaCppInstalled && status.EngineBuilt {
		return nil // already good
	}

	fmt.Fprintf(os.Stderr, "\n⚠  Training engine setup required\n\n")

	// Step 1: Install llama.cpp
	if !status.LlamaCppInstalled {
		if err := installLlamaCpp(); err != nil {
			return fmt.Errorf("failed to install llama.cpp: %w", err)
		}
	}

	// Step 2: Build engine
	if !status.EngineBuilt {
		if err := buildEngine(); err != nil {
			return fmt.Errorf("failed to build engine: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "\n✓  Setup complete. Starting training...\n\n")
	return nil
}

func installLlamaCpp() error {
	switch runtime.GOOS {
	case "darwin":
		fmt.Fprintf(os.Stderr, "→ Installing llama.cpp via Homebrew...\n")
		cmd := exec.Command("brew", "install", "llama.cpp")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Try upgrade if already installed but outdated
			cmd = exec.Command("brew", "upgrade", "llama.cpp")
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err2 := cmd.Run(); err2 != nil {
				return fmt.Errorf("brew install/upgrade failed: %v / %v", err, err2)
			}
		}
		fmt.Fprintf(os.Stderr, "  ✓ llama.cpp installed\n")
		return nil

	case "linux":
		fmt.Fprintf(os.Stderr, "→ Installing llama.cpp from source...\n")
		// Clone and build
		tmpDir := "/tmp/llama-cpp-build"
		os.RemoveAll(tmpDir)

		cmds := [][]string{
			{"git", "clone", "--depth=1", "https://github.com/ggerganov/llama.cpp", tmpDir},
			{"cmake", "-B", tmpDir + "/build", "-S", tmpDir, "-DCMAKE_INSTALL_PREFIX=/usr/local"},
			{"cmake", "--build", tmpDir + "/build", "--config", "Release", "-j"},
			{"sudo", "cmake", "--install", tmpDir + "/build"},
		}
		for _, args := range cmds {
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("command failed: %s: %w", strings.Join(args, " "), err)
			}
		}
		os.RemoveAll(tmpDir)
		fmt.Fprintf(os.Stderr, "  ✓ llama.cpp installed to /usr/local\n")
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s. Install llama.cpp manually", runtime.GOOS)
	}
}

func buildEngine() error {
	// Find the engine source
	engineDir := ""
	candidates := []string{
		"pkg/grpo_engine",
		filepath.Join(os.Getenv("HOME"), ".defenseclaw/grpo_engine"),
	}
	for _, d := range candidates {
		if _, err := os.Stat(filepath.Join(d, "Makefile")); err == nil {
			engineDir = d
			break
		}
	}

	if engineDir == "" {
		return fmt.Errorf("engine source not found. Expected pkg/grpo_engine/Makefile")
	}

	fmt.Fprintf(os.Stderr, "→ Building GRPO engine (%s)...\n", engineDir)

	cmd := exec.Command("make", "clean")
	cmd.Dir = engineDir
	cmd.Run() // ignore error

	cmd = exec.Command("make")
	cmd.Dir = engineDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make failed in %s: %w", engineDir, err)
	}

	fmt.Fprintf(os.Stderr, "  ✓ Engine built: %s/libgrpo_stream.a\n", engineDir)
	return nil
}

// SetupInfo prints the current setup status.
func SetupInfo() string {
	s := CheckSetup()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Platform:  %s\n", s.Platform))
	if s.LlamaCppInstalled {
		sb.WriteString(fmt.Sprintf("llama.cpp: ✓ installed (%s)\n", s.LlamaCppVersion))
	} else {
		sb.WriteString("llama.cpp: ✗ not installed\n")
	}
	if s.EngineBuilt {
		sb.WriteString(fmt.Sprintf("Engine:    ✓ built (%s)\n", s.EnginePath))
	} else {
		sb.WriteString("Engine:    ✗ not built\n")
	}
	return sb.String()
}
