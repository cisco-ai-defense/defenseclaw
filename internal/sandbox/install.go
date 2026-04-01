package sandbox

import (
	"fmt"
	"os/exec"
	"strings"
)

// VerifyOpenShellBinary checks that the openshell-sandbox binary exists at
// the given path (or on PATH if empty) and returns the installed version.
func VerifyOpenShellBinary(binaryPath string) (string, error) {
	if binaryPath == "" {
		binaryPath = "openshell-sandbox"
	}

	path, err := exec.LookPath(binaryPath)
	if err != nil {
		return "", fmt.Errorf("sandbox: openshell-sandbox not found: %w", err)
	}

	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sandbox: openshell-sandbox --version failed: %w", err)
	}

	version := strings.TrimSpace(string(out))
	// Output may be "openshell-sandbox 0.6.2" or just "0.6.2"
	if idx := strings.LastIndex(version, " "); idx >= 0 {
		version = version[idx+1:]
	}
	version = strings.TrimPrefix(version, "v")
	return version, nil
}

// CheckVersionCompatibility warns if the installed version differs from the
// required version. Returns nil if they match, an error with a warning message
// if they differ (non-fatal — the user may have a valid reason).
func CheckVersionCompatibility(installed, required string) error {
	installed = strings.TrimPrefix(installed, "v")
	required = strings.TrimPrefix(required, "v")

	if installed == required {
		return nil
	}
	return fmt.Errorf("sandbox: version mismatch: installed %s, expected %s (may still work)", installed, required)
}
