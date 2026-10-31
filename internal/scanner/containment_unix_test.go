// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func scannerQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// scannerDetachedFixture is a scanner that starts a child in a session of
// its own with every stream redirected and then reports a clean scan. macOS
// has no setsid(1); perl's POSIX::setsid does the same.
func scannerDetachedFixture(t *testing.T, pidFile string) string {
	t.Helper()
	detach := "setsid"
	if _, err := exec.LookPath("setsid"); err != nil {
		if _, err := exec.LookPath("perl"); err != nil {
			t.Skip("neither setsid nor perl is installed")
		}
		detach = `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; exec @ARGV or die'`
	}
	pidWrite := `echo $$ > "$1"`
	if runtime.GOOS == "linux" {
		// /proc is the host mount even inside the scanner's PID namespace.
		// Shell $$ is namespace-local and may name an unrelated host process.
		pidWrite = `read -r p _ < /proc/self/stat; echo "$p" > "$1"`
	}
	path := filepath.Join(t.TempDir(), "scanner-fixture")
	script := "#!/bin/sh\npidfile=" + scannerQuote(pidFile) + "\n" + detach + ` sh -c '` + pidWrite + `; exec sleep 60' sh "$pidfile" </dev/null >/dev/null 2>&1 &
while [ ! -s "$pidfile" ]; do sleep 0.01; done
if [ "${DC_SCANNER_TEST_WAIT:-}" = 1 ]; then sleep 60; fi
printf '{"findings":[]}\n'
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func scannerFixturePID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if convErr == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("detached scanner child never wrote %s", path)
	return 0
}

func scannerFixtureGone(t *testing.T, pid int) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for scannerFixtureRunning(t, pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return !scannerFixtureRunning(t, pid)
}

// The liveness check must not depend on an external tool: with ps missing,
// the old check reported every process gone, so the containment tests
// passed without checking anything.
func TestScannerFixtureRunningNeedsNoTools(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	t.Setenv("PATH", t.TempDir())
	pid := cmd.Process.Pid
	if !scannerFixtureRunning(t, pid) {
		t.Fatalf("running process %d reported gone", pid)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if !scannerFixtureGone(t, pid) {
		t.Fatalf("killed process %d still reported running", pid)
	}
	_ = cmd.Wait()
	if scannerFixtureRunning(t, pid) {
		t.Fatalf("reaped process %d still reported running", pid)
	}
}

func scannerRoutes() []struct {
	name string
	new  func(string) Scanner
} {
	return []struct {
		name string
		new  func(string) Scanner
	}{
		{"plugin", func(fixture string) Scanner { return NewPluginScanner(fixture) }},
		{"skill", func(fixture string) Scanner {
			return NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
		{"mcp", func(fixture string) Scanner {
			return NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
	}
}

// Plugin, skill, and MCP scans must own children that leave their process
// group and close inherited streams. The old RunTree path returned a clean
// scan while the child kept running (GAP-0456).
func TestScannersContainDetachedChildren(t *testing.T) {
	for _, tc := range scannerRoutes() {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "detached.pid")
			fixture := scannerDetachedFixture(t, pidFile)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := tc.new(fixture).Scan(ctx, t.TempDir())
			pid := scannerFixturePID(t, pidFile)
			if !scannerFixtureGone(t, pid) {
				t.Fatalf("Scan() = %+v, %v; detached scanner child %d is still running", result, err, pid)
			}
			if err != nil {
				t.Fatalf("contained scan failed: %v", err)
			}
		})
	}
}

// A scanner may start ordinary subprocesses: skill-scanner 2.3.2 does on
// every scan. The macOS no-fork launcher failed every such gateway scan.
func TestScannersRunForkingChildren(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "scanner-fixture")
	script := "#!/bin/sh\nout=$(/bin/sh -c 'printf \"{\\\"findings\\\":[]}\"')\n/bin/sleep 0 &\nwait\nprintf '%s\\n' \"$out\"\n"
	if err := os.WriteFile(fixture, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range scannerRoutes() {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := tc.new(fixture).Scan(ctx, t.TempDir())
			if err != nil || result == nil || len(result.Findings) != 0 {
				t.Fatalf("Scan() = %+v, %v; a scanner that starts subprocesses must scan", result, err)
			}
		})
	}
}

// An ungraceful gateway exit does not run its Go cleanup. The scanner's
// supervisor must still end a detached child that closed all inherited
// pipes (GAP-0492).
func TestScannerDetachedChildDiesWithGateway(t *testing.T) {
	if os.Getenv("DC_SCANNER_TEST_GATEWAY") == "1" {
		_, _ = NewPluginScanner(os.Getenv("DC_SCANNER_TEST_FIXTURE")).Scan(context.Background(), "local")
		return
	}
	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	fixture := scannerDetachedFixture(t, pidFile)
	gateway := exec.Command(os.Args[0], "-test.run=^TestScannerDetachedChildDiesWithGateway$")
	gateway.Env = append(os.Environ(),
		"DC_SCANNER_TEST_GATEWAY=1", "DC_SCANNER_TEST_FIXTURE="+fixture,
		"DC_SCANNER_TEST_WAIT=1")
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	pid := scannerFixturePID(t, pidFile)
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	if !scannerFixtureGone(t, pid) {
		t.Fatalf("detached scanner child %d survived gateway death", pid)
	}
}

// DC_TEST_SKILL_SCANNER names an installed skill-scanner (the version the
// release ships). The gateway route must scan a skill with it and leave
// none of the scanner's processes behind.
func TestShippedSkillScannerScansThroughGateway(t *testing.T) {
	binary := os.Getenv("DC_TEST_SKILL_SCANNER")
	if binary == "" {
		t.Skip("DC_TEST_SKILL_SCANNER is not set")
	}
	skill := filepath.Join(t.TempDir(), "hello-skill")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := "---\nname: hello-skill\ndescription: Prints a greeting.\n---\n\n# Hello\n\nSay hello to the user.\n"
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: binary}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := scan.Scan(ctx, skill)
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatalf("Scan() = %+v, %v; the shipped skill-scanner must scan through the gateway", result, err)
	}
	out, _ := exec.Command("pgrep", "-f", skill).Output()
	if pids := strings.TrimSpace(string(out)); pids != "" {
		t.Fatalf("skill-scanner processes still running after the scan: %s", pids)
	}
}
