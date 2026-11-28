// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// buildSleepScannerFixture builds a scanner that never answers within scan_s.
func buildSleepScannerFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	program := "package main\nimport \"time\"\nfunc main() { time.Sleep(60 * time.Second) }\n"
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "scanner-sleep")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build sleep scanner fixture: %v\n%s", err, output)
	}
	return binary
}

// GAP-1030: a scan cut off by timeouts.scan_s says it timed out and names the
// key, and still fails closed.
func TestSkillScanner_ScanTimeoutSaysTimedOutGAP1030(t *testing.T) {
	bin := buildSleepScannerFixture(t)
	cfg := config.SkillScannerConfig{Binary: bin}
	cfg.Timeouts.ScanS = 1
	ss := NewSkillScannerFromLLM(cfg, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	result, err := ss.Scan(context.Background(), "/tmp/target")
	if err == nil {
		t.Fatalf("a timed-out scan must fail closed, got result %+v", result)
	}
	for _, want := range []string{"timed out after 1 s", "scanners.skill_scanner.timeouts.scan_s"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("timeout failure %q does not contain %q", err, want)
		}
	}
}

// GAP-1030: a scanner killed or crashed (signal-style or Windows kill exit
// status) says it crashed and carries the exit code, and still fails closed.
func TestSkillScanner_CrashSaysCrashedWithExitCodeGAP1030(t *testing.T) {
	bin := buildScannerFixture(t, "", 137)
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	result, err := ss.Scan(context.Background(), "/tmp/target")
	if err == nil {
		t.Fatalf("a crashed scan must fail closed, got result %+v", result)
	}
	if !strings.Contains(err.Error(), "crashed with exit code 137") {
		t.Fatalf("crash failure %q does not say it crashed with its exit code", err)
	}
}

func TestSkillScanFailureTextWordingGAP1030(t *testing.T) {
	cases := []struct {
		name     string
		timedOut bool
		code     int
		stderr   string
		want     string
	}{
		{"timeout", true, 1, "", "timed out after 90 s (scanners.skill_scanner.timeouts.scan_s)"},
		{"timeout linux launcher", true, -1, "", "timed out after 90 s"},
		{"kill windows", false, 4294967295, "", "crashed with exit code 4294967295"},
		{"killed", false, 137, "", "crashed with exit code 137"},
		{"signal", false, -1, "", "crashed with exit code -1"},
		{"plain failure", false, 2, "bad config", "exited 2: bad config"},
		{"empty plain failure", false, 7, "", "exited 7 with no error output"},
	}
	for _, c := range cases {
		got := skillScanFailureText("skill-scanner", c.timedOut, 90, c.code, c.stderr)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.name, got, c.want)
		}
	}
}
