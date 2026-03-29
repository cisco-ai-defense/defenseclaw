// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type OpenShell struct {
	BinaryPath  string
	PolicyDir   string
	FallbackDir string
}

func New(binaryPath, policyDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir}
}

func NewWithFallback(binaryPath, policyDir, fallbackDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir, FallbackDir: fallbackDir}
}

func (o *OpenShell) IsAvailable() bool {
	_, err := exec.LookPath(o.BinaryPath)
	return err == nil
}

func (o *OpenShell) PolicyPath() string {
	return filepath.Join(o.PolicyDir, "defenseclaw-policy.yaml")
}

func (o *OpenShell) fallbackPolicyPath() string {
	if o.FallbackDir != "" {
		return filepath.Join(o.FallbackDir, "defenseclaw-policy.yaml")
	}
	return ""
}

// EffectivePolicyPath returns the resolved path for the sandbox policy file.
// It tries the primary PolicyDir first; if that directory cannot be created,
// it falls back to FallbackDir.
func (o *OpenShell) EffectivePolicyPath() string {
	primary := o.PolicyPath()
	dir := filepath.Dir(primary)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if fb := o.fallbackPolicyPath(); fb != "" {
			return fb
		}
	}
	return primary
}

func (o *OpenShell) LoadPolicy() (*Policy, error) {
	path := o.EffectivePolicyPath()
	return LoadPolicy(path)
}

func (o *OpenShell) SavePolicy(p *Policy) error {
	path := o.EffectivePolicyPath()
	return p.Save(path)
}

func (o *OpenShell) ReloadPolicy() error {
	if !o.IsAvailable() {
		return fmt.Errorf("sandbox: openshell binary not found at %q", o.BinaryPath)
	}
	cmd := exec.Command(o.BinaryPath, "policy", "reload")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sandbox: reload policy: %s: %w", string(out), err)
	}
	return nil
}

func (o *OpenShell) Start(policyPath string) error {
	if !o.IsAvailable() {
		return fmt.Errorf("sandbox: openshell binary not found at %q", o.BinaryPath)
	}
	args := []string{"start", "--policy", policyPath}
	cmd := exec.Command(o.BinaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sandbox: start openshell: %w", err)
	}
	if err := writePidFile(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("sandbox: write pid file: %w", err)
	}
	go func() {
		_ = cmd.Wait()
		_ = removePidFile()
	}()
	return nil
}

func (o *OpenShell) Stop() error {
	pid, err := readPidFile()
	if err != nil {
		return fmt.Errorf("sandbox: no running openshell process found: %w", err)
	}

	if !isOpenShellProcess(pid) {
		_ = removePidFile()
		return fmt.Errorf("sandbox: stale pid file (process %d is not openshell-sandbox)", pid)
	}

	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(os.Interrupt); err != nil {
		_ = proc.Kill()
	}
	_ = removePidFile()
	return nil
}

func (o *OpenShell) IsRunning() bool {
	pid, err := readPidFile()
	if err != nil {
		return false
	}
	if !isOpenShellProcess(pid) {
		return false
	}
	proc, _ := os.FindProcess(pid)
	return proc.Signal(nil) == nil
}

func pidFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".defenseclaw", "openshell.pid")
}

func writePidFile(pid int) error {
	path := pidFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o600)
}

// isOpenShellProcess checks whether the process at pid is actually an
// openshell-sandbox process, guarding against PID reuse after the
// original process has exited.
func isOpenShellProcess(pid int) bool {
	// Linux: read /proc/<pid>/cmdline directly (no subprocess).
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil {
		return strings.Contains(string(cmdline), "openshell-sandbox")
	}
	// Fallback (macOS, etc.): ask ps for the command name.
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(out)), "openshell")
}

func readPidFile() (int, error) {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func removePidFile() error {
	return os.Remove(pidFilePath())
}
