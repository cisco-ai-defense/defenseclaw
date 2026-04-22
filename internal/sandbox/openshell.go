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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const openshellStderrTailMax = 4096

type OpenShell struct {
	BinaryPath  string
	PolicyDir   string
	FallbackDir string

	tel    *telemetry.Provider
	events *gatewaylog.Writer
}

func New(binaryPath, policyDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir}
}

func NewWithFallback(binaryPath, policyDir, fallbackDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir, FallbackDir: fallbackDir}
}

// BindObservability attaches structured event + metric sinks (optional).
func (o *OpenShell) BindObservability(p *telemetry.Provider, w *gatewaylog.Writer) {
	if o == nil {
		return
	}
	o.tel = p
	o.events = w
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

func (o *OpenShell) effectivePolicyPath() string {
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
	path := o.effectivePolicyPath()
	return LoadPolicy(path)
}

func (o *OpenShell) SavePolicy(p *Policy) error {
	path := o.effectivePolicyPath()
	return p.Save(path)
}

func stderrTail(b []byte) string {
	if len(b) <= openshellStderrTailMax {
		return string(b)
	}
	return string(b[len(b)-openshellStderrTailMax:])
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (o *OpenShell) emitOpenShellError(ctx context.Context, command string, exitCode int, stderrText string) {
	if o.tel != nil {
		o.tel.RecordOpenShellExit(ctx, command, exitCode)
	}
	if o.events == nil {
		return
	}
	o.events.Emit(gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemOpenShell),
			Code:      string(gatewaylog.ErrCodeSubprocessExit),
			Message:   fmt.Sprintf("openshell subprocess exited with code %d", exitCode),
			Cause:     stderrText,
		},
	})
}

func (o *OpenShell) ReloadPolicy() error {
	if !o.IsAvailable() {
		return fmt.Errorf("sandbox: openshell binary not found at %q", o.BinaryPath)
	}
	ctx := context.Background()
	cmd := exec.Command(o.BinaryPath, "policy", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		code := exitCode(err)
		tail := stderrTail(out)
		o.emitOpenShellError(ctx, "openshell policy reload", code, tail)
		return fmt.Errorf("sandbox: reload policy: %s: %w", tail, err)
	}
	if o.events != nil {
		o.events.Emit(gatewaylog.Event{
			EventType: gatewaylog.EventLifecycle,
			Severity:  gatewaylog.SeverityInfo,
			Lifecycle: &gatewaylog.LifecyclePayload{
				Subsystem:  string(gatewaylog.SubsystemOpenShell),
				Transition: "policy-reloaded",
				Details:    map[string]string{"command": "policy reload"},
			},
		})
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
	var stderrBuf bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sandbox: start openshell: %w", err)
	}
	if err := writePidFile(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("sandbox: write pid file: %w", err)
	}
	go func() {
		ctx := context.Background()
		waitErr := cmd.Wait()
		_ = removePidFile()
		code := 0
		if waitErr != nil {
			code = exitCode(waitErr)
			if code < 0 {
				code = 1
			}
		}
		if code != 0 {
			o.emitOpenShellError(ctx, "openshell start", code, stderrTail(stderrBuf.Bytes()))
		}
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !isOpenShellProcess(pid) {
			_ = removePidFile()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = proc.Kill()
	_ = removePidFile()
	return fmt.Errorf("sandbox: openshell stop: process %d did not exit within 15s", pid)
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
