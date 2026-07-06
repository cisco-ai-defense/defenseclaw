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

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

const executableExitMarker = "__DEFENSECLAW_LASTEXITCODE__="

func TestNativeWindowsExecutableForeignCollisionAndRecovery(t *testing.T) {
	binary := buildGatewayExecutable(t)
	home := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listenerOpen := true
	t.Cleanup(func() {
		if listenerOpen {
			_ = listener.Close()
		}
	})

	const token = "win-aud-029-executable-test-token"
	configText := fmt.Sprintf(`gateway:
  api_bind: 127.0.0.1
  api_port: %d
  token: %s
  fleet_mode: disabled
  watcher:
    enabled: false
  watchdog:
    enabled: false
guardrail:
  enabled: false
otel:
  enabled: false
`, port, token)
	if err := os.WriteFile(filepath.Join(home, config.DefaultConfigName), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	foreignPID := os.Getpid()
	assertExecutableTestListenerOwner(t, port, foreignPID)
	startOutput, startExit := runGatewayExecutablePowerShell(t, binary, home, "start")
	if startExit == 0 {
		t.Fatalf("start LASTEXITCODE = 0, want nonzero on foreign collision; output:\n%s", startOutput)
	}
	if !strings.Contains(startOutput, "foreign process PID") || strings.Contains(startOutput, "STARTING") {
		t.Fatalf("start output does not report terminal collision failure:\n%s", startOutput)
	}
	assertExecutableTestListenerOwner(t, port, foreignPID)
	assertExecutableTestArtifactMissing(t, filepath.Join(home, daemon.PIDFileName))
	assertExecutableTestArtifactMissing(t, filepath.Join(home, watchdogPIDFile))
	assertExecutableTestArtifactMissing(t, filepath.Join(home, watchdogStateFile))

	statusOutput, statusExit := runGatewayExecutablePowerShell(t, binary, home, "status")
	if statusExit == 0 {
		t.Fatalf("status LASTEXITCODE = 0, want nonzero while foreign listener remains; output:\n%s", statusOutput)
	}
	assertExecutableTestListenerOwner(t, port, foreignPID)
	restartOutput, restartExit := runGatewayExecutablePowerShell(t, binary, home, "restart")
	if restartExit == 0 {
		t.Fatalf("restart LASTEXITCODE = 0, want nonzero on foreign collision; output:\n%s", restartOutput)
	}
	assertExecutableTestListenerOwner(t, port, foreignPID)
	assertExecutableTestArtifactMissing(t, filepath.Join(home, daemon.PIDFileName))
	assertExecutableTestArtifactMissing(t, filepath.Join(home, watchdogPIDFile))

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	listenerOpen = false

	startOutput, startExit = runGatewayExecutablePowerShell(t, binary, home, "start")
	if startExit != 0 {
		t.Fatalf("start LASTEXITCODE = %d after collision removal, want 0; output:\n%s", startExit, startOutput)
	}
	if !strings.Contains(startOutput, "OK (PID") || strings.Contains(startOutput, "STARTING") {
		t.Fatalf("successful start did not render READY-only completion:\n%s", startOutput)
	}

	d := daemon.New(home)
	t.Cleanup(func() {
		if running, _ := d.IsRunning(); running {
			_ = d.Stop(defaultStopTimeout)
		}
	})
	running, managedPID := d.IsRunning()
	if !running || !d.HasManagedProcessIdentity(managedPID) {
		t.Fatalf("managed process identity = (running=%v, PID=%d, strong=%v)", running, managedPID, d.HasManagedProcessIdentity(managedPID))
	}
	assertExecutableTestListenerOwner(t, port, managedPID)

	cfg := config.DefaultConfig()
	cfg.DataDir = home
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = port
	cfg.Gateway.Token = token
	status, err := fetchSidecarStatus(&http.Client{Timeout: time.Second}, sidecarStatusURL(cfg), token)
	if err != nil {
		t.Fatalf("authenticated /status: %v", err)
	}
	if err := verifyGatewayRuntimeIdentity(status, managedPID, home); err != nil {
		t.Fatal(err)
	}
	repeatOutput, repeatExit := runGatewayExecutablePowerShell(t, binary, home, "start")
	if repeatExit != 0 || !strings.Contains(repeatOutput, "already running") {
		t.Fatalf("authenticated repeated start = exit %d; output:\n%s", repeatExit, repeatOutput)
	}
	assertExecutableTestListenerOwner(t, port, managedPID)

	statusOutput, statusExit = runGatewayExecutablePowerShell(t, binary, home, "status")
	if statusExit != 0 {
		t.Fatalf("status LASTEXITCODE = %d for managed gateway, want 0; output:\n%s", statusExit, statusOutput)
	}
	if err := d.Stop(defaultStopTimeout); err != nil {
		t.Fatalf("stop recovered managed gateway: %v", err)
	}

	testExecutableStartingDeadline(t, binary)
}

func testExecutableStartingDeadline(t *testing.T, binary string) {
	t.Helper()
	home := t.TempDir()
	apiPort := reserveExecutableTestPort(t)
	fleetPort := reserveExecutableTestPort(t)
	configText := fmt.Sprintf(`gateway:
  host: 127.0.0.1
  port: %d
  api_bind: 127.0.0.1
  api_port: %d
  token: win-aud-029-timeout-test-token
  fleet_mode: enabled
  watcher:
    enabled: false
  watchdog:
    enabled: false
guardrail:
  enabled: false
otel:
  enabled: false
`, fleetPort, apiPort)
	if err := os.WriteFile(filepath.Join(home, config.DefaultConfigName), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	startOutput, startExit := runGatewayExecutablePowerShell(t, binary, home, "start")
	if startExit == 0 {
		t.Fatalf("STARTING deadline LASTEXITCODE = 0, want nonzero; output:\n%s", startOutput)
	}
	if !strings.Contains(startOutput, "FAILED") || !strings.Contains(startOutput, "remained STARTING") || strings.Contains(startOutput, "OK (PID") {
		t.Fatalf("STARTING deadline did not render terminal failure:\n%s", startOutput)
	}
	d := daemon.New(home)
	if running, pid := d.IsRunning(); running {
		t.Fatalf("timed-out managed process still running as PID %d", pid)
	}
	assertExecutableTestArtifactMissing(t, filepath.Join(home, daemon.PIDFileName))
	assertExecutableTestArtifactMissing(t, filepath.Join(home, watchdogPIDFile))
	assertExecutableTestArtifactMissing(t, filepath.Join(home, watchdogStateFile))
	if _, err := daemon.ListenerOwnerPID("127.0.0.1", apiPort); !errors.Is(err, daemon.ErrNoListener) {
		t.Fatalf("API listener remains after timeout cleanup: %v", err)
	}
	statusOutput, statusExit := runGatewayExecutablePowerShell(t, binary, home, "status")
	if statusExit == 0 {
		t.Fatalf("status LASTEXITCODE = 0 after timeout cleanup, want nonzero; output:\n%s", statusOutput)
	}
}

func reserveExecutableTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func buildGatewayExecutable(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	binary := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/defenseclaw")
	cmd.Dir = repoRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build gateway executable: %v\n%s", err, output)
	}
	return binary
}

func runGatewayExecutablePowerShell(t *testing.T, binary, home, command string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	script := `$output = & $env:DEFENSECLAW_TEST_EXE $env:DEFENSECLAW_TEST_COMMAND 2>&1 | Out-String
$code = $LASTEXITCODE
[Console]::Out.Write($output)
[Console]::Out.WriteLine("` + executableExitMarker + `$code")
exit 0`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = executableTestEnv(home, binary, command)
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("invoke %s through PowerShell: %v\n%s", command, err, outputBytes)
	}
	output := string(outputBytes)
	marker := strings.LastIndex(output, executableExitMarker)
	if marker < 0 {
		t.Fatalf("PowerShell %s output omitted LASTEXITCODE marker:\n%s", command, output)
	}
	exitText := strings.TrimSpace(output[marker+len(executableExitMarker):])
	exitCode, err := strconv.Atoi(exitText)
	if err != nil {
		t.Fatalf("parse PowerShell %s LASTEXITCODE %q: %v", command, exitText, err)
	}
	return strings.TrimSpace(output[:marker]), exitCode
}

func executableTestEnv(home, binary, command string) []string {
	removed := []string{"DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG", "DEFENSECLAW_TEST_EXE", "DEFENSECLAW_TEST_COMMAND"}
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			env = append(env, entry)
			continue
		}
		drop := false
		for _, candidate := range removed {
			if strings.EqualFold(key, candidate) {
				drop = true
				break
			}
		}
		if !drop {
			env = append(env, entry)
		}
	}
	return append(env,
		"DEFENSECLAW_HOME="+home,
		"DEFENSECLAW_TEST_EXE="+binary,
		"DEFENSECLAW_TEST_COMMAND="+command,
	)
}

func assertExecutableTestListenerOwner(t *testing.T, port, wantPID int) {
	t.Helper()
	ownerPID, err := daemon.ListenerOwnerPID("127.0.0.1", port)
	if err != nil {
		t.Fatalf("listener owner for port %d: %v", port, err)
	}
	if ownerPID != wantPID {
		t.Fatalf("listener owner for port %d = %d, want %d", port, ownerPID, wantPID)
	}
}

func assertExecutableTestArtifactMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("startup artifact %s exists or cannot be checked: %v", path, err)
	}
}
