// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func restoreProtectedDarwinChildSeams(t *testing.T) {
	t.Helper()
	realUID := protectedDarwinRealUID
	effectiveUID := protectedDarwinEffectiveUID
	effectiveGID := protectedDarwinEffectiveGID
	setEUID := protectedDarwinSetEUID
	kill := protectedDarwinKill
	executable := protectedDarwinExecutable
	start := protectedDarwinCommandStart
	wait := protectedDarwinCommandWait
	launcher := protectedDarwinLauncher
	stage := protectedDarwinStageImage
	createStage := protectedDarwinCreateStage
	chown := protectedDarwinChown
	validateStage := protectedDarwinValidateStagedImage
	t.Cleanup(func() {
		protectedDarwinRealUID = realUID
		protectedDarwinEffectiveUID = effectiveUID
		protectedDarwinEffectiveGID = effectiveGID
		protectedDarwinSetEUID = setEUID
		protectedDarwinKill = kill
		protectedDarwinExecutable = executable
		protectedDarwinCommandStart = start
		protectedDarwinCommandWait = wait
		protectedDarwinLauncher = launcher
		protectedDarwinStageImage = stage
		protectedDarwinCreateStage = createStage
		protectedDarwinChown = chown
		protectedDarwinValidateStagedImage = validateStage
	})
}

func TestStartProtectedDarwinAgentCommandUsesRootCustodiedBrokerWithoutParentElevation(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	protectedDarwinRealUID = func() int { return 0 }
	protectedDarwinEffectiveUID = func() int { return 501 }
	protectedDarwinEffectiveGID = func() int { return 20 }
	protectedDarwinSetEUID = func(int) error {
		t.Fatal("parent attempted to change process-wide euid")
		return nil
	}
	protectedDarwinLauncher = func() (string, error) { return "/usr/local/bin/defenseclaw", nil }

	digest := strings.Repeat("a", 64)
	command := exec.Command("/Users/alice/bin/codex", "--version")
	command.Env = []string{
		"CODEX_HOME=/Users/alice/.codex",
		"DEFENSECLAW_TEST_PARENT_SECRET=must-not-reach-client",
	}
	protectedDarwinCommandStart = func(got *exec.Cmd) error {
		if got.Path != "/usr/local/bin/defenseclaw" {
			t.Fatalf("broker path = %q", got.Path)
		}
		wantArgs := []string{
			"/usr/local/bin/defenseclaw", protectedDarwinAgentChildMode,
			"501", "20", "codex", digest, "/Users/alice/bin/codex", "--version",
		}
		if !reflect.DeepEqual(got.Args, wantArgs) {
			t.Fatalf("broker args = %#v, want %#v", got.Args, wantArgs)
		}
		if got.Dir != "/" || got.SysProcAttr == nil || !got.SysProcAttr.Setpgid || got.SysProcAttr.Credential != nil {
			t.Fatalf("broker process boundary = dir %q attr %#v", got.Dir, got.SysProcAttr)
		}
		joined := strings.Join(got.Env, "\n")
		if strings.Contains(joined, "DEFENSECLAW_TEST_PARENT_SECRET") ||
			!strings.Contains(joined, "CODEX_HOME=/Users/alice/.codex") {
			t.Fatalf("broker environment = %q", joined)
		}
		if got.Cancel == nil {
			t.Fatal("broker context cancellation does not kill its process group")
		}
		return nil
	}
	if err := startProtectedDarwinAgentCommand(command, "codex", digest); err != nil {
		t.Fatalf("startProtectedDarwinAgentCommand: %v", err)
	}
}

func TestStartProtectedDarwinAgentCommandPreservesOrdinaryUserEnvironmentAndCWD(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	protectedDarwinRealUID = func() int { return 501 }
	protectedDarwinEffectiveUID = func() int { return 501 }
	protectedDarwinEffectiveGID = func() int { return 20 }
	command := exec.Command("/usr/bin/true")
	command.Dir = "/Users/alice/work"
	command.Env = []string{"OPENAI_API_KEY=user-key", "HTTPS_PROXY=https://proxy.invalid"}
	protectedDarwinCommandStart = func(got *exec.Cmd) error {
		if got.Path != "/usr/bin/true" || got.Dir != "/Users/alice/work" ||
			!reflect.DeepEqual(got.Env, command.Env) {
			t.Fatalf("ordinary command was rewritten: path=%q dir=%q env=%#v", got.Path, got.Dir, got.Env)
		}
		if got.SysProcAttr != nil && got.SysProcAttr.Credential != nil {
			t.Fatalf("ordinary command received Credential: %#v", got.SysProcAttr.Credential)
		}
		return nil
	}
	if err := startProtectedDarwinAgentCommand(command, "", ""); err != nil {
		t.Fatalf("ordinary start: %v", err)
	}
}

func TestProtectedDarwinAgentChildRunsOnlySealedImageWithIrreversibleCredential(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	protectedDarwinRealUID = func() int { return 0 }
	protectedDarwinEffectiveUID = func() int { return 501 }
	protectedDarwinEffectiveGID = func() int { return 20 }
	var elevated bool
	protectedDarwinSetEUID = func(uid int) error {
		if uid != 0 {
			t.Fatalf("broker seteuid = %d", uid)
		}
		elevated = true
		return nil
	}
	stageDir := t.TempDir()
	stagePath := filepath.Join(stageDir, "codex")
	if err := os.WriteFile(stagePath, []byte("sealed fixture"), 0o500); err != nil {
		t.Fatal(err)
	}
	protectedDarwinStageImage = func(connectorName, selectedPath, digest string, gid int) (protectedDarwinStagedImage, error) {
		if connectorName != "codex" || selectedPath != "/Users/alice/bin/codex" ||
			digest != strings.Repeat("b", 64) || gid != 20 {
			t.Fatalf("stage identity = %q %q %q %d", connectorName, selectedPath, digest, gid)
		}
		return protectedDarwinStagedImage{directory: stageDir, path: stagePath}, nil
	}
	t.Setenv("DEFENSECLAW_TEST_PARENT_SECRET", "must-not-reach-client")
	protectedDarwinCommandStart = func(command *exec.Cmd) error {
		if command.Path != stagePath || !reflect.DeepEqual(command.Args, []string{"/Users/alice/bin/codex", "app-server", "--stdio"}) {
			t.Fatalf("sealed command = path %q args %#v", command.Path, command.Args)
		}
		credential := command.SysProcAttr.Credential
		if credential == nil || credential.Uid != 501 || credential.Gid != 20 ||
			!reflect.DeepEqual(credential.Groups, []uint32{20}) {
			t.Fatalf("sealed child credential = %#v", credential)
		}
		if command.Dir != "/" || strings.Contains(strings.Join(command.Env, "\n"), "DEFENSECLAW_TEST_PARENT_SECRET") {
			t.Fatalf("sealed child dir/env = %q / %#v", command.Dir, command.Env)
		}
		return nil
	}
	waited := false
	protectedDarwinCommandWait = func(*exec.Cmd) error {
		waited = true
		if _, err := os.Lstat(stageDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sealed staging directory remains while child runs: %v", err)
		}
		return nil
	}
	err := runProtectedDarwinAgentChild([]string{
		"501", "20", "codex", strings.Repeat("b", 64),
		"/Users/alice/bin/codex", "app-server", "--stdio",
	})
	if err != nil {
		t.Fatalf("runProtectedDarwinAgentChild: %v", err)
	}
	if !elevated {
		t.Fatal("isolated broker did not regain root before sealing")
	}
	if !waited {
		t.Fatal("isolated broker did not wait for the sealed child")
	}
}

func TestStageProtectedDarwinAgentImageBindsDigestAndIdentityToSameCopy(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	root := t.TempDir()
	selected := filepath.Join(root, "codex")
	malicious := []byte("unsigned receipt-bound image")
	if err := os.WriteFile(selected, malicious, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(malicious))
	protectedDarwinCreateStage = func() (string, error) {
		return os.MkdirTemp(root, "sealed-")
	}
	protectedDarwinChown = func(string, int, int) error { return nil }
	validated := false
	protectedDarwinValidateStagedImage = func(connectorName, path string) error {
		validated = true
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if connectorName != "codex" || !reflect.DeepEqual(body, malicious) {
			t.Fatalf("staged validator saw %q %q", connectorName, body)
		}
		return errors.New("staged bytes lack pinned signature")
	}
	if _, err := stageProtectedDarwinAgentImage("codex", selected, digest, 20); err == nil ||
		!strings.Contains(err.Error(), "pinned signature") || !validated {
		t.Fatalf("unsigned same-vnode stage error = %v, validated=%t", err, validated)
	}

	validated = false
	if _, err := stageProtectedDarwinAgentImage("codex", selected, strings.Repeat("0", 64), 20); err == nil ||
		!strings.Contains(err.Error(), "digest") || validated {
		t.Fatalf("digest mismatch error = %v, validator called=%t", err, validated)
	}
}

func TestTrustedProtectedDarwinLauncherRejectsTargetOwnedExecutable(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	path := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.WriteFile(path, []byte("fixture"), 0o500); err != nil {
		t.Fatal(err)
	}
	protectedDarwinExecutable = func() (string, error) { return path, nil }
	if _, err := trustedProtectedDarwinLauncherExecutable(); err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("target-owned launcher error = %v", err)
	}
}

func TestTerminateCodexAppServerProcessUsesBrokerProcessGroup(t *testing.T) {
	restoreProtectedDarwinChildSeams(t)
	var pid int
	var signal syscall.Signal
	protectedDarwinKill = func(gotPID int, gotSignal syscall.Signal) error {
		pid = gotPID
		signal = gotSignal
		return nil
	}
	command := &exec.Cmd{
		Process:     &os.Process{Pid: 7654},
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	if err := terminateCodexAppServerProcess(command); err != nil {
		t.Fatalf("terminate process group: %v", err)
	}
	if pid != -7654 || signal != syscall.SIGKILL {
		t.Fatalf("kill = (%d, %v), want (-7654, SIGKILL)", pid, signal)
	}
}
