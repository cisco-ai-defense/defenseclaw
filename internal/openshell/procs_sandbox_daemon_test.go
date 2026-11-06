// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func startSandboxImageProbe(t *testing.T) (int, string) {
	t.Helper()
	image, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	claimed := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.WriteFile(claimed, []byte("named gateway file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(image, "30")
	cmd.Args[0] = claimed
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid, image
}

func TestGAP0617ProcessImagePathUsesRunningFile(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process image lookup requires Linux or macOS")
	}
	pid, image := startSandboxImageProbe(t)
	path, err := sandboxDaemonProcessPath(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(path)
	if err != nil || !os.SameFile(got, want) {
		t.Fatalf("process image path = %q, want running file %q: %v", path, image, err)
	}
}

// A different account or process cannot satisfy the daemon status identity.
func TestMacSandboxDaemonPortNeedsExactAnsweringExecutable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process image lookup requires Linux or macOS")
	}
	pid, uid := os.Getpid(), os.Geteuid()
	r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", DaemonPID: pid, Geteuid: os.Geteuid}}
	holder := daemon.PortHolder{PID: pid, UID: uid}
	if !r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("answering daemon executable was not recognized")
	}
	holder.PID++
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different process was accepted")
	}
	holder.PID = pid
	holder.UID++
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different account was accepted")
	}
	foreignPID, _ := startSandboxImageProbe(t)
	r.DaemonPID = foreignPID
	holder = daemon.PortHolder{PID: foreignPID, UID: uid}
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different executable with the same account was accepted")
	}
}

func TestInstalledSandboxDaemonCopyRequiresContentAddressedFile(t *testing.T) {
	bin := t.TempDir()
	canonical := filepath.Join(bin, "defenseclaw-gateway")
	content := []byte("installed gateway file")
	if err := os.WriteFile(canonical, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(canonical)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(bin, "launch-agents", digest, "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if !installedSandboxDaemonCopy(canonical, copyPath) {
		t.Fatal("installed content-addressed copy was not accepted")
	}
	other := filepath.Join(bin, "other", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if installedSandboxDaemonCopy(canonical, other) {
		t.Fatal("same bytes outside the installed copy path were accepted")
	}
	if err := os.WriteFile(copyPath, []byte("installed gateway filE"), 0o700); err != nil {
		t.Fatal(err)
	}
	if installedSandboxDaemonCopy(canonical, copyPath) {
		t.Fatal("modified copy was accepted")
	}
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, copyPath); err != nil {
		t.Fatal(err)
	}
	if installedSandboxDaemonCopy(canonical, copyPath) {
		t.Fatal("symlinked copy was accepted")
	}
}

func TestInstalledSandboxDaemonCopyResolvesLauncher(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(bin, "defenseclaw-gateway")
	content := []byte("installed gateway file")
	if err := os.WriteFile(canonical, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(canonical)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(bin, "launch-agents", digest, "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, content, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "usr", "local", "bin", "defenseclaw")
	if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, launcher); err != nil {
		t.Fatal(err)
	}
	if !installedSandboxDaemonCopy(canonical, copyPath) {
		t.Fatal("direct gateway file was not recognized")
	}
	if !installedSandboxDaemonCopy(launcher, copyPath) {
		t.Fatal("installed launcher target was not recognized")
	}
	other := filepath.Join(root, "other", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(launcher); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, launcher); err != nil {
		t.Fatal(err)
	}
	if installedSandboxDaemonCopy(launcher, copyPath) {
		t.Fatal("launcher pointing outside the installed gateway directory was recognized")
	}
}
