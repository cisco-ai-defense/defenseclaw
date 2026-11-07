// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"net"
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

// A different account or process cannot satisfy the daemon status identity.
func TestMacSandboxDaemonPortNeedsExactAnsweringExecutable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process image lookup requires Linux or macOS")
	}
	pid, uid := os.Getpid(), os.Geteuid()
	r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", DaemonPID: pid, ResponderPID: pid, Geteuid: os.Geteuid}}
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
	r.ResponderPID = foreignPID
	holder = daemon.PortHolder{PID: foreignPID, UID: uid}
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different executable with the same account was accepted")
	}
}

// GAP-0617: a status responder cannot name another same-account process as
// the daemon merely because it runs the installed image and holds the port.
func TestGAP0617PortNeedsVerifiedStatusResponder(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process image lookup requires Linux or macOS")
	}
	pid, uid := os.Getpid(), os.Geteuid()
	holder := daemon.PortHolder{PID: pid, UID: uid}
	r := &doctorRun{Doctor: &Doctor{GOOS: runtime.GOOS, DaemonPID: pid, Geteuid: os.Geteuid}}
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a claimed PID proved a port without the status responder")
	}
	r.ResponderPID = pid + 1
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different status responder proved the port holder")
	}
	r.ResponderPID = pid
	if !r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("the verified status responder was not recognized")
	}
}

func TestGAP0617AdvertisedManagedPortStillNeedsItsResponder(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process image lookup requires Linux or macOS")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pid, uid := os.Getpid(), os.Geteuid()
	port := ln.Addr().(*net.TCPAddr).Port
	d := &Doctor{
		GOOS: runtime.GOOS, Managed: true, DaemonPID: pid, Geteuid: os.Geteuid,
		Ports:  []PortRequirement{{Name: "ingress", Port: port, ServedByDaemon: true}},
		Listen: net.Listen, PortHolder: func(string, int) (daemon.PortHolder, error) {
			return daemon.PortHolder{PID: pid, UID: uid}, nil
		},
	}
	run := func() CheckStatus {
		r := &doctorRun{Doctor: d, report: &DoctorReport{}}
		r.checkPorts(context.Background())
		return r.report.Get(CheckIDPortPrefix + "ingress").Status
	}
	if got := run(); got != StatusFail {
		t.Fatalf("unverified advertised port = %s, want fail", got)
	}
	d.ResponderPID = pid
	if got := run(); got != StatusPass {
		t.Fatalf("verified advertised port = %s, want pass", got)
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
