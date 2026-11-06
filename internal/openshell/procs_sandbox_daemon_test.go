// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestSandboxDaemonMacProcessInspectionUsesFixedCommand(t *testing.T) {
	cmd := sandboxDaemonPSCommand(os.Getpid())
	if cmd.Name != "/bin/ps" || cmd.Timeout != 3*time.Second || !slices.Equal(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) ||
		!slices.Equal(cmd.Args, []string{"-p", fmt.Sprint(os.Getpid()), "-o", "comm="}) ||
		!slices.Equal(cmd.Unset, []string{"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"}) {
		t.Fatalf("process inspection command = %+v", cmd)
	}
}

// macOS lsof identifies the socket PID; ps comm gives its executable path.
// A same-account process with a different file, or a different PID, does
// not satisfy the daemon's status identity.
func TestMacSandboxDaemonPortNeedsExactAnsweringExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pid, uid := os.Getpid(), os.Geteuid()
	r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", DaemonPID: pid, Geteuid: os.Geteuid}}
	holder := daemon.PortHolder{PID: pid, UID: uid}
	setProcess := func(path string) {
		r.DaemonProcessPath = func(context.Context, int) (string, error) { return path, nil }
	}
	setProcess(exe)
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
	holder.UID = uid
	other := filepath.Join(t.TempDir(), filepath.Base(exe))
	if err := os.WriteFile(other, []byte("different executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	setProcess(other)
	if r.ownSandboxDaemonProcess(context.Background(), holder) {
		t.Fatal("a different executable with the same name was accepted")
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
