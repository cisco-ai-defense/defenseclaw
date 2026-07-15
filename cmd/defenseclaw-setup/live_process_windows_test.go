// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveProcessWithinInstallRoot(t *testing.T) {
	installRoot := t.TempDir()
	binDir := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(binDir, "defenseclaw-test-helper.exe")
	copyExecutable(t, source, target)

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(target, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_SETUP_PROCESS_HELPER=1",
		"GO_SETUP_PROCESS_READY="+ready,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start installed process helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect helper readiness: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("installed process helper did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}

	pid, imagePath, err := liveProcessWithinInstallRoot(installRoot)
	if err != nil {
		t.Fatalf("liveProcessWithinInstallRoot: %v", err)
	}
	if pid != uint32(cmd.Process.Pid) {
		t.Fatalf("PID = %d, want %d (image %q)", pid, cmd.Process.Pid, imagePath)
	}
	if !strings.EqualFold(filepath.Clean(imagePath), filepath.Clean(target)) {
		t.Fatalf("image path = %q, want %q", imagePath, target)
	}
	pid, imagePath, err = liveProcessWithinInstallRoot(installRoot, target)
	if err != nil {
		t.Fatalf("liveProcessWithinInstallRoot with ignored image: %v", err)
	}
	if pid != 0 || imagePath != "" {
		t.Fatalf("ignored installed process = (%d, %q), want no match", pid, imagePath)
	}
}

func TestLiveProcessWithinInstallRootHelper(t *testing.T) {
	if os.Getenv("GO_WANT_SETUP_PROCESS_HELPER") != "1" {
		return
	}
	ready := os.Getenv("GO_SETUP_PROCESS_READY")
	if ready == "" {
		os.Exit(2)
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		os.Exit(3)
	}
	time.Sleep(2 * time.Minute)
}

func TestPathWithinRoot(t *testing.T) {
	root := filepath.Join(`C:\`, "Users", "example", "DefenseClaw")
	for _, test := range []struct {
		name string
		path string
		want bool
	}{
		{name: "child", path: filepath.Join(root, "bin", "defenseclaw.exe"), want: true},
		{name: "case-insensitive child", path: filepath.Join(`c:\`, "USERS", "EXAMPLE", "DEFENSECLAW", "bin", "python.exe"), want: true},
		{name: "root itself", path: root, want: false},
		{name: "sibling prefix", path: root + "-old\\bin\\defenseclaw.exe", want: false},
		{name: "parent", path: filepath.Dir(root), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pathWithinRoot(test.path, root); got != test.want {
				t.Fatalf("pathWithinRoot(%q, %q) = %t, want %t", test.path, root, got, test.want)
			}
		})
	}
}

func copyExecutable(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
