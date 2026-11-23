// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// podHelperEnv is the result file of the pod-mode helper below.
const podHelperEnv = "DC_PROCESSUTIL_TEST_POD_HELPER"

// TestPodRunnerHelper is a scanner sidecar under a container's default
// seccomp profile: PID 1 of its own PID namespace with its own /proc, no
// capabilities, and a filter that refuses user namespaces with EPERM. It
// writes one line per check to the result file.
func TestPodRunnerHelper(t *testing.T) {
	out := os.Getenv(podHelperEnv)
	if out == "" {
		t.Skip("helper process")
	}
	var lines []string
	say := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	defer func() { _ = os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o600) }()
	if os.Getpid() != 1 {
		say("setup: pid %d", os.Getpid())
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		say("setup: private mounts: %v", err)
		return
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		say("setup: mount proc: %v", err)
		return
	}
	refuseUserNamespaces(t, syscall.EPERM)
	// Root of this user namespace only; drop every capability as the chart's
	// sidecar has none.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var none [2]unix.CapUserData
	if err := unix.Capset(&hdr, &none[0]); err != nil {
		say("setup: drop capabilities: %v", err)
		return
	}
	podAllowRoot = true
	ctx := context.Background()

	// Outside pod mode a refused namespace still fails closed, as PID 1 too.
	err := RunTracked(CommandContext(ctx, "/bin/sh", "-c", `: > "$1"`, "sh", out+".tracked"))
	_, ranErr := os.Stat(out + ".tracked")
	say("tracked unavailable=%t ran=%t", errors.Is(err, ErrContainmentUnavailable), ranErr == nil)

	scratch := filepath.Join(filepath.Dir(out), "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		say("setup: scratch: %v", err)
		return
	}
	p := NewPodRunner(scratch)
	say("check err=%v", p.Check())

	// The scan runs; a detached leftover that holds the output does not
	// hold the scan, and is gone when Run returns.
	var stdout strings.Builder
	cmd := CommandContext(ctx, "/bin/sh", "-c", `: > "$1"; setsid sleep 300 & echo scanned`, "sh", out+".pod")
	cmd.Stdout = &stdout
	err = p.Run(cmd)
	_, ranErr = os.Stat(out + ".pod")
	others, _ := podOtherPIDs()
	say("pod err=%v ran=%t stdout=%q others=%d", err, ranErr == nil, strings.TrimSpace(stdout.String()), len(others))

	// A non-zero exit is the scanner's own answer.
	err = p.Run(CommandContext(ctx, "/bin/sh", "-c", "exit 3"))
	var exitErr *exec.ExitError
	say("exit3 code=%d", func() int {
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		return -1
	}())

	// The scanner's Landlock domain and filter: no ptrace of the worker.
	err = p.Run(CommandContext(ctx, "/bin/sh", "-c", `cat /proc/1/environ >/dev/null 2>&1 && exit 9; exit 0`))
	say("environ err=%v", err)

	// Reset sweeps a leftover the worker did not start and empties scratch.
	_ = os.WriteFile(filepath.Join(scratch, "planted"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(scratch, "cache", "deep"), 0o700)
	stray := exec.Command("/bin/sleep", "300")
	_ = stray.Start()
	err = p.Reset()
	left, _ := os.ReadDir(scratch)
	others, _ = podOtherPIDs()
	say("reset err=%v scratch=%d others=%d", err, len(left), len(others))
}

// GAP-0828: under RuntimeDefault the scanner sidecar never scanned, as
// RunTracked's namespaces are refused there and it fails closed (GAP-0521).
// The explicit pod-contained mode scans with the container as the boundary;
// outside it the refusal still fails closed.
func TestPodRunnerScansWhereNamespacesAreRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "result")
	helper := exec.Command(os.Args[0], "-test.run=^TestPodRunnerHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), podHelperEnv+"="+out)
	helper.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	if b, err := helper.CombinedOutput(); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("this host refuses the test's own namespaces: %v", err)
		}
		t.Fatalf("helper: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("helper wrote no result: %v", err)
	}
	report := string(b)
	for _, want := range []string{
		"tracked unavailable=true ran=false\n",
		"check err=<nil>\n",
		`pod err=<nil> ran=true stdout="scanned" others=0` + "\n",
		"exit3 code=3\n",
		"environ err=<nil>\n",
		"reset err=<nil> scratch=0 others=0\n",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("pod mode report lacks %q:\n%s", want, report)
		}
	}
}

// The pod-contained mode refuses outside PID 1 of its own namespace, and a
// runner without a usable scratch folder refuses every command.
func TestPodRunnerRefusesOutsidePID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("the test itself is PID 1")
	}
	ran := filepath.Join(t.TempDir(), "ran")
	for _, p := range []*PodRunner{NewPodRunner(t.TempDir()), NewPodRunner("/"), NewPodRunner("")} {
		err := p.Run(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", ran))
		if !errors.Is(err, ErrContainmentUnavailable) || !errors.Is(err, ErrNotContained) {
			t.Fatalf("Run outside pod conditions = %v, want unavailable", err)
		}
		if _, err := os.Stat(ran); err == nil {
			t.Fatal("the command ran outside pod conditions")
		}
		if err := p.Check(); !errors.Is(err, ErrContainmentUnavailable) {
			t.Fatalf("Check = %v", err)
		}
	}
}
