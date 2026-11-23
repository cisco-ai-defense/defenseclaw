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
// seccomp profile: PID 1 of its own PID namespace, not root and without
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
	refuseUserNamespaces(t, syscall.EPERM)
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
	// The helper's PID and user namespaces are the container's; its mounts
	// are the chart container's (GAP-1031: a read-only root, scratch its own
	// mount).
	fakePodMounts(t, scratch)
	p := NewPodRunner(scratch)
	say("check err=%v", p.Check())

	// The scan runs; a detached leftover that holds the output does not
	// hold the scan, and is gone when Run returns.
	podMark := filepath.Join(scratch, "pod-marker")
	var stdout strings.Builder
	cmd := CommandContext(ctx, "/bin/sh", "-c", `: > "$1"; setsid sleep 300 & echo scanned`, "sh", podMark)
	cmd.Stdout = &stdout
	err = p.Run(cmd)
	_, ranErr = os.Stat(podMark)
	say("pod err=%v ran=%t stdout=%q alone=%t", err, ranErr == nil, strings.TrimSpace(stdout.String()), podAlone())

	// A non-zero exit is the scanner's own answer.
	err = p.Run(CommandContext(ctx, "/bin/sh", "-c", "exit 3"))
	var exitErr *exec.ExitError
	say("exit3 code=%d", func() int {
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		return -1
	}())

	// The worker is not dumpable and the scanner is in its own Landlock
	// domain: it cannot read the worker's environment or memory. This /proc
	// is the host's, where the worker has its host PID.
	self, _ := os.Readlink("/proc/self")
	err = p.Run(CommandContext(ctx, "/bin/sh", "-c", `cat "/proc/$1/environ" >/dev/null 2>&1 && exit 9; exit 0`, "sh", self))
	say("environ err=%v", err)

	// Alice's scan may read Alice's job, but not Bob's queued job.
	jobs := filepath.Join(filepath.Dir(out), "jobs")
	alice := filepath.Join(jobs, "alice")
	bob := filepath.Join(jobs, "bob")
	if err := os.MkdirAll(alice, 0o700); err != nil {
		say("setup: alice: %v", err)
		return
	}
	if err := os.MkdirAll(bob, 0o700); err != nil {
		say("setup: bob: %v", err)
		return
	}
	_ = os.WriteFile(filepath.Join(alice, "SKILL.md"), []byte("alice-private"), 0o600)
	_ = os.WriteFile(filepath.Join(bob, "SKILL.md"), []byte("bob-private"), 0o600)
	ownOut := filepath.Join(scratch, "own")
	otherOut := filepath.Join(scratch, "other")
	cmd = CommandContext(ctx, "/bin/sh", "-c", `cat "$1/SKILL.md" > "$3"; cat "$2/SKILL.md" > "$4" 2>/dev/null || :`, "sh", alice, bob, ownOut, otherOut)
	err = p.RunJob(cmd, alice)
	own, _ := os.ReadFile(ownOut)
	other, _ := os.ReadFile(otherOut)
	say("jobread err=%v own=%q other=%q", err, own, other)

	// Reset sweeps a leftover the worker did not start and empties scratch.
	_ = os.WriteFile(filepath.Join(scratch, "planted"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(scratch, "cache", "deep"), 0o700)
	stray := exec.Command("/bin/sleep", "300")
	_ = stray.Start()
	err = p.Reset()
	left, _ := os.ReadDir(scratch)
	say("reset err=%v scratch=%d alone=%t", err, len(left), podAlone())
}

func podAlone() bool { return errors.Is(unix.Kill(-1, 0), unix.ESRCH) }

// GAP-0828: under RuntimeDefault the scanner sidecar never scanned, as
// RunTracked's namespaces are refused there and it fails closed (GAP-0521).
// The explicit pod-contained mode scans with the container as the boundary;
// outside it the refusal still fails closed.
func TestPodRunnerScansWhereNamespacesAreRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "result")
	helper := exec.Command(os.Args[0], "-test.run=^TestPodRunnerHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), podHelperEnv+"="+out)
	helper.SysProcAttr = &syscall.SysProcAttr{
		// The helper keeps its own non-root IDs, so its exec leaves it
		// without capabilities, as the chart's sidecar is.
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}},
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
		`pod err=<nil> ran=true stdout="scanned" alone=true` + "\n",
		"exit3 code=3\n",
		"environ err=<nil>\n",
		`jobread err=<nil> own="alice-private" other=""` + "\n",
		"reset err=<nil> scratch=0 alone=true\n",
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
