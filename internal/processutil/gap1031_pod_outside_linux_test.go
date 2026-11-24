// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil_test

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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/substrate/scanworker"
)

// outsidePodHelperEnv is the folder of the GAP-1031 helper below.
const outsidePodHelperEnv = "DC_PROCESSUTIL_TEST_GAP1031_OUTSIDE_POD"

// TestGAP1031OutsidePodHelper is `defenseclaw-gateway substrate scan-worker
// --pod-contained` started by hand on a host under `unshare -U -p -f`: PID 1
// of its own PID namespace, not root, no capabilities, but the host's mounts.
// Its scratch and clear folders stand for the host's /tmp and /dev/shm.
func TestGAP1031OutsidePodHelper(t *testing.T) {
	dir := os.Getenv(outsidePodHelperEnv)
	if dir == "" {
		t.Skip("helper process")
	}
	result := "setup: pid " + fmt.Sprint(os.Getpid())
	defer func() { _ = os.WriteFile(filepath.Join(dir, "result"), []byte(result+"\n"), 0o600) }()
	if os.Getpid() != 1 {
		return
	}
	w := &scanworker.Worker{
		Dir: filepath.Join(dir, "scan"),
		Pod: processutil.NewPodRunner(filepath.Join(dir, "host-tmp"), filepath.Join(dir, "host-shm")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := w.Serve(ctx)
	result = fmt.Sprintf("serve err=%v unavailable=%t", err, errors.Is(err, processutil.ErrContainmentUnavailable))
}

// GAP-1031: run outside a pod as a non-root PID 1 under unshare, the pod
// scan worker's startup Reset emptied the host's /tmp (and /dev/shm, and the
// --dir folder) of every file its user could remove, then failed on the
// first one it could not. It must refuse before it removes anything.
func TestGAP1031PodWorkerOutsidePodKeepsHostFiles(t *testing.T) {
	dir := t.TempDir()
	planted := []string{
		filepath.Join(dir, "host-tmp", "another-session.sock"),
		filepath.Join(dir, "host-tmp", "build-cache", "object"),
		filepath.Join(dir, "host-shm", "app-segment"),
		filepath.Join(dir, "scan", "kept"),
	}
	for _, p := range planted {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestGAP1031OutsidePodHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), outsidePodHelperEnv+"="+dir)
	helper.SysProcAttr = &syscall.SysProcAttr{
		// unshare -U --map-user=UID --map-group=GID -p -f: non-root PID 1,
		// no capabilities after exec, the host's mounts.
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
	b, err := os.ReadFile(filepath.Join(dir, "result"))
	if err != nil {
		t.Fatalf("helper wrote no result: %v", err)
	}
	report := string(b)
	for _, p := range planted {
		if got, err := os.ReadFile(p); err != nil || string(got) != "keep" {
			t.Errorf("GAP-1031: the pod scan worker outside a pod removed %s (%v); report: %s", p, err, report)
		}
	}
	want := "empties no folder outside a pod"
	if !strings.Contains(report, want) || !strings.Contains(report, "unavailable=true") {
		t.Fatalf("GAP-1031: the worker outside a pod did not refuse with a plain reason (%q): %s", want, report)
	}
}
