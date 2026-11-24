// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/scanworker"
)

// workerHelperEnv is "<tracked|pod>,<folder>" for the helper below.
const workerHelperEnv = "DC_PROCESSUTIL_TEST_GAP0828_WORKER"

const gap0828Job = "0123456789abcdef0123456789abcdef"

// TestGAP0828WorkerHelper is the scanner sidecar under the chart's default
// seccomp profile (user namespaces refused with EPERM), with the worker's
// default containment (tracked) or the chart's pod-contained mode (pod, as
// PID 1 of its own PID namespace, not root, without capabilities).
// It sends one skill job from its own PID namespace and writes the answer
// to <folder>/answer.json. Pod mode must refuse that peer (GAP-0873).
func TestGAP0828WorkerHelper(t *testing.T) {
	spec := os.Getenv(workerHelperEnv)
	if spec == "" {
		t.Skip("helper process")
	}
	mode, dir, _ := strings.Cut(spec, ",")
	processutil.RefuseUserNamespacesForTest(t, syscall.EPERM)
	w := &scanworker.Worker{Dir: filepath.Join(dir, "scan"), Launcher: filepath.Join(dir, "fake-skill-scanner"), Timeout: 20 * time.Second}
	if mode == "pod" {
		// The chart container's mounts (GAP-1031): a read-only root and
		// its own mount on the scratch folder.
		processutil.PodMountsForTest(t, filepath.Join(dir, "tmp"))
		w.Pod = processutil.NewPodRunner(filepath.Join(dir, "tmp"))
	}
	job := filepath.Join(w.Dir, scanner.ScanJobsDirName, gap0828Job)
	if err := os.MkdirAll(job, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "SKILL.md"), []byte("---\nname: fixture\ndescription: a fixture\n---\nSay hello.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Serve(ctx) }()
	sock := filepath.Join(w.Dir, scanner.ScanSocketName)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	body, _ := json.Marshal(scanner.RemoteScanRequest{Job: gap0828Job, Kind: scanner.RemoteKindSkill})
	var resp *http.Response
	var err error
	for i := 0; i < 100; i++ {
		resp, err = client.Post("http://worker/v1/scan", "application/json", bytes.NewReader(body))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var a bytes.Buffer
	_, _ = a.ReadFrom(resp.Body)
	if err := os.WriteFile(filepath.Join(dir, "answer.json"), a.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0828: under the chart's RuntimeDefault seccomp the scanner sidecar
// answered every scan "unavailable", as the scanner's namespaces are refused
// there and that containment fails closed (GAP-0521). The pod-contained mode
// the chart selects scans; a worker without it still fails closed. A
// same-namespace request cannot impersonate the separate gateway container.
func TestGAP0828WorkerRuntimeDefault(t *testing.T) {
	for _, mode := range []string{"tracked", "pod"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			mark := filepath.Join(dir, "tmp", "scanner-ran")
			fake := "#!/bin/sh\n: > '" + mark + "'\necho '{\"findings\":[]}'\n"
			if err := os.WriteFile(filepath.Join(dir, "fake-skill-scanner"), []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o700); err != nil {
				t.Fatal(err)
			}
			helper := exec.Command(os.Args[0], "-test.run=^TestGAP0828WorkerHelper$", "-test.count=1")
			helper.Env = append(os.Environ(), workerHelperEnv+"="+mode+","+dir)
			if mode == "pod" {
				helper.SysProcAttr = &syscall.SysProcAttr{
					Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
					UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}},
					GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}},
				}
			}
			if b, err := helper.CombinedOutput(); err != nil {
				if mode == "pod" && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSPC)) {
					t.Skipf("this host refuses the test's own namespaces: %v", err)
				}
				t.Fatalf("helper: %v\n%s", err, b)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "answer.json"))
			if err != nil {
				t.Fatal(err)
			}
			var a scanner.RemoteScanAnswer
			if err := json.Unmarshal(raw, &a); err != nil {
				t.Fatalf("answer %s: %v", raw, err)
			}
			_, ranErr := os.Stat(mark)
			switch mode {
			case "tracked":
				if a.Code != "unavailable" || !strings.Contains(a.Error, "refuses the namespaces") || ranErr == nil {
					t.Fatalf("outside pod mode a refused namespace must fail closed: answer %s, scanner ran=%t", raw, ranErr == nil)
				}
			case "pod":
				if a.Code != "refused" || !strings.Contains(a.Error, "gateway container") || ranErr == nil {
					t.Fatalf("pod mode accepted its own same-namespace peer: answer %s, scanner ran=%t", raw, ranErr == nil)
				}
			}
		})
	}
}
