// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

func TestHostStageWindowsGitCommandOwnsDescendantsOnTimeout(t *testing.T) {
	const helperKey = "DEFENSECLAW_HOST_STAGE_GIT_TREE_HELPER"
	const pidKey = "DEFENSECLAW_HOST_STAGE_GIT_TREE_PID"
	const releaseKey = "DEFENSECLAW_HOST_STAGE_GIT_TREE_RELEASE"
	const selector = "-test.run=^TestHostStageWindowsGitCommandOwnsDescendantsOnTimeout$"
	if mode := os.Getenv(helperKey); mode != "" {
		if mode == "child" {
			if err := testenv.PublishFile(os.Getenv(pidKey), []byte(strconv.Itoa(os.Getpid()))); err != nil {
				os.Exit(21)
			}
		} else if mode == "parent" {
			child := exec.Command(os.Args[0], selector)
			child.Env = append(os.Environ(), helperKey+"=child")
			// Deliberately inherit the captured streams: killing only the
			// launcher would leave Cmd.Wait blocked on the descendant.
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			if err := child.Start(); err != nil {
				os.Exit(22)
			}
		} else {
			os.Exit(23)
		}
		_, _ = testenv.AwaitRelease(os.Getenv(releaseKey))
		os.Exit(0)
	}
	release := testenv.NewRelease(t)
	pidFile := filepath.Join(t.TempDir(), "owned-descendant.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], selector)
	cmd.Env = append(os.Environ(), helperKey+"=parent", pidKey+"="+pidFile, releaseKey+"="+release.Token())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- processutil.RunTree(cmd) }()
	data, err := testenv.WaitForFile(pidFile, done)
	if err != nil {
		t.Fatalf("owned descendant did not become ready: %v", err)
	}
	pid, err := strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	// Hold the exact live descendant handle before cancellation; never
	// signal or make cleanup decisions from a potentially reused PID.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled host-stage command reported success")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("host-stage command exceeded bounded Job/pipe cleanup")
	}
	status, err := windows.WaitForSingleObject(process, 1000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("owned descendant survived command cancellation: status=%d error=%v", status, err)
	}
}
