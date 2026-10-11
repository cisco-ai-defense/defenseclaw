// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestPluginScanCancellationStopsWorker(t *testing.T) {
	switch os.Getenv("DC_PLUGIN_CANCEL_ROLE") {
	case "child":
		time.Sleep(10 * time.Second)
		return
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestPluginScanCancellationStopsWorker$")
		child.Env = append(os.Environ(), "DC_PLUGIN_CANCEL_ROLE=child")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(20)
		}
		if err := testenv.PublishFile(os.Getenv("DC_PLUGIN_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid))); err != nil {
			os.Exit(21)
		}
		time.Sleep(10 * time.Second)
		return
	}
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "scanner.cmd")
	script := fmt.Sprintf("@echo off\r\n\"%s\" -test.run=^TestPluginScanCancellationStopsWorker$\r\n", os.Args[0])
	if err := os.WriteFile(wrapper, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "child.pid")
	t.Setenv("DC_PLUGIN_CANCEL_ROLE", "parent")
	t.Setenv("DC_PLUGIN_CHILD_PID", pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (&PluginScanner{BinaryPath: wrapper}).Scan(ctx, dir)
		done <- err
	}()
	data, err := testenv.WaitForFile(pidFile, done)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	childExit := testenv.ProcessExit(t, pid)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled plugin scan returned success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("plugin scan kept waiting for the worker after cancellation")
	}
	select {
	case <-childExit:
	case <-time.After(4 * time.Second):
		t.Fatal("plugin worker survived cancellation")
	}
}
