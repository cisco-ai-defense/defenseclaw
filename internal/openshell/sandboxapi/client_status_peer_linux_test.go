//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestGAP0617InheritedSocketResponder(t *testing.T) {
	if os.Getenv("DC_G617_STATUS_HELPER") == "1" {
		file := os.NewFile(3, "inherited sandbox socket")
		ln, err := net.FileListener(file)
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		claim := os.Getpid()
		if text := os.Getenv("DC_G617_CLAIM_PID"); text != "" {
			claim, err = strconv.Atoi(text)
			if err != nil {
				t.Fatal(err)
			}
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(Status{DaemonPID: claim})
		})}
		fmt.Println("READY")
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			t.Fatal(err)
		}
		return
	}
	for _, tc := range []struct {
		name, claimedPID string
		verified         bool
	}{
		{name: "answering daemon", verified: true},
		{name: "different claimed process", claimedPID: strconv.Itoa(os.Getpid())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unix socket paths have a small kernel limit. Use a short private
			// directory even when the test runner has a long TMPDIR.
			dir, err := os.MkdirTemp("/tmp", "g617-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "s")
			ln, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			listener := ln.(*net.UnixListener)
			listener.SetUnlinkOnClose(false)
			file, err := listener.File()
			if err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(self, "-test.run=^TestGAP0617InheritedSocketResponder$")
			cmd.Env = append(os.Environ(), "DC_G617_STATUS_HELPER=1", "DC_G617_CLAIM_PID="+tc.claimedPID)
			cmd.ExtraFiles = []*os.File{file}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			})
			_ = file.Close()
			_ = ln.Close()
			if scan := bufio.NewScanner(stdout); !scan.Scan() || scan.Text() != "READY" {
				t.Fatal("inherited status responder did not start")
			}
			st, pid, err := NewUnixClient(path).StatusWithPeer(context.Background())
			if err != nil || st == nil {
				t.Fatalf("status = %+v, pid = %d, err = %v", st, pid, err)
			}
			if tc.verified && pid != cmd.Process.Pid || !tc.verified && pid != 0 {
				t.Fatalf("verified responder PID = %d, child = %d, claimed = %d", pid, cmd.Process.Pid, st.DaemonPID)
			}
		})
	}
}
