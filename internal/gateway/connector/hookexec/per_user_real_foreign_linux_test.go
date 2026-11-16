// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This integration test uses a real second local account when passwordless
// sudo is available. It proves that a foreign listener sees zero request
// bytes, including the bearer and tool event, on the connected socket.
func TestPerUserHookRefusesAnotherAccountListener(t *testing.T) {
	if os.Getenv("DC_TEST_FOREIGN_LISTENER") == "1" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		fmt.Printf("FOREIGN_ADDR=%s\n", listener.Addr())
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var first [1]byte
		n, _ := conn.Read(first[:])
		fmt.Printf("FOREIGN_BYTES=%d\n", n)
		return
	}
	if err := exec.Command("sudo", "-n", "-u", "nobody", "true").Run(); err != nil {
		t.Skipf("passwordless second-account execution is unavailable: %v", err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "defenseclaw-foreign-listener-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, "hookexec.test")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "/usr/bin/env",
		"DC_TEST_FOREIGN_LISTENER=1", copyPath, "-test.run=^TestPerUserHookRefusesAnotherAccountListener$")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || !strings.HasPrefix(reader.Text(), "FOREIGN_ADDR=") {
		t.Fatalf("second-account listener did not start: %q, stderr=%q", reader.Text(), stderr.String())
	}
	addr := strings.TrimPrefix(reader.Text(), "FOREIGN_ADDR=")
	_, postErr := PostPerUserHook(ctx, addr, "/api/v1/opencode/hook",
		map[string]string{"Authorization": "Bearer account-private-token"}, []byte(`{"tool_input":"private command"}`))
	if postErr == nil {
		t.Error("foreign listener was accepted")
	}
	if !reader.Scan() || reader.Text() != "FOREIGN_BYTES=0" {
		t.Errorf("foreign listener received request bytes or did not finish: %q, stderr=%q", reader.Text(), stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("second-account listener: %v, stderr=%q", err, stderr.String())
	}
}
