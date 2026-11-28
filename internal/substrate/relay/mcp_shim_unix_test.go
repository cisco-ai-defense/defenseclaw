// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMCPStdioShim (B3.3 S4b): `defenseclaw-actor-relay mcp-stdio NAME`
// with no bridge says so and exits 1; with one it copies stdin to the
// socket and the socket to stdout byte for byte (no decode: bytes that are
// not JSON, not UTF-8 or "\r\n" pass as they are) and exits when the relay
// ends the connection.
func TestMCPStdioShim(t *testing.T) {
	home, err := os.MkdirTemp("", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	t.Setenv("HOME", home)

	var out, errb bytes.Buffer
	if code := MCPStdio("notes", strings.NewReader("{}\n"), &out, &errb); code != 1 ||
		errb.String() != "the laptop MCP server notes is not bridged right now\n" || out.Len() != 0 {
		t.Fatalf("no socket: exit %d stderr %q stdout %q", code, errb.String(), out.String())
	}
	// The relay binary's subcommand is this shim.
	errb.Reset()
	if code := Main([]string{"mcp-stdio", "notes"}, &out, &errb); code != 1 ||
		errb.String() != "the laptop MCP server notes is not bridged right now\n" {
		t.Fatalf("defenseclaw-actor-relay mcp-stdio notes: exit %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := Main([]string{"mcp-stdio"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage: defenseclaw-actor-relay mcp-stdio NAME") {
		t.Fatalf("mcp-stdio without NAME: exit %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := MCPStdio("../x", strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("bad name: exit %d %q", code, errb.String())
	}

	if err := os.Mkdir(filepath.Join(home, MCPSocketDir), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", mcpSocketPath(home, "notes"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	in := []byte("{\"id\":1}\r\nnot json \xff\x00\n{\"a\":\"\\u2028\"}")
	back := []byte("{\"id\":1,\"result\":{}}\n\xfe raw\n")
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c) // until the shim half-closes at stdin EOF
		got <- b
		_, _ = c.Write(back)
	}()
	out.Reset()
	errb.Reset()
	done := make(chan int, 1)
	go func() { done <- MCPStdio("notes", bytes.NewReader(in), &out, &errb) }()
	select {
	case code := <-done:
		if code != 0 || errb.Len() != 0 {
			t.Fatalf("exit %d stderr %q", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shim did not exit when the relay ended the connection")
	}
	if b := <-got; !bytes.Equal(b, in) {
		t.Fatalf("socket got %q, want %q", b, in)
	}
	if !bytes.Equal(out.Bytes(), back) {
		t.Fatalf("stdout %q, want %q", out.Bytes(), back)
	}
}

// TestMCPLineCap: an agent line over the cap is drained and dropped, and
// the next line is read whole.
func TestMCPLineCap(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 40)+"\nok\r\nlast"), 16)
	if l, err := readMCPLine(r, 32); !errors.Is(err, errMCPLineTooLong) || l != nil {
		t.Fatalf("long line: %q %v", l, err)
	}
	if l, err := readMCPLine(r, 32); err != nil || string(l) != "ok" {
		t.Fatalf("next line: %q %v", l, err)
	}
	if l, err := readMCPLine(r, 32); !errors.Is(err, io.EOF) || string(l) != "last" {
		t.Fatalf("last line: %q %v", l, err)
	}
}
