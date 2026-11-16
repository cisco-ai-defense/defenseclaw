// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// #1164: the relay starts nothing itself. A bad request, an enumerator that
// does not serve, and a refusal all end the relay with a non-zero code and
// the reason on stderr, which the scanner keeps with the failed scan.
func TestEnterpriseWindowsMCPRelayFailsClosed(t *testing.T) {
	oldDial, oldRun := enterpriseWindowsMCPRelayDial, enterpriseWindowsMCPRelayRun
	t.Cleanup(func() { enterpriseWindowsMCPRelayDial, enterpriseWindowsMCPRelayRun = oldDial, oldRun })
	request, err := mcpasuser.NewRequest("DefenseClawGateway", "S-1-5-21-1-2-3-1001", config.MCPServerEntry{
		Name: "notes", Command: "npx", Args: []string{"-y", "."}, Connector: "claudecode",
	})
	if err != nil {
		t.Fatal(err)
	}
	arg, err := mcpasuser.EncodeRequestArg(request)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := runEnterpriseWindowsMCPRelay(context.Background(), "not-a-request", strings.NewReader(""), io.Discard, &stderr); code != 2 ||
		!strings.Contains(stderr.String(), "mcp as-user scan") {
		t.Fatalf("bad request: code %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	enterpriseWindowsMCPRelayDial = func(context.Context, string) (io.ReadWriteCloser, error) {
		return nil, errors.New("the DefenseClaw hook enumerator service is not serving MCP as-user scans")
	}
	if code := runEnterpriseWindowsMCPRelay(context.Background(), arg, strings.NewReader(""), io.Discard, &stderr); code != 3 ||
		!strings.Contains(stderr.String(), "not serving") {
		t.Fatalf("no enumerator: code %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	enterpriseWindowsMCPRelayDial = func(context.Context, string) (io.ReadWriteCloser, error) {
		return nopConn{}, nil
	}
	enterpriseWindowsMCPRelayRun = func(io.ReadWriter, mcpasuser.Request, io.Reader, io.Writer, io.Writer) (int, error) {
		return 0, &mcpasuser.RefusedError{Reason: "dcw-std1 is not signed in"}
	}
	if code := runEnterpriseWindowsMCPRelay(context.Background(), arg, strings.NewReader(""), io.Discard, &stderr); code != 3 ||
		!strings.Contains(stderr.String(), "did not start the server: dcw-std1 is not signed in") {
		t.Fatalf("refused: code %d, stderr %q", code, stderr.String())
	}
	enterpriseWindowsMCPRelayRun = func(io.ReadWriter, mcpasuser.Request, io.Reader, io.Writer, io.Writer) (int, error) {
		return 7, nil
	}
	if code := runEnterpriseWindowsMCPRelay(context.Background(), arg, strings.NewReader(""), io.Discard, io.Discard); code != 7 {
		t.Fatalf("server exit code: %d", code)
	}
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error) { return len(p), nil }
func (nopConn) Close() error                { return nil }
