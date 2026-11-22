// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// TestGAP1164ReusedPIDHelper is the process of this account that got the
// gateway's PID in TestHomeGatewayHoldsPortRefusesAReusedPID.
func TestGAP1164ReusedPIDHelper(t *testing.T) {
	if os.Getenv("DC_GAP1164_HELPER") != "1" {
		t.Skip("helper process only")
	}
	time.Sleep(2 * time.Minute)
}

// rel-1-0-10:GAP-1164 (PID reuse): gateway-api.json names the PID and port of
// the gateway that wrote it, and outlives a crash. A later process of this
// account that got that PID and bound the port is not this home's gateway:
// its creation time is not the one the record carries.
func TestHomeGatewayHoldsPortRefusesAReusedPID(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^TestGAP1164ReusedPIDHelper$")
	child.Env = append(os.Environ(), "DC_GAP1164_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := child.Process.Pid
	var live string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if identity, err := processStartIdentity(pid); err == nil && identity != "" {
			live = identity
			break
		}
		if time.Now().After(deadline) {
			t.Skip("no start identity for a child process on this system")
		}
	}

	dir := t.TempDir()
	const port = 18972
	prev := homeGatewayPortHolder
	homeGatewayPortHolder = func(string, int) (PortHolder, error) { return PortHolder{PID: pid, UID: os.Getuid()}, nil }
	t.Cleanup(func() { homeGatewayPortHolder = prev })
	write := func(body string) {
		t.Helper()
		record := filepath.Join(dir, "gateway-api.json")
		_ = os.Remove(record)
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(record); err != nil {
			t.Fatal(err)
		}
	}

	write(fmt.Sprintf(`{"pid":%d,"host":"127.0.0.1","port":%d,"start_identity":"1"}`, pid, port))
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("a process of this account that reused the recorded gateway's PID holds the port")
	}
	write(fmt.Sprintf(`{"pid":%d,"host":"127.0.0.1","port":%d,"start_identity":%q}`, pid, port, live))
	if !HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("the gateway the record names, by PID, port and start identity, holds the port")
	}
	// A gateway older than 1.0.10 wrote no start identity: the account check
	// is all it has until it restarts.
	write(fmt.Sprintf(`{"pid":%d,"host":"127.0.0.1","port":%d}`, pid, port))
	if !HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("a record without a start identity, of this account's holder, holds the port")
	}
}
