// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package openshell_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// A second copy of this test binary named openshell-gateway listens on a
// loopback port. /proc/<pid>/exe then names the actual gateway executable.
func TestUserVMDriverGatewayHelper(t *testing.T) {
	if os.Getenv("DC_TEST_VM_GATEWAY_HELPER") != "1" {
		return
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("GATEWAY_READY " + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

// The selected gateway may live outside every conventional driver folder.
// A missing driver_dir falls through to its real executable's sibling, and
// an explicit driver_dir tries that same sibling after the configured path.
func TestUserVMDriverDirsFindSelectedGatewaySibling(t *testing.T) {
	parent := t.TempDir()
	configDir := filepath.Join(parent, "openshell")
	t.Setenv("XDG_CONFIG_HOME", parent)
	home := t.TempDir()
	binDir := filepath.Join(t.TempDir(), "gateway", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gw := filepath.Join(binDir, openshell.GatewayBinary)
	if err := os.Link(self, gw); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gw, "-test.run=^TestUserVMDriverGatewayHelper$")
	cmd.Env = append(os.Environ(), "DC_TEST_VM_GATEWAY_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if line := scanner.Text(); strings.HasPrefix(line, "GATEWAY_READY ") {
				ready <- strings.TrimPrefix(line, "GATEWAY_READY ")
				return
			}
		}
		ready <- ""
	}()
	var port string
	select {
	case port = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway helper did not listen")
	}
	if port == "" {
		t.Fatal("gateway helper exited before listening")
	}
	// The active CLI registration is unrelated. The managed daemon selects
	// its gateway by its configured port, not by that registration.
	writeRegistration(t, configDir, "openshell", map[string]any{
		"name": "openshell", "gateway_endpoint": "https://127.0.0.1:1",
		"is_remote": false, "auth_mode": "mtls",
	}, nil)
	driver := filepath.Join(binDir, "openshell-driver-vm")
	touchExecutable(t, driver)
	defaultDriver := filepath.Join(home, ".local", "libexec", "openshell", "openshell-driver-vm")
	touchExecutable(t, defaultDriver)
	configured := filepath.Join(home, "configured")
	selected := openshell.GatewayExecutableOnPort(mustPort(t, port))
	if selected != gw {
		t.Fatalf("listener executable %q, want %q", selected, gw)
	}
	dirs := openshell.UserVMDriverDirs(home, configured, selected)
	if len(dirs) != 2 || dirs[0] != configured || dirs[1] != binDir || openshell.FindVMDriverIn(dirs) != driver {
		t.Fatalf("driver_dir and contacted gateway sibling: dirs %v, selected %q; want %q", dirs, openshell.FindVMDriverIn(dirs), driver)
	}
	if err := os.Remove(defaultDriver); err != nil {
		t.Fatal(err)
	}
	dirs = openshell.UserVMDriverDirs(home, "", selected)
	if openshell.FindVMDriverIn(dirs) != driver {
		t.Fatalf("no driver_dir: dirs %v, selected %q; want contacted gateway sibling %q", dirs, openshell.FindVMDriverIn(dirs), driver)
	}
}

func mustPort(t *testing.T, text string) int {
	t.Helper()
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
