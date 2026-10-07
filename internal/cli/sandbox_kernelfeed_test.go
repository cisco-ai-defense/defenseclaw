// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

type kernelFeedHeader struct{}

func (kernelFeedHeader) Header() sandboxfeed.Header {
	return sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: "dev", Tetragon: sandboxfeed.TetragonConnected}
}
func (kernelFeedHeader) Close() error { return nil }

// kernelFeedTest points the kernel-feed commands at a temporary root, a
// gateway with its helper beside it, and fake systemctl and helper runs.
func kernelFeedTest(t *testing.T, euid int) (gateway string, calls *[]string) {
	t.Helper()
	root := t.TempDir()
	bin := t.TempDir()
	gateway = filepath.Join(bin, "defenseclaw-gateway")
	for _, name := range []string{"defenseclaw-gateway", sandboxfeed.HelperName} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("binary "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	calls = &[]string{}
	installed := func() bool { _, err := os.Stat(filepath.Join(root, sandboxfeed.UnitPath)); return err == nil }
	lifecycle := &sandboxfeed.Lifecycle{
		Root:    root,
		Geteuid: func() int { return euid },
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			*calls = append(*calls, filepath.Base(name)+" "+strings.Join(args, " "))
			switch {
			case slices.Equal(args, []string{"--version"}):
				return "defenseclaw-sensor-helper version dev (commit=unknown)", nil
			case slices.Equal(args, []string{"--sandbox-feed", "--check"}):
				return "Tetragon v1.7.1 on /var/run/tetragon/tetragon.sock; Docker Engine answers", nil
			case len(args) > 0 && args[0] == "is-active":
				return "active", nil
			}
			return "", nil
		},
		Dial: func(context.Context, string) (sandboxfeed.FeedHeader, error) {
			if !installed() {
				return nil, sandboxfeed.ErrNotInstalled
			}
			return kernelFeedHeader{}, nil
		},
	}
	previous, previousPath, previousGOOS := sandboxKernelFeed, sandboxGatewayPath, sandboxKernelFeedGOOS
	sandboxKernelFeed = func() *sandboxfeed.Lifecycle { return lifecycle }
	sandboxGatewayPath = func() string { return gateway }
	sandboxKernelFeedGOOS = "linux"
	t.Cleanup(func() {
		sandboxKernelFeed, sandboxGatewayPath, sandboxKernelFeedGOOS = previous, previousPath, previousGOOS
	})
	return gateway, calls
}

func runKernelFeed(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(append([]string{"sandbox", "kernel-feed"}, args...))
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	_, err := rootCmd.ExecuteC()
	return stdout.String() + stderr.String(), err
}

func TestSandboxKernelFeedInstallStatusUninstall(t *testing.T) {
	gateway, calls := kernelFeedTest(t, 0)
	out, err := runKernelFeed(t, "status", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Installed      bool   `json:"installed"`
		Reachable      bool   `json:"reachable"`
		Reason         string `json:"reason"`
		InstallCommand string `json:"install_command"`
		Uninstall      string `json:"uninstall_command"`
		Protocol       int    `json:"gateway_protocol"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil || status.Installed || status.Reason != sandboxfeed.ReasonNotInstalled ||
		status.InstallCommand != "sudo "+gateway+" sandbox kernel-feed install" || status.Uninstall != "" || status.Protocol != sandboxfeed.ProtocolVersion {
		t.Fatalf("status before install = %s (%v)", out, err)
	}

	out, err = runKernelFeed(t, "install")
	if err != nil || !strings.Contains(out, "the sandbox kernel feed is installed") || !strings.Contains(out, "Tetragon connected") {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if !slices.Contains(*calls, "systemctl restart "+sandboxfeed.UnitName) {
		t.Fatalf("calls = %q", *calls)
	}
	out, err = runKernelFeed(t, "status", "-o", "text")
	if err != nil || !strings.Contains(out, "installed:  yes") || !strings.Contains(out, "answers (build dev") {
		t.Fatalf("status after install: %v\n%s", err, out)
	}
	out, err = runKernelFeed(t, "status", "-o", "json")
	if err != nil || json.Unmarshal([]byte(out), &status) != nil || !status.Installed || !status.Reachable ||
		status.Uninstall != "sudo "+gateway+" sandbox kernel-feed uninstall" {
		t.Fatalf("status json after install: %v\n%s", err, out)
	}
	out, err = runKernelFeed(t, "uninstall")
	if err != nil || !strings.Contains(out, "removed") || !strings.Contains(out, sandboxfeed.UnitPath) {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	out, err = runKernelFeed(t, "uninstall")
	if err != nil || !strings.Contains(out, "not installed") {
		t.Fatalf("second uninstall: %v\n%s", err, out)
	}
}

func TestSandboxKernelFeedRefusals(t *testing.T) {
	gateway, calls := kernelFeedTest(t, 1000)
	out, err := runKernelFeed(t, "install")
	if err == nil || !strings.Contains(err.Error(), "sudo "+gateway+" sandbox kernel-feed install") {
		t.Fatalf("install as a user: %v\n%s", err, out)
	}
	if _, err := runKernelFeed(t, "uninstall"); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("uninstall as a user: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
	if _, err := runKernelFeed(t, "install"); err == nil || commandExitCode(err) != 3 || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("install on a managed host: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	sandboxKernelFeedGOOS = "darwin"
	if _, err := runKernelFeed(t, "status", "-o", "text"); err == nil || commandExitCode(err) != 3 || !strings.Contains(err.Error(), "Linux only") {
		t.Fatalf("status on a Mac: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("something ran: %q", *calls)
	}
}
