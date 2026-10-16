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

//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The launcher cuts the real command tree down in place, so these tests run
// ExecuteContext (the argv0 hook in root.go and the real rootCmd) in a child
// process and read its output and exit code.

const launcherRealTreeEnv = "DEFENSECLAW_TEST_LAUNCHER_ARGS"

// TestLauncherRealTreeHelperProcess is the child's body; it does nothing when
// run as an ordinary test.
func TestLauncherRealTreeHelperProcess(t *testing.T) {
	raw, ok := os.LookupEnv(launcherRealTreeEnv)
	if !ok {
		return
	}
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return nil }
	launcherArgv0 = func() string { return "/usr/bin/defenseclaw" }
	os.Args = []string{"/usr/bin/defenseclaw"}
	if raw != "" {
		os.Args = append(os.Args, strings.Split(raw, "\n")...)
	}
	os.Exit(ExecuteContext(context.Background()))
}

func runLauncherRealTree(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(exe, "-test.run=^TestLauncherRealTreeHelperProcess$")
	command.Env = append(os.Environ(), launcherRealTreeEnv+"="+strings.Join(args, "\n"), "HOME="+t.TempDir())
	var out, errOut bytes.Buffer
	command.Stdout, command.Stderr = &out, &errOut
	err = command.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func TestLauncherOnTheRealCommandTree(t *testing.T) {
	t.Run("help offers the sandbox tree and none of the gateway's flags", func(t *testing.T) {
		for _, args := range [][]string{nil, {"--help"}, {"help"}} {
			stdout, stderr, code := runLauncherRealTree(t, args...)
			if code != 0 {
				t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
			}
			if !strings.Contains(stdout, "defenseclaw sandbox run claude") {
				t.Errorf("%v: help does not offer the sandbox tree:\n%s", args, stdout)
			}
			for _, hidden := range []string{"--host", "--port", "--version-json", "completion", "enterprise", "sidecar"} {
				if strings.Contains(stdout, hidden) {
					t.Errorf("%v: help mentions %q:\n%s", args, hidden, stdout)
				}
			}
		}
	})
	t.Run("everything outside the sandbox tree is refused with exit 2", func(t *testing.T) {
		for _, args := range [][]string{
			{"status"}, {"enterprise", "linux", "status"}, {"help", "status"},
			{"--version-json"}, {"--host", "example"}, {"--port", "1"}, {"completion"},
		} {
			stdout, stderr, code := runLauncherRealTree(t, args...)
			if code != 2 || strings.TrimSpace(stderr) != launcherRefusal || stdout != "" {
				t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2 and only the refusal", args, code, stdout, stderr)
			}
		}
	})
	t.Run("the sandbox help is the managed text and does not offer setup", func(t *testing.T) {
		stdout, stderr, code := runLauncherRealTree(t, "sandbox", "--help")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if !strings.Contains(stdout, "Your organization manages sandboxes") {
			t.Errorf("help is not the managed text:\n%s", stdout)
		}
		for _, wrong := range []string{"sandbox setup", "Start with", "on Linux live", "on macOS", "One-time setup"} {
			if strings.Contains(stdout, wrong) {
				t.Errorf("managed sandbox help mentions %q:\n%s", wrong, stdout)
			}
		}
	})
	t.Run("the run help describes copy mode only (GAP-0249)", func(t *testing.T) {
		stdout, stderr, code := runLauncherRealTree(t, "sandbox", "run", "--help")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if !strings.Contains(stdout, "every run works on a copy") {
			t.Errorf("run help is not the managed text:\n%s", stdout)
		}
		for _, wrong := range []string{"live-mounted", "on Linux", "on macOS", "pre-session snapshot", "--context", "--no-snapshot", "sandbox setup"} {
			if strings.Contains(stdout, wrong) {
				t.Errorf("managed run help mentions %q:\n%s", wrong, stdout)
			}
		}
	})
	// The root help lists `help`, so `help --help` answers with its usage
	// and exit 0, as every other listed command does (GAP-0471, GAP-0479,
	// GAP-0480).
	t.Run("the listed help command answers --help", func(t *testing.T) {
		for _, args := range [][]string{{"help", "--help"}, {"help", "-h"}} {
			stdout, stderr, code := runLauncherRealTree(t, args...)
			if code != 0 || strings.Contains(stderr, launcherRefusal) {
				t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
			}
			if !strings.Contains(stdout, "Usage:") || !strings.Contains(stdout, "defenseclaw help") {
				t.Errorf("%v: no usage of the help command:\n%s", args, stdout)
			}
			for _, hidden := range []string{"--host", "--port", "--version-json"} {
				if strings.Contains(stdout, hidden) {
					t.Errorf("%v: help mentions %q:\n%s", args, hidden, stdout)
				}
			}
		}
	})
	t.Run("the sandbox tree answers help", func(t *testing.T) {
		stdout, stderr, code := runLauncherRealTree(t, "sandbox", "--help")
		if code != 0 || !strings.Contains(stdout, "run") {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}

func TestLauncherOffersHelpOnlyForTheSandboxTree(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"help"}, true},
		{[]string{"help", "sandbox"}, true},
		{[]string{"help", "sandbox", "run"}, true},
		{[]string{"help", "status"}, false},
		{[]string{"help", "--help"}, true},
		{[]string{"help", "-h"}, true},
		{[]string{"help", "--host"}, false},
		{[]string{"sandbox", "list"}, true},
		{[]string{"--version-json"}, false},
		{[]string{"--host", "x"}, false},
	} {
		if got := launcherOffers(test.args); got != test.want {
			t.Errorf("launcherOffers(%v) = %v, want %v", test.args, got, test.want)
		}
	}
}

func TestLauncherManagedConfigTakesThePortsAndGatewayFromTheDaemon(t *testing.T) {
	base := config.DefaultConfig()
	defaultIngress, defaultEgress := base.OpenShellIngressPort(), base.OpenShellEgressPort()

	status := &sandboxapi.Status{
		Enabled:     true,
		IngressAddr: "127.0.0.1:19971",
		EgressAddr:  "127.0.0.1:19972",
		Pack:        "balanced",
		Profile:     "strict",
		Gateway:     &sandboxapi.Gateway{Name: "managed-gw", Workspace: "team"},
	}
	got := launcherManagedConfig(base, status)
	if got.OpenShellIngressPort() != 19971 || got.OpenShellEgressPort() != 19972 {
		t.Errorf("ports = %d/%d, want the daemon's 19971/19972", got.OpenShellIngressPort(), got.OpenShellEgressPort())
	}
	if got.OpenShell.Gateway.Name != "managed-gw" || got.OpenShell.Gateway.Workspace != "team" ||
		got.OpenShell.Pack != "balanced" || got.OpenShell.Profile != "strict" || !got.OpenShell.Enabled {
		t.Errorf("OpenShell = %+v, want the daemon's gateway, pack and profile", got.OpenShell)
	}
	if base.OpenShellIngressPort() != defaultIngress || base.OpenShellEgressPort() != defaultEgress || base.OpenShell.Gateway.Name != "" {
		t.Error("the base config was modified")
	}

	// A daemon whose lazy listeners are not bound yet reports no address: the
	// defaults stay.
	lazy := launcherManagedConfig(base, &sandboxapi.Status{Enabled: true})
	if lazy.OpenShellIngressPort() != defaultIngress || lazy.OpenShellEgressPort() != defaultEgress {
		t.Errorf("unbound ports = %d/%d, want the defaults", lazy.OpenShellIngressPort(), lazy.OpenShellEgressPort())
	}
	// An organization pack is the administrator's file: the CLI does not
	// load it by name from the user's own pack folder (GAP-0478).
	if org := launcherManagedConfig(base, &sandboxapi.Status{Enabled: true, Pack: "contractors"}); org.OpenShell.Pack != "" {
		t.Errorf("organization pack copied into openshell.pack: %q", org.OpenShell.Pack)
	}
	// An unreachable daemon leaves the config as it was.
	if launcherManagedConfig(base, nil) != base {
		t.Error("an unreachable daemon changed the config")
	}
	if launcherAddrPort("not an address") != 0 || launcherAddrPort("host:99999") != 0 || launcherAddrPort("[::1]:80") != 80 {
		t.Error("launcherAddrPort parsed a bad address or missed a good one")
	}
}
