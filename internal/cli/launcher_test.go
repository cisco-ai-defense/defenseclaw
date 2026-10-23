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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

func TestLauncherInvoked(t *testing.T) {
	for _, test := range []struct {
		goos, argv0 string
		want        bool
	}{
		{"linux", "defenseclaw", true},
		{"linux", "/usr/bin/defenseclaw", true},
		{"darwin", "/usr/local/bin/defenseclaw", true},
		{"linux", "./defenseclaw", true},
		{"linux", "/opt/defenseclaw/bin/defenseclaw-gateway", false},
		{"linux", "defenseclaw-gateway", false},
		{"linux", "DefenseClaw", false},
		{"linux", "", false},
		// Windows ships defenseclaw.exe as the administrator command.
		{"windows", `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe`, false},
		{"windows", "defenseclaw", false},
	} {
		if got := launcherInvoked(test.goos, test.argv0); got != test.want {
			t.Errorf("launcherInvoked(%q, %q) = %v, want %v", test.goos, test.argv0, got, test.want)
		}
	}
}

// withManagedRecord points the managed-host checks at a descriptor file whose
// trust the test decides, and names the process argv0.
func withManagedRecord(t *testing.T, argv0 string, present bool, trust error) {
	t.Helper()
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if present {
		if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restorePath, restoreTrust, restoreArgv0 := managedHostDescriptorPath, managedHostRecordTrusted, launcherArgv0
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return trust }
	launcherArgv0 = func() string { return argv0 }
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostRecordTrusted, launcherArgv0 = restorePath, restoreTrust, restoreArgv0
	})
}

func TestLauncherNeedsTheDefenseclawNameAndATrustedManagedRecord(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the launcher is a Linux and macOS command")
	}
	for _, test := range []struct {
		name    string
		argv0   string
		present bool
		trust   error
		want    bool
	}{
		{"managed host, launcher name", "/usr/bin/defenseclaw", true, nil, true},
		{"managed host, gateway name", "/opt/defenseclaw/bin/defenseclaw-gateway", true, nil, false},
		{"no managed record", "/usr/bin/defenseclaw", false, nil, false},
		{"record a user could have planted", "/usr/bin/defenseclaw", true, errors.New("owner is a standard user"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			withManagedRecord(t, test.argv0, test.present, test.trust)
			if got := launcherActive(); got != test.want {
				t.Fatalf("launcherActive() = %v, want %v", got, test.want)
			}
		})
	}
}

// launcherTestRoot is a stand-in for the gateway's command tree.
func launcherTestRoot(ran *[]string) *cobra.Command {
	root := &cobra.Command{
		Use:          "defenseclaw-gateway",
		SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			*ran = append(*ran, "sidecar")
			return nil
		},
		PersistentPreRunE: func(*cobra.Command, []string) error {
			*ran = append(*ran, "gateway-bootstrap")
			return nil
		},
	}
	for _, name := range []string{"status", "setup", "start", "enterprise"} {
		name := name
		root.AddCommand(&cobra.Command{Use: name, RunE: func(*cobra.Command, []string) error {
			*ran = append(*ran, name)
			return nil
		}})
	}
	sandbox := &cobra.Command{Use: "sandbox", Short: "sandboxes"}
	sandbox.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error {
		*ran = append(*ran, "sandbox list")
		return nil
	}})
	root.AddCommand(sandbox)
	return root
}

func TestLauncherRefusesEveryCommandThatIsNotSandbox(t *testing.T) {
	for _, args := range [][]string{
		{"status"}, {"setup", "gateway"}, {"enterprise", "linux", "status"}, {"start"},
		{"sandboxes"}, {"--bogus"}, {"-v"}, {"--version-json"}, {"unknown-command"},
	} {
		var ran []string
		root := launcherTestRoot(&ran)
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		if code := executeLauncher(context.Background(), root, args); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if got := strings.TrimSpace(stderr.String()); got != launcherRefusal {
			t.Errorf("%v: stderr %q, want %q", args, got, launcherRefusal)
		}
		if len(ran) != 0 || stdout.Len() != 0 {
			t.Errorf("%v: ran %v and printed %q before refusing", args, ran, stdout.String())
		}
	}
	const want = "This computer is managed; only `defenseclaw sandbox` commands are available here."
	if launcherRefusal != want {
		t.Fatalf("refusal text = %q, want %q", launcherRefusal, want)
	}
}

func TestLauncherHelpShowsOnlySandbox(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"help"}} {
		var ran []string
		root := launcherTestRoot(&ran)
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		if code := executeLauncher(context.Background(), root, args); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "defenseclaw sandbox run claude") || !strings.Contains(out, "sandbox") {
			t.Errorf("%v: help does not offer the sandbox tree:\n%s", args, out)
		}
		for _, hidden := range []string{"status", "setup", "enterprise", "completion", "sidecar"} {
			if strings.Contains(out, hidden) {
				t.Errorf("%v: help mentions %q:\n%s", args, hidden, out)
			}
		}
		if len(ran) != 0 {
			t.Errorf("%v: ran %v", args, ran)
		}
	}
}

func TestPrepareLauncherRootKeepsOnlyTheSandboxTree(t *testing.T) {
	var ran []string
	root := launcherTestRoot(&ran)
	prepareLauncherRoot(root)
	var names []string
	for _, command := range root.Commands() {
		names = append(names, command.Name())
	}
	if !reflect.DeepEqual(names, []string{"sandbox"}) {
		t.Fatalf("commands = %v, want [sandbox]", names)
	}
	if root.Use != "defenseclaw" {
		t.Fatalf("Use = %q", root.Use)
	}
	sandbox, _, err := root.Find([]string{"sandbox", "list"})
	if err != nil || sandbox.Name() != "list" {
		t.Fatalf("sandbox list not kept: %v", err)
	}
}

// launcherDaemonStub serves the status of a sandbox daemon on a managed host.
func launcherDaemonStub(t *testing.T, status string) *sandboxapi.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(status))
	}))
	t.Cleanup(server.Close)
	return sandboxapi.NewClient(server.URL, "")
}

func TestLauncherRunsSandboxCommandsWithoutTheGatewayBootstrap(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the launcher is a Linux and macOS command")
	}
	client := launcherDaemonStub(t, `{"enabled":true,"available":true}`)
	restoreClient, restoreApp, restoreRun, restoreCfg := launcherManagedClient, newSandboxApp, launcherRun, cfg
	launcherManagedClient = func(string) (*sandboxapi.Client, error) { return client, nil }
	launcherRun = func(context.Context, string, ...string) (string, error) {
		t.Error("a running daemon was restarted")
		return "", nil
	}
	t.Cleanup(func() {
		launcherManagedClient, newSandboxApp, launcherRun, launcherClient, cfg = restoreClient, restoreApp, restoreRun, nil, restoreCfg
	})

	var ran []string
	root := launcherTestRoot(&ran)
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	if code := executeLauncher(context.Background(), root, []string{"sandbox", "list"}); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if !reflect.DeepEqual(ran, []string{"sandbox list"}) {
		t.Fatalf("ran %v, want only the sandbox command (no gateway bootstrap, no sidecar)", ran)
	}
	// The sandbox commands talk to the caller's own daemon.
	if app := newSandboxApp(root); app.API != sandboxcli.API(client) {
		t.Fatalf("sandbox app API = %v, want the managed daemon client", app.API)
	}
}

func TestLauncherSandboxPreRunRefusesAnUntrustedDaemonSocket(t *testing.T) {
	restoreClient, restoreCfg := launcherManagedClient, cfg
	launcherManagedClient = func(string) (*sandboxapi.Client, error) {
		return nil, errors.New("the managed runtime descriptor is not trusted")
	}
	t.Cleanup(func() { launcherManagedClient, cfg = restoreClient, restoreCfg })
	command := &cobra.Command{Use: "list"}
	err := launcherSandboxPreRun(command, nil)
	want := "not trusted"
	if runtime.GOOS == "windows" {
		// Sandboxes don't run on Windows; that refusal comes first.
		want = "Linux and macOS only"
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("pre-run = %v, want the descriptor refusal (never a per-user fallback)", err)
	}
}

// scriptedStatus answers launcherEnsureDaemon's status requests in turn.
type scriptedStatus struct {
	answers []*sandboxapi.Status // nil = unreachable
	calls   int
}

func (s *scriptedStatus) Status(context.Context) (*sandboxapi.Status, error) {
	i := s.calls
	if i >= len(s.answers) {
		i = len(s.answers) - 1
	}
	s.calls++
	if s.answers[i] == nil {
		return nil, errors.New("dial unix: connect: no such file or directory")
	}
	return s.answers[i], nil
}

// recordRuns replaces launcherRun with a recorder; fail names the commands
// that fail (matched by their joined argument text).
func recordRuns(t *testing.T, fail map[string]string) *[]string {
	t.Helper()
	var calls []string
	restore := launcherRun
	launcherRun = func(_ context.Context, name string, args ...string) (string, error) {
		line := strings.TrimSpace(name + " " + strings.Join(args, " "))
		calls = append(calls, line)
		for needle, out := range fail {
			if strings.Contains(line, needle) {
				return out, errors.New("exit status 1")
			}
		}
		return "", nil
	}
	t.Cleanup(func() { launcherRun = restore })
	return &calls
}

func fastLauncherWaits(t *testing.T) {
	t.Helper()
	probe, start, poll := launcherProbeTimeout, launcherStartWait, launcherPollEvery
	launcherProbeTimeout, launcherStartWait, launcherPollEvery = time.Second, 300*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { launcherProbeTimeout, launcherStartWait, launcherPollEvery = probe, start, poll })
}

func TestLauncherEnsureDaemon(t *testing.T) {
	fastLauncherWaits(t)
	up := &sandboxapi.Status{Enabled: true, Available: true}
	pending := func(running int) *sandboxapi.Status {
		return &sandboxapi.Status{Running: running, Managed: &sandboxapi.ManagedStatus{PendingRestart: true}}
	}
	// pendingLive: no sandbox is ready, but live may still hold compute (a
	// MicroVM in OpenShell's error state); a daemon before 1.0.4 reports
	// no live count, only how many sandboxes it has.
	pendingLive := func(live *int, sandboxes int) *sandboxapi.Status {
		return &sandboxapi.Status{Sandboxes: sandboxes, Live: live, Managed: &sandboxapi.ManagedStatus{PendingRestart: true}}
	}
	one := 1
	for _, test := range []struct {
		name    string
		goos    string
		answers []*sandboxapi.Status
		fail    map[string]string
		calls   []string
		errText string
		stderr  string
	}{
		{name: "a running daemon is left alone", goos: "linux", answers: []*sandboxapi.Status{up}},
		{
			name: "linux starts the socket unit of a stopped daemon", goos: "linux",
			answers: []*sandboxapi.Status{nil, up},
			calls:   []string{"/usr/bin/systemctl --user start defenseclaw-sandbox.socket"},
		},
		{
			name: "linux reports a user manager that is not there", goos: "linux",
			answers: []*sandboxapi.Status{nil},
			fail:    map[string]string{"--user start": "Failed to connect to bus: No medium found\nmore"},
			calls:   []string{"/usr/bin/systemctl --user start defenseclaw-sandbox.socket"},
			errText: "could not be started: /usr/bin/systemctl --user start defenseclaw-sandbox.socket: Failed to connect to bus: No medium found",
		},
		{
			name: "a started daemon that never answers is reported", goos: "linux",
			answers: []*sandboxapi.Status{nil},
			calls:   []string{"/usr/bin/systemctl --user start defenseclaw-sandbox.socket"},
			errText: "was started but does not answer",
		},
		{
			name: "linux restarts an idle daemon that waits for a restart", goos: "linux",
			answers: []*sandboxapi.Status{pending(0), up},
			calls:   []string{"/usr/bin/systemctl --user restart defenseclaw-sandbox.service"},
			stderr:  "restarting your sandbox service",
		},
		{
			name: "a daemon whose sandboxes run keeps its restart pending", goos: "linux",
			answers: []*sandboxapi.Status{pending(2)},
		},
		{
			// The restart takes the account's OpenShell gateway with it.
			name: "a daemon with a sandbox that may still hold compute keeps its restart pending", goos: "linux",
			answers: []*sandboxapi.Status{pendingLive(&one, 1)},
		},
		{
			name: "a daemon before the live count keeps its restart pending while it has sandboxes", goos: "linux",
			answers: []*sandboxapi.Status{pendingLive(nil, 2)},
		},
		{
			name: "macos registers and starts the agent in the graphical session", goos: "darwin",
			answers: []*sandboxapi.Status{nil, up},
			fail:    map[string]string{"print gui/501/com.cisco.defenseclaw.sandbox": "Could not find service"},
			calls: []string{
				"/bin/launchctl print gui/501",
				"/bin/launchctl print user/501",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.sandbox",
				"/bin/launchctl bootstrap gui/501 /Library/LaunchAgents/com.cisco.defenseclaw.sandbox.plist",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.openshell-gateway",
				"/bin/launchctl kickstart gui/501/com.cisco.defenseclaw.sandbox",
			},
		},
		{
			name: "macos falls back to the background session of an ssh login", goos: "darwin",
			answers: []*sandboxapi.Status{nil, up},
			fail: map[string]string{
				"print gui/501":      "Domain does not support specified action",
				"print user/501/com": "Could not find service",
			},
			calls: []string{
				"/bin/launchctl print gui/501",
				"/bin/launchctl print user/501",
				"/bin/launchctl print user/501/com.cisco.defenseclaw.sandbox",
				"/bin/launchctl bootstrap user/501 /Library/LaunchAgents/com.cisco.defenseclaw.sandbox.plist",
				"/bin/launchctl print user/501/com.cisco.defenseclaw.openshell-gateway",
				"/bin/launchctl kickstart user/501/com.cisco.defenseclaw.sandbox",
			},
		},
		{
			name: "macos does not register an agent that is loaded", goos: "darwin",
			answers: []*sandboxapi.Status{nil, up},
			calls: []string{
				"/bin/launchctl print gui/501",
				"/bin/launchctl print user/501",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.sandbox",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.openshell-gateway",
				"/bin/launchctl kickstart gui/501/com.cisco.defenseclaw.sandbox",
			},
		},
		{
			name: "macos restarts an idle daemon with kickstart -k", goos: "darwin",
			answers: []*sandboxapi.Status{pending(0), up},
			calls: []string{
				"/bin/launchctl print gui/501",
				"/bin/launchctl print user/501",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.sandbox",
				"/bin/launchctl print gui/501/com.cisco.defenseclaw.openshell-gateway",
				"/bin/launchctl kickstart -k gui/501/com.cisco.defenseclaw.sandbox",
			},
			stderr: "restarting your sandbox service",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := recordRuns(t, test.fail)
			var stderr bytes.Buffer
			_, err := launcherEnsureDaemon(context.Background(), &scriptedStatus{answers: test.answers}, test.goos, 501, &stderr)
			switch {
			case test.errText == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.errText != "" && (err == nil || !strings.Contains(err.Error(), test.errText)):
				t.Fatalf("error = %v, want it to contain %q", err, test.errText)
			}
			if !reflect.DeepEqual(*calls, test.calls) && (len(*calls) != 0 || len(test.calls) != 0) {
				t.Fatalf("service-manager calls:\n got %q\nwant %q", *calls, test.calls)
			}
			if !strings.Contains(stderr.String(), test.stderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), test.stderr)
			}
		})
	}
}

func TestLauncherServiceEnvGivesSystemctlTheRuntimeDirectory(t *testing.T) {
	env := launcherServiceEnv([]string{"A=1", "XDG_RUNTIME_DIR=/run/user/7"}, 501)
	if !reflect.DeepEqual(env, []string{"A=1", "XDG_RUNTIME_DIR=/run/user/7"}) {
		t.Fatalf("an exported runtime dir was changed: %v", env)
	}
	// /run/user/<uid> exists only for a signed-in account, so a uid without
	// one adds nothing.
	if env := launcherServiceEnv([]string{"A=1"}, 4000000); len(env) != 1 {
		t.Fatalf("env = %v, want it unchanged for an account without a runtime dir", env)
	}
}

func TestLauncherReportsOnlyNamedManagedRefusals(t *testing.T) {
	previous := reportManagedCommandRefusal
	var reported []string
	reportManagedCommandRefusal = func(command, reason string) {
		reported = append(reported, command+":"+reason)
	}
	t.Cleanup(func() { reportManagedCommandRefusal = previous })
	for _, args := range [][]string{
		{"guardrail", "disable"}, {"uninstall", "--all"},
		{"guardrail", "status"}, {"config", "set", "token=untrusted"},
	} {
		root := &cobra.Command{Use: "defenseclaw"}
		root.SetErr(&bytes.Buffer{})
		if code := executeLauncher(context.Background(), root, args); code != 2 {
			t.Fatalf("%v: exit %d, want refusal", args, code)
		}
	}
	if got, want := strings.Join(reported, ","), "guardrail disable:,uninstall:"; got != want {
		t.Fatalf("reported %q, want %q", got, want)
	}
}
