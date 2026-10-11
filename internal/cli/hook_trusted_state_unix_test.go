// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withStandaloneHookRuntime(
	t *testing.T,
	goos string,
	load func(string) (*managed.RuntimeDescriptor, error),
	policy func(string) (enterprisepolicy.Options, bool),
	secureClientDir string,
) {
	t.Helper()
	oldGOOS, oldLoad, oldPolicy, oldSC := standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyOptions, standaloneSecureClientInstallDir
	oldUserNamespace, oldReport := standaloneHookInUserNamespace, reportStandaloneHookRefusal
	standaloneHookInUserNamespace = func() bool { return false }
	reportStandaloneHookRefusal = func(string, string, string) {}
	standaloneHookGOOS = goos
	standaloneRuntimeDescriptorLoad = load
	standaloneMachinePolicyOptions = policy
	standaloneSecureClientInstallDir = secureClientDir
	t.Cleanup(func() {
		standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyOptions, standaloneSecureClientInstallDir = oldGOOS, oldLoad, oldPolicy, oldSC
		standaloneHookInUserNamespace, reportStandaloneHookRefusal = oldUserNamespace, oldReport
		standaloneHookRuntime.Lock()
		standaloneHookRuntime.prepared = false
		standaloneHookRuntime.descriptor = nil
		standaloneHookRuntime.reason = ""
		standaloneHookRuntime.secureClientHost = false
		standaloneHookRuntime.Unlock()
	})
}

func testDescriptor() *managed.RuntimeDescriptor {
	return &managed.RuntimeDescriptor{
		SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
		Profile:                 managed.ProfileStandalone,
		ServiceUser:             "defenseclaw",
		ServiceUID:              995,
		ServiceGID:              985,
		APIAddr:                 managed.StandaloneAPIAddr,
		HookSocket:              "/run/defenseclaw-hook/hook.sock",
		MachinePolicyConnectors: []string{"codex"},
	}
}

func noMarkers(string) (enterprisepolicy.Options, bool) { return enterprisepolicy.Options{}, false }

// rootedMachinePolicy resolves the real standalone machine policy paths
// under root, as the publisher writes them.
func rootedMachinePolicy(root string) func(string) (enterprisepolicy.Options, bool) {
	return func(goos string) (enterprisepolicy.Options, bool) {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			return enterprisepolicy.Options{}, false
		}
		opts := enterprisepolicy.LayoutOptions(layout, "", "")
		opts.Root = root
		opts.StateDir = filepath.Join(root, opts.StateDir)
		opts.PublicPolicyPath = filepath.Join(root, opts.PublicPolicyPath)
		opts.SkipTrustChecks = true
		return opts, true
	}
}

func TestStandaloneHookRuntimeUsesDescriptor(t *testing.T) {
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return testDescriptor(), nil },
		noMarkers, "/nonexistent-secure-client")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "10.0.0.1:1")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "inherited")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "99999999")
	if enterpriseManagedHookRuntimeNoop("Codex") {
		t.Fatal("a present descriptor is never a no-op")
	}
	opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure != "" {
		t.Fatalf("unexpected runtime failure %q", opts.ManagedRuntimeFailure)
	}
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || opts.ManagedUnixSocket != "/run/defenseclaw-hook/hook.sock" || opts.ManagedServiceUID != 995 {
		t.Fatalf("standalone transport not bound to descriptor: %+v", opts)
	}
	if opts.APIAddr != managed.StandaloneAPIAddr {
		t.Fatalf("api addr = %q; environment must not redirect a managed hook", opts.APIAddr)
	}
	if opts.Token != "" || opts.FailMode != "closed" || !opts.StrictAvailability || opts.MaxBody != 1<<20 {
		t.Fatalf("inherited environment weakened the managed hook: token=%q fail=%q strict=%v max=%d",
			opts.Token, opts.FailMode, opts.StrictAvailability, opts.MaxBody)
	}
	layout, _ := managed.StandaloneLayoutFor("linux")
	if opts.Home != layout.ConfigDir {
		t.Fatalf("home = %q, want the administrator-owned %q", opts.Home, layout.ConfigDir)
	}
}

func TestStandaloneHookRuntimeNoopOnlyAfterUninstall(t *testing.T) {
	dir := t.TempDir()
	markers := rootedMachinePolicy(dir)
	policyOpts, _ := markers("linux")
	claudeDir, _ := enterprisepolicy.ClaudeManagedDir(policyOpts)
	policy := filepath.Join(claudeDir, "managed-settings.d", enterprisepolicy.DefenseClawDropInName)
	if err := os.MkdirAll(filepath.Dir(policy), 0o755); err != nil {
		t.Fatal(err)
	}
	requirements, _ := enterprisepolicy.CodexRequirementsPath(policyOpts)
	if err := os.MkdirAll(filepath.Dir(requirements), 0o755); err != nil {
		t.Fatal(err)
	}
	missing := func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor }
	withStandaloneHookRuntime(t, "linux", missing, markers, filepath.Join(dir, "no-secure-client"))

	if !enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("descriptor and machine policy both absent must be a no-op")
	}
	if err := os.WriteFile(policy, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("machine policy without a descriptor must fail closed")
	}
	if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonDescriptorMissing {
		t.Fatalf("reason = %q", reason)
	}
	if !enterpriseManagedHookRuntimeForceClosed() {
		t.Fatal("missing descriptor with policy must force the hook closed")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "", true)
	// No transport; the failure is marked as the standalone profile's.
	if opts.ManagedRuntimeFailure != standaloneRuntimeReasonDescriptorMissing || !opts.ManagedStandalone || opts.ManagedUnixSocket != "" {
		t.Fatalf("fail-closed options wrong: %+v", opts)
	}

	if err := os.WriteFile(requirements, []byte("[hooks]\n# other admin hook\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("an admin requirements file without the DefenseClaw hook is not DefenseClaw policy")
	}
	if err := os.WriteFile(requirements, []byte("command = \"/opt/defenseclaw/bin/defenseclaw-hook hook --connector codex\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("requirements that still name defenseclaw-hook must fail closed")
	}
}

// A standalone runtime that fails its checks (an untrusted descriptor, or one
// that names no hook socket, since the standalone hook has no loopback TCP
// fallback and never reads a token) fails closed. Its options select no
// transport but stay marked as the standalone profile's, whose stop events
// are not blocked, and only for the connector the runtime was prepared for.
func TestStandaloneHookRuntimeFailsClosed(t *testing.T) {
	untrusted := func(string) (*managed.RuntimeDescriptor, error) {
		return nil, errors.New("owner uid 1000 is not trusted")
	}
	noSocket := func(string) (*managed.RuntimeDescriptor, error) {
		descriptor := testDescriptor()
		descriptor.HookSocket = ""
		return descriptor, nil
	}
	for _, tc := range []struct {
		name, goos  string
		load        func(string) (*managed.RuntimeDescriptor, error)
		reason      string
		forceClosed bool
		userns      bool
	}{
		{"untrusted descriptor", "linux", untrusted, standaloneRuntimeReasonInvalid, false, false},
		// Inside a user namespace the root-owned descriptor reads as owned
		// by the overflow uid; the hook says why it refuses and reports it
		// to the gateway (GAP-0923).
		{"user namespace", "linux", untrusted, hookexec.ManagedUserNamespaceReason, false, true},
		{"no hook socket on linux", "linux", noSocket, standaloneRuntimeReasonHookSocketMissing, true, false},
		{"no hook socket on darwin", "darwin", noSocket, standaloneRuntimeReasonHookSocketMissing, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStandaloneHookRuntime(t, tc.goos, tc.load, noMarkers, "/nonexistent-secure-client")
			reported := ""
			standaloneHookInUserNamespace = func() bool { return tc.userns }
			reportStandaloneHookRefusal = func(_, connectorName, reason string) { reported = connectorName + " " + reason }
			if enterpriseManagedHookRuntimeNoop("claudecode") {
				t.Fatal("a failed standalone runtime is never a no-op")
			}
			if reason := enterpriseManagedHookRuntimeFailureReason(); reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			if tc.forceClosed && !enterpriseManagedHookRuntimeForceClosed() {
				t.Fatal("a descriptor without a hook socket must force the hook closed")
			}
			if _, _, _, ok := enterpriseManagedHookRuntimeConnection("claudecode"); ok {
				t.Fatal("a failed standalone runtime must not yield an endpoint")
			}
			opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "", true)
			if opts.ManagedRuntimeFailure != tc.reason || !opts.ManagedStandalone || opts.ManagedUnixSocket != "" ||
				opts.FailMode != "closed" || !opts.StrictAvailability {
				t.Fatalf("options: failure=%q standalone=%v socket=%q fail=%q strict=%v",
					opts.ManagedRuntimeFailure, opts.ManagedStandalone, opts.ManagedUnixSocket, opts.FailMode, opts.StrictAvailability)
			}
			if other := buildHookOptionsForRuntime("codex", "Stop", "", "", true); other.ManagedStandalone {
				t.Fatal("the runtime prepared for claudecode must not mark a codex invocation")
			}
			if want := map[bool]string{true: "claudecode " + hookexec.ManagedUserNamespaceReason}[tc.userns]; reported != want {
				t.Fatalf("refusal reported to the gateway = %q, want %q", reported, want)
			}
		})
	}
}

func TestStandaloneHookRuntimeKeepsSecureClientMacFailClosed(t *testing.T) {
	secureClient := t.TempDir()
	withStandaloneHookRuntime(t, "darwin",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		noMarkers, secureClient)
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("a Secure Client Mac keeps the historical fail-closed --enterprise-managed result")
	}
	if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonInvalid {
		t.Fatalf("reason = %q", reason)
	}
	// Its failures keep their results: never marked as the standalone
	// profile's.
	opts := buildHookOptionsForRuntime("claudecode", "", "", "", true)
	if opts.ManagedRuntimeFailure != standaloneRuntimeReasonInvalid || opts.ManagedStandalone {
		t.Fatalf("Secure Client options: failure=%q standalone=%v", opts.ManagedRuntimeFailure, opts.ManagedStandalone)
	}
}

func TestStandaloneMachinePolicyPresenceUsesPublisherDetection(t *testing.T) {
	dir := t.TempDir()
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		rootedMachinePolicy(dir), filepath.Join(dir, "no-secure-client"))
	opts, _ := rootedMachinePolicy(dir)("linux")
	connectors := []string{"claudecode", "codex", "copilot", "cursor"}
	if _, err := enterprisepolicy.Publish(opts, connectors); err != nil {
		t.Fatal(err)
	}
	for _, connector := range connectors {
		if enterpriseManagedHookRuntimeNoop(connector) {
			t.Fatalf("%s: published machine policy without a descriptor must fail closed", connector)
		}
	}
	if _, err := enterprisepolicy.RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	for _, connector := range connectors {
		if !enterpriseManagedHookRuntimeNoop(connector) {
			t.Fatalf("%s: a clean uninstall must be a no-op (reason %q)", connector, enterpriseManagedHookRuntimeFailureReason())
		}
	}
}
