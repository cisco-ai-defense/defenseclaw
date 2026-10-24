// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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
	oldContext, oldReport := standaloneLinuxHookContext, reportStandaloneHookRefusal
	standaloneLinuxHookContext = func() string { return "" }
	reportStandaloneHookRefusal = func(string, string, string) {}
	standaloneHookGOOS = goos
	standaloneRuntimeDescriptorLoad = load
	standaloneMachinePolicyOptions = policy
	standaloneSecureClientInstallDir = secureClientDir
	t.Cleanup(func() {
		standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyOptions, standaloneSecureClientInstallDir = oldGOOS, oldLoad, oldPolicy, oldSC
		standaloneLinuxHookContext, reportStandaloneHookRefusal = oldContext, oldReport
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
		PolicyViewDigests:       map[string]string{"codex": strings.Repeat("a", 64)},
	}
}

func noMarkers(string) (enterprisepolicy.Options, bool) { return enterprisepolicy.Options{}, false }

func TestForeignHookSessionPreparesUnixManagedTransport(t *testing.T) {
	// The transport refuses a socket directory that group or others can
	// write, so the mode must not come from the umask (t.TempDir is
	// group-writable under umask 0002). The short /tmp path keeps the socket
	// within the 104-byte macOS sun_path limit, which a t.TempDir path named
	// after this test exceeds.
	dir, err := os.MkdirTemp("/tmp", "dch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/foreign-hook-session/opencode" {
			t.Errorf("unexpected route %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"deny":false}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	descriptor := testDescriptor()
	descriptor.HookSocket = path
	descriptor.ServiceUID = os.Getuid()
	withStandaloneHookRuntime(t, "linux", func(string) (*managed.RuntimeDescriptor, error) {
		return descriptor, nil
	}, noMarkers, "/nonexistent-secure-client")
	standaloneHookRuntime.Lock()
	standaloneHookRuntime.prepared = false
	standaloneHookRuntime.Unlock()
	if before := buildHookOptionsForRuntime("opencode", "tool.execute.before", "", "closed", true); before.ManagedRuntimeFailure == "" {
		t.Fatal("test must start without prepared managed state")
	}
	decision, err := exchangeForeignHookSession("opencode", "tool.execute.before", time.Now(), time.Now().Add(5*time.Second), enterprisepolicy.SessionExchange{})
	if err != nil || decision.Deny {
		t.Fatalf("real hook socket exchange = %+v, error %v", decision, err)
	}
	opts := buildHookOptionsForRuntime("opencode", "tool.execute.before", "", "closed", true)
	if !opts.ManagedStandalone || opts.ManagedUnixSocket != path || opts.ManagedServiceUID != os.Getuid() || opts.ManagedRuntimeFailure != "" {
		t.Fatalf("foreign exchange did not bind verified socket: standalone=%v socket=%q uid=%d failure=%q",
			opts.ManagedStandalone, opts.ManagedUnixSocket, opts.ManagedServiceUID, opts.ManagedRuntimeFailure)
	}
}

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
	if prepareEnterpriseManagedHookRuntime("Codex") {
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
	if want := filepath.Join(accountDatabaseHomeForTest(t), ".defenseclaw"); opts.FailureLogHome == nil || opts.FailureLogHome() != want {
		t.Fatalf("failure log home does not resolve to the invoking user's %q", want)
	}
}

// Even a readable, valid descriptor cannot make a hook safe when the agent
// launched it from a private user namespace. An administrator's outage-only
// open setting must not turn that process-context refusal into an allow.
func TestStandaloneHookRefusesPrivateAgentContextWithValidDescriptor(t *testing.T) {
	descriptor := testDescriptor()
	descriptor.OpenHookConnectors = []string{"codex"}
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return descriptor, nil },
		noMarkers, "/nonexistent-secure-client")
	standaloneLinuxHookContext = func() string { return hookexec.ManagedUserNamespaceReason }
	reported := ""
	reportStandaloneHookRefusal = func(_, connectorName, reason string) { reported = connectorName + " " + reason }
	if prepareEnterpriseManagedHookRuntime("codex") {
		t.Fatal("a private-context hook became a no-op")
	}
	opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure != hookexec.ManagedUserNamespaceReason || !opts.ManagedStandalone ||
		opts.FailMode != "closed" || !opts.StrictAvailability || !enterpriseManagedHookRuntimeForceClosed() {
		t.Fatalf("valid descriptor hid the private context: failure=%q standalone=%v mode=%q strict=%v",
			opts.ManagedRuntimeFailure, opts.ManagedStandalone, opts.FailMode, opts.StrictAvailability)
	}
	if reported != "codex "+hookexec.ManagedUserNamespaceReason {
		t.Fatalf("private-context refusal was not reported: %q", reported)
	}
}

// Review loop round 1 (P1): a managed hook does no policy-view work on any
// call. Whatever the vendor policy on the host (the pinned view, a changed
// one, one far larger than any real policy, or a descriptor from before
// pins), preparing the runtime and building the call's options never reads
// machine policy (the policy-path seam is never consulted), never refuses,
// and keeps the descriptor's transport and fail mode, outage-open included.
// The hook's p99 stays at the cost of loading its descriptor. The gateway
// proves the view when it changes and raises the alert
// (gateway/managed_policy_view.go).
func TestStandaloneManagedHookDoesNoPolicyViewWork(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name                           string
			changed, large, prePin, opened bool
		}{
			{name: "pinned view"},
			{name: "changed view", changed: true},
			{name: "large view", large: true},
			{name: "descriptor from before pins", prePin: true},
			{name: "changed view with outage-open", changed: true, opened: true},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				policy := enterprisepolicy.Options{GOOS: goos, Root: t.TempDir(), SkipTrustChecks: true}
				managedDir, err := enterprisepolicy.ClaudeManagedDir(policy)
				if err != nil {
					t.Fatal(err)
				}
				dropIns := filepath.Join(managedDir, "managed-settings.d")
				if err := os.MkdirAll(dropIns, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dropIns, enterprisepolicy.DefenseClawDropInName), []byte(`{"hooks": {}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.large {
					for i := 0; i < 3; i++ {
						if err := os.WriteFile(filepath.Join(dropIns, fmt.Sprintf("%02d-large.json", i)), []byte(`{"x": "`+strings.Repeat("a", 3<<20)+`"}`), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				pin, err := enterprisepolicy.PolicyViewDigest(policy, enterprisepolicy.ConnectorClaudeCode)
				if err != nil {
					t.Fatal(err)
				}
				if tc.changed {
					pin = strings.Repeat("b", 64)
				}
				descriptor := testDescriptor()
				descriptor.MachinePolicyConnectors = []string{enterprisepolicy.ConnectorClaudeCode}
				descriptor.PolicyViewDigests = map[string]string{enterprisepolicy.ConnectorClaudeCode: pin}
				if tc.prePin {
					descriptor.PolicyViewDigests = nil
				}
				if tc.opened {
					descriptor.OpenHookConnectors = []string{enterprisepolicy.ConnectorClaudeCode}
				}
				lookups := 0
				withStandaloneHookRuntime(t, goos,
					func(string) (*managed.RuntimeDescriptor, error) { return descriptor, nil },
					func(string) (enterprisepolicy.Options, bool) { lookups++; return policy, true }, "/nonexistent-secure-client")
				const calls = 200
				durations := make([]time.Duration, 0, calls)
				for i := 0; i < calls; i++ {
					started := time.Now()
					prepareEnterpriseManagedHookRuntime(enterprisepolicy.ConnectorClaudeCode)
					opts := buildHookOptionsForRuntime(enterprisepolicy.ConnectorClaudeCode, "PreToolUse", "", "", true)
					durations = append(durations, time.Since(started))
					if opts.ManagedRuntimeFailure != "" || enterpriseManagedHookRuntimeForceClosed() {
						t.Fatalf("call %d was refused: failure %q", i, opts.ManagedRuntimeFailure)
					}
					if !opts.ManagedStandalone || opts.ManagedUnixSocket != descriptor.HookSocket || opts.ManagedServiceUID != descriptor.ServiceUID ||
						opts.FailMode != descriptor.HookFailMode(enterprisepolicy.ConnectorClaudeCode) {
						t.Fatalf("call %d did not keep the descriptor's transport and fail mode: %+v", i, opts)
					}
				}
				if lookups != 0 {
					t.Fatalf("the hook read machine policy %d times in %d calls; it must do no policy-view work", lookups, calls)
				}
				sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
				if p99 := durations[calls*99/100]; p99 > 25*time.Millisecond {
					t.Fatalf("hook p99 = %s over %d calls; policy-view work is on the call path", p99, calls)
				}
			})
		}
	}
}

// A hook with no trusted descriptor has no managed policy to enforce and
// stays closed.
func TestStandaloneHookWithoutDescriptorRefuses(t *testing.T) {
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		noMarkers, "/nonexistent-secure-client")
	prepareEnterpriseManagedHookRuntime("codex")
	opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure != standaloneRuntimeReasonDescriptorMissing || opts.FailMode != "closed" || opts.ManagedUnixSocket != "" {
		t.Fatalf("missing descriptor: failure %q mode %q socket %q", opts.ManagedRuntimeFailure, opts.FailMode, opts.ManagedUnixSocket)
	}
}

func TestLinuxManagedHookContextReason(t *testing.T) {
	for _, tc := range []struct {
		name, uidMap, selfUser, selfMount, status, want string
		hostLinksDenied                                 bool
	}{
		{name: "host login", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "Name:\thook\nTracerPid:\t0\n"},
		{name: "private user namespace", uidMap: "0 1000 1\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "TracerPid:\t0\n", want: hookexec.ManagedUserNamespaceReason},
		{name: "fully mapped child user namespace", uidMap: "0 0 4294967295\n", selfUser: "user:[9]", selfMount: "mnt:[2]", status: "TracerPid:\t0\n", want: hookexec.ManagedUserNamespaceReason},
		// pam_namespace logins and PrivateTmp services have a private
		// mount view: it is not refused (the gateway proves the policy).
		{name: "private mount view", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[3]", status: "TracerPid:\t0\n"},
		{name: "private mount view behind protected host links", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[3]", status: "TracerPid:\t0\n", hostLinksDenied: true},
		{name: "traced hook", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "TracerPid:\t42\n", want: hookexec.ManagedTracedProcessReason},
		{name: "unverifiable context", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "Name:\thook\n", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "unreadable own user namespace", uidMap: "0 0 4294967295\n", selfMount: "mnt:[2]", status: "TracerPid:\t0\n", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "protected host namespace links", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "TracerPid:\t0\n", hostLinksDenied: true},
		// Only the head of status is read: lines after TracerPid, such as
		// a long Groups line, never refuse a valid call.
		{name: "65,536 supplementary groups", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: linuxStatusWithGroups("0", 65536)},
		{name: "traced with 65,536 supplementary groups", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: linuxStatusWithGroups("42", 65536), want: hookexec.ManagedTracedProcessReason},
		// A TracerPid line cut by end of file or by the read bound (here
		// right after its 0) is never trusted, and neither is one past the
		// bound.
		{name: "cut TracerPid line", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "Name:\thook\nTracerPid:\t0", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "TracerPid cut by the bound", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "Name:\t" + strings.Repeat("x", linuxHookContextMaxBytes-len("Name:\t\nTracerPid:\t0")) + "\nTracerPid:\t0\n", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "TracerPid past the bound", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "Name:\t" + strings.Repeat("x", 2*linuxHookContextMaxBytes) + "\nTracerPid:\t0\n", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "oversized uid_map", uidMap: "0 0 4294967295\n" + strings.Repeat(" ", linuxHookContextMaxBytes), selfUser: "user:[1]", selfMount: "mnt:[2]", status: "TracerPid:\t0\n", want: hookexec.ManagedProcessContextUnknownReason},
		{name: "unparsable TracerPid", uidMap: "0 0 4294967295\n", selfUser: "user:[1]", selfMount: "mnt:[2]", status: "TracerPid:\tx\n", want: hookexec.ManagedProcessContextUnknownReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := map[string]string{
				"/proc/self/ns/user": tc.selfUser, "/proc/1/ns/user": "user:[1]",
				"/proc/self/ns/mnt": tc.selfMount, "/proc/1/ns/mnt": "mnt:[2]",
			}
			got := linuxManagedHookContextReason(func(path string) (string, error) {
				if tc.hostLinksDenied && strings.HasPrefix(path, "/proc/1/ns/") {
					return "", os.ErrPermission
				}
				if target := links[path]; target != "" {
					return target, nil
				}
				return "", os.ErrNotExist
			}, func(path string) (io.ReadCloser, error) {
				switch path {
				case "/proc/self/uid_map":
					return io.NopCloser(strings.NewReader(tc.uidMap)), nil
				case "/proc/self/status":
					return io.NopCloser(strings.NewReader(tc.status)), nil
				default:
					return nil, os.ErrNotExist
				}
			})
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

// linuxStatusWithGroups is a /proc/self/status in the kernel's line order
// (TracerPid before Groups) for an account with groups supplementary
// seven-digit group ids.
func linuxStatusWithGroups(tracerPid string, groups int) string {
	var b strings.Builder
	b.WriteString("Name:\thook\nUmask:\t0022\nState:\tR (running)\nTgid:\t4242\nNgid:\t0\nPid:\t4242\nPPid:\t4200\n")
	b.WriteString("TracerPid:\t" + tracerPid + "\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nFDSize:\t64\nGroups:\t")
	for i := 0; i < groups; i++ {
		fmt.Fprintf(&b, "%d ", 1000000+i)
	}
	b.WriteString("\nNStgid:\t4242\nNSpid:\t4242\nNSpgid:\t4242\nNSsid:\t4200\nKthread:\t0\n")
	for _, field := range []string{"VmPeak", "VmSize", "VmLck", "VmPin", "VmHWM", "VmRSS", "RssAnon", "RssFile", "RssShmem",
		"VmData", "VmStk", "VmExe", "VmLib", "VmPTE", "VmSwap", "HugetlbPages"} {
		b.WriteString(field + ":\t  123456 kB\n")
	}
	b.WriteString("CoreDumping:\t0\nTHP_enabled:\t1\nuntag_mask:\t0xffffffffffffffff\nThreads:\t1\nSigQ:\t0/63432\n" +
		"SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n" +
		"SigCgt:\t0000000000000000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
		"CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n" +
		"Speculation_Store_Bypass:\tthread vulnerable\nSpeculationIndirectBranch:\tconditional enabled\n" +
		"Cpus_allowed:\tffff\nCpus_allowed_list:\t0-15\nMems_allowed:\t00000000,00000001\nMems_allowed_list:\t0\n" +
		"voluntary_ctxt_switches:\t1\nnonvoluntary_ctxt_switches:\t0\n")
	return b.String()
}

// A host login whose account has about 2,000 supplementary groups has a
// /proc/self/status over the read bound. The hook reads, from the real
// files, only through TracerPid and takes the call.
func TestLinuxManagedHookContextReadsOnlyTheStatusHead(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"/proc/self/uid_map": "         0          0 4294967295\n",
		"/proc/self/status":  linuxStatusWithGroups("0", 2000),
	}
	if len(files["/proc/self/status"]) <= linuxHookContextMaxBytes {
		t.Fatalf("fixture status is %d bytes; it must exceed the %d-byte bound", len(files["/proc/self/status"]), linuxHookContextMaxBytes)
	}
	paths := map[string]string{}
	for name, body := range files {
		path := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	open := func(path string) (io.ReadCloser, error) {
		if paths[path] == "" {
			return nil, os.ErrNotExist
		}
		return openLinuxHookContextFile(paths[path])
	}
	readlink := func(string) (string, error) { return "user:[1]", nil }
	if got := linuxManagedHookContextReason(readlink, open); got != "" {
		t.Fatalf("host login with 2,000 groups: reason = %q, want none", got)
	}
	if err := os.WriteFile(paths["/proc/self/status"], []byte(linuxStatusWithGroups("42", 2000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := linuxManagedHookContextReason(readlink, open); got != hookexec.ManagedTracedProcessReason {
		t.Fatalf("traced hook with 2,000 groups: reason = %q, want %q", got, hookexec.ManagedTracedProcessReason)
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
			standaloneLinuxHookContext = func() string {
				if tc.userns {
					return hookexec.ManagedUserNamespaceReason
				}
				return ""
			}
			reportStandaloneHookRefusal = func(_, connectorName, reason string) { reported = connectorName + " " + reason }
			if prepareEnterpriseManagedHookRuntime("claudecode") {
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
	if prepareEnterpriseManagedHookRuntime("claudecode") {
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

// A first-install rollback or uninstall can remove the descriptor and policy
// while an already-running agent still holds the hook command. Both states
// must produce the same native decisions; the policy-free case failed open
// through the former no-op branch.
func TestStandaloneMissingDescriptorDeniesToolCallsWithOrWithoutMachinePolicy(t *testing.T) {
	dir := t.TempDir()
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		rootedMachinePolicy(dir), filepath.Join(dir, "no-secure-client"))
	opts, _ := rootedMachinePolicy(dir)("linux")
	connectors := []string{"claudecode", "codex", "copilot", "cursor", "opencode"}
	if _, err := enterprisepolicy.Publish(opts, connectors); err != nil {
		t.Fatal(err)
	}
	for _, policyPresent := range []bool{true, false} {
		if !policyPresent {
			if _, err := enterprisepolicy.RemoveAll(opts); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range []struct {
			connector, toolEvent, stopEvent, toolDeny string
			toolCode                                  int
		}{
			{"claudecode", "PreToolUse", "Stop", `"permissionDecision":"deny"`, 0},
			{"codex", "PreToolUse", "Stop", `"permissionDecision":"deny"`, 0},
			{"copilot", "preToolUse", "agentStop", `"permissionDecision":"deny"`, 0},
			{"cursor", "beforeShellExecution", "stop", `"permission":"deny"`, 2},
			{"devin", "PreToolUse", "Stop", "DefenseClaw blocked this tool call", 2},
			{"kiro", "PreToolUse", "Stop", "", 2},
			{"opencode", "tool.execute.before", "session.idle", `"decision":"deny"`, 2},
		} {
			if prepareEnterpriseManagedHookRuntime(tc.connector) {
				t.Fatalf("%s: missing descriptor became a no-op with policy=%v", tc.connector, policyPresent)
			}
			if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonDescriptorMissing {
				t.Fatalf("%s: reason = %q with policy=%v", tc.connector, reason, policyPresent)
			}
			if !enterpriseManagedHookRuntimeForceClosed() {
				t.Fatalf("%s: missing descriptor must force closed with policy=%v", tc.connector, policyPresent)
			}
			for _, event := range []string{tc.toolEvent, tc.stopEvent} {
				var stdout, stderr bytes.Buffer
				boundEvent := event
				if tc.connector == "claudecode" {
					boundEvent = ""
				}
				hookOpts := buildHookOptionsForRuntime(tc.connector, boundEvent, "", "", true)
				if hookOpts.ManagedRuntimeFailure != standaloneRuntimeReasonDescriptorMissing || !hookOpts.ManagedStandalone || hookOpts.ManagedUnixSocket != "" {
					t.Fatalf("%s %s: fail-closed options wrong: %+v", tc.connector, event, hookOpts)
				}
				hookOpts.Home = t.TempDir()
				hookOpts.Stdin = strings.NewReader(`{"hook_event_name":"` + event + `"}`)
				hookOpts.Stdout, hookOpts.Stderr = &stdout, &stderr
				code := hookexec.Run(context.Background(), hookOpts)
				if event == tc.toolEvent {
					if code != tc.toolCode || (tc.toolDeny != "" && !strings.Contains(stdout.String(), tc.toolDeny)) ||
						(tc.connector == "devin" && json.Valid(bytes.TrimSpace(stdout.Bytes()))) ||
						(tc.connector == "kiro" && (stdout.Len() != 0 || !strings.Contains(stderr.String(), "DefenseClaw blocked"))) {
						t.Fatalf("%s %s with policy=%v: want native deny, got code=%d stdout=%q stderr=%q", tc.connector, event, policyPresent, code, stdout.String(), stderr.String())
					}
				} else if code != 0 || strings.Contains(stdout.String(), "deny") || strings.Contains(stdout.String(), "block") {
					t.Fatalf("%s %s with policy=%v: want neutral allow, got code=%d stdout=%q stderr=%q", tc.connector, event, policyPresent, code, stdout.String(), stderr.String())
				} else if tc.connector != "copilot" && !strings.Contains(stderr.String(), "DefenseClaw is not blocking the ") {
					t.Fatalf("%s %s with policy=%v: stop did not use standalone neutral allow: %q", tc.connector, event, policyPresent, stderr.String())
				}
			}
		}
	}
}
