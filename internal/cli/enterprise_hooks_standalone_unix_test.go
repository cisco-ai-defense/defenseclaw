//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const enterpriseHookWorkerHelperEnv = "DEFENSECLAW_TEST_APPLY_TARGET_HELPER"

// TestEnterpriseHookWorkerHelperProcess is the apply-target worker body for
// the protocol tests. It does nothing when run as an ordinary test.
func TestEnterpriseHookWorkerHelperProcess(t *testing.T) {
	mode := os.Getenv(enterpriseHookWorkerHelperEnv)
	if mode == "" {
		return
	}
	if mode == "real" {
		// Root-only sentinel test: run the real installer and verifier.
		os.Exit(enterpriseHookWorkerMain(context.Background(), os.Stdin, os.Stdout, os.Stderr))
	}
	switch mode {
	case "garbage":
		fmt.Fprint(os.Stdout, "not json")
		os.Exit(0)
	case "oversize":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), enterpriseHookWorkerResponseLimit+1))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	result := func(opts enterprisehooks.InstallOptions) enterprisehooks.InstallResult {
		// Report what the worker saw so the parent can assert on its
		// identity and environment.
		return enterprisehooks.InstallResult{
			Connector:      opts.ConnectorName,
			UserHome:       opts.UserHome,
			AgentVersion:   os.Getenv("HOME"),
			DataDir:        os.Getenv("DEFENSECLAW_TEST_LEAK"),
			HookContractID: os.Getenv(enterprisehooks.TrustedBinPrefixesEnv),
		}
	}
	enterpriseHookWorkerInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if mode == "fail" {
			return enterprisehooks.InstallResult{}, errors.New("install refused")
		}
		return result(opts), nil
	}
	enterpriseHookWorkerVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if mode == "drift" || mode == "fail" {
			return enterprisehooks.InstallResult{}, errors.New("hook config drifted")
		}
		return result(opts), nil
	}
	enterpriseHookWorkerDiscoverVersion = func(_ context.Context, home, connector string, allowExec bool) (string, string) {
		if connector == "codex" && allowExec {
			return "0.142.0", ""
		}
		return "", "not installed"
	}
	enterpriseHookWorkerDiscoverStaticVersion = func(_ context.Context, home, connector string) (string, string) {
		if connector == "codex" {
			return "", enterprisehooks.UnixAgentUnversionedReasonPrefix + filepath.Join(home, ".local", "bin", "codex")
		}
		return "", "not installed"
	}
	os.Exit(enterpriseHookWorkerMain(context.Background(), os.Stdin, os.Stdout, os.Stderr))
}

func useEnterpriseHookWorkerHelper(t *testing.T, mode string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the helper worker runs as the invoking user; root cannot be a target")
	}
	origExe, origArgs, origEnv, origLog := enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog
	t.Cleanup(func() {
		enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog = origExe, origArgs, origEnv, origLog
	})
	enterpriseHookWorkerExecutable = os.Executable
	enterpriseHookWorkerArgs = []string{"-test.run=^TestEnterpriseHookWorkerHelperProcess$"}
	enterpriseHookWorkerExtraEnv = []string{enterpriseHookWorkerHelperEnv + "=" + mode}
	enterpriseHookWorkerLog = io.Discard
}

func selfWorkerAccount(t *testing.T) enterpriseHookWorkerAccount {
	t.Helper()
	return enterpriseHookWorkerAccount{UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: filepath.Clean(t.TempDir())}
}

func workerTarget(account enterpriseHookWorkerAccount, index int, mode, connectorName string, previouslyProtected bool) enterpriseHookWorkerTarget {
	return enterpriseHookWorkerTarget{
		Index:               index,
		Mode:                mode,
		PreviouslyProtected: previouslyProtected,
		Options: enterpriseHookWorkerOptions{
			ConnectorName: connectorName,
			UserHome:      account.Home,
			OwnerUID:      account.UID,
			OwnerGID:      account.GID,
			APIToken:      "scoped-token",
		},
	}
}

func TestEnterpriseHookWorkerRunsTargetsWithAMinimalEnvironment(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "ok")
	t.Setenv("DEFENSECLAW_TEST_LEAK", "root-secret")
	t.Setenv(enterprisehooks.TrustedBinPrefixesEnv, "/opt/agents")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpApply,
		Standalone: true,
		Targets: []enterpriseHookWorkerTarget{
			workerTarget(account, 3, enterpriseHookWorkerModeInstall, "codex", false),
			workerTarget(account, 7, enterpriseHookWorkerModeVerifyOrRepair, "claudecode", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Targets) != 2 {
		t.Fatalf("targets = %+v", response.Targets)
	}
	for i, want := range []int{3, 7} {
		got := response.Targets[i]
		if got.Index != want || !got.OK || got.Result == nil || got.Repaired {
			t.Fatalf("target %d = %+v", i, got)
		}
		if got.Result.AgentVersion != account.Home {
			t.Fatalf("worker HOME = %q, want the target home %q", got.Result.AgentVersion, account.Home)
		}
		if got.Result.DataDir != "" {
			t.Fatalf("the guardian's environment leaked into the worker: %q", got.Result.DataDir)
		}
		if got.Result.HookContractID != "/opt/agents" {
			t.Fatalf("administrator passthrough env = %q", got.Result.HookContractID)
		}
	}

	// The worker PATH keeps the system directories first and then the
	// discovery directories (OmniGent setup looks itself up on PATH).
	path := enterpriseHookWorkerPath("/home/alice", 1000)
	parts := strings.Split(path, ":")
	if len(parts) < 3 || parts[0] != "/usr/bin" || parts[1] != "/bin" {
		t.Fatalf("worker PATH = %q", path)
	}
	if !strings.Contains(path, ":/home/alice/.local/bin") {
		t.Fatalf("worker PATH lacks the per-user bin dir: %q", path)
	}
	seen := map[string]bool{}
	for _, part := range parts {
		if seen[part] {
			t.Fatalf("worker PATH repeats %q: %q", part, path)
		}
		seen[part] = true
	}
}

func TestEnterpriseHookWorkerRepairsDriftOnlyForProtectedTargets(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "drift")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply,
		Targets: []enterpriseHookWorkerTarget{
			workerTarget(account, 0, enterpriseHookWorkerModeVerifyOrRepair, "codex", true),
			workerTarget(account, 1, enterpriseHookWorkerModeVerify, "codex", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets[0]; !got.OK || !got.Repaired {
		t.Fatalf("drift on a protected target must be repaired: %+v", got)
	}
	if got := response.Targets[1]; got.OK || !strings.Contains(got.Error, "drifted") || got.Pending {
		t.Fatalf("verify must report drift without repairing: %+v", got)
	}
}

func TestEnterpriseHookWorkerReportsPerTargetFailures(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "fail")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply,
		Targets:   []enterpriseHookWorkerTarget{workerTarget(account, 0, enterpriseHookWorkerModeInstall, "codex", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets[0]; got.OK || got.Pending || got.Error != "install refused" {
		t.Fatalf("a failure inside an available home is a failure, not pending: %+v", got)
	}
}

func TestEnterpriseHookWorkerDiscoverRunsAsTheUser(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "ok")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpDiscover,
		Connectors: []string{"codex", "claudecode"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Versions["codex"] != "0.142.0" || response.Reasons["claudecode"] == "" {
		t.Fatalf("discover response = %+v", response)
	}

	// For an untrusted home the parent asks for a static discovery, and the
	// worker then never takes the executing path.
	t.Run("static discovery", func(t *testing.T) {
		useEnterpriseHookWorkerHelper(t, "ok")
		account := selfWorkerAccount(t)
		response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
			Operation:       enterpriseHookWorkerOpDiscover,
			Connectors:      []string{"codex"},
			StaticDiscovery: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, executed := response.Versions["codex"]; executed || !enterprisehooks.UnixAgentInstalledWithoutVersion(response.Reasons["codex"]) {
			t.Fatalf("static discover response = %+v, want the static finding only", response)
		}
	})
}

func TestEnterpriseHookWorkerRejectsMalformedOrRunawayWorkers(t *testing.T) {
	// Only the runaway worker gets the short timeout: an instrumented test
	// binary can take longer than a second to start on a busy runner.
	for _, tc := range []struct {
		mode    string
		want    string
		timeout time.Duration
	}{
		{"garbage", "invalid JSON", 30 * time.Second},
		{"oversize", "oversized response", 30 * time.Second},
		{"sleep", "timed out", time.Second},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, tc.mode)
			origTimeout := enterpriseHookWorkerTimeout
			enterpriseHookWorkerTimeout = tc.timeout
			t.Cleanup(func() { enterpriseHookWorkerTimeout = origTimeout })
			account := selfWorkerAccount(t)
			started := time.Now()
			_, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if time.Since(started) > 10*time.Second {
				t.Fatalf("a runaway worker was not killed promptly (%s)", time.Since(started))
			}
		})
	}
}

func TestEnterpriseHookWorkerRefusesForeignOrRootIdentity(t *testing.T) {
	if _, err := runEnterpriseHookWorker(context.Background(), enterpriseHookWorkerAccount{UID: 0, GID: 0, Home: "/root"}, enterpriseHookWorkerRequest{}); err == nil {
		t.Fatal("a worker for uid 0 must be refused")
	}
	if os.Geteuid() != 0 {
		_, err := runEnterpriseHookWorker(context.Background(), enterpriseHookWorkerAccount{UID: os.Getuid() + 1, GID: os.Getgid(), Home: "/home/other"}, enterpriseHookWorkerRequest{})
		if err == nil || !strings.Contains(err.Error(), "only run a worker for itself") {
			t.Fatalf("a non-root parent must not target another uid: %v", err)
		}
	}
	home := filepath.Clean(t.TempDir())
	for name, request := range map[string]enterpriseHookWorkerRequest{
		"wrong uid":     {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid() + 1, GID: os.Getgid(), Home: home},
		"wrong version": {Version: 99, UID: os.Getuid(), GID: os.Getgid(), Home: home},
		"root home":     {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid(), GID: os.Getgid(), Home: "/"},
		"foreign target": {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid(), GID: os.Getgid(), Home: home,
			Targets: []enterpriseHookWorkerTarget{{Options: enterpriseHookWorkerOptions{UserHome: "/elsewhere", OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("identity mismatches are exercised as an unprivileged user")
			}
			payload, _ := json.Marshal(request)
			var stdout bytes.Buffer
			if code := enterpriseHookWorkerMain(context.Background(), bytes.NewReader(payload), &stdout, io.Discard); code != 4 {
				t.Fatalf("exit = %d, want 4 (%s)", code, stdout.String())
			}
			var response enterpriseHookWorkerResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil || response.Error == "" || len(response.Targets) != 0 {
				t.Fatalf("response = %s (%v)", stdout.String(), err)
			}
		})
	}
	var stdout bytes.Buffer
	if code := enterpriseHookWorkerMain(context.Background(), strings.NewReader(`{"version":1,"unknown":true}`), &stdout, io.Discard); code != 3 {
		t.Fatalf("an unknown request field must be rejected, exit = %d", code)
	}
}

func TestEnterpriseHookWorkerPoolBoundsParallelism(t *testing.T) {
	origRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = origRunner })
	var active, peak int32
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, _ enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		now := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if now <= old || atomic.CompareAndSwapInt32(&peak, old, now) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return enterpriseHookWorkerResponse{Versions: map[string]string{"uid": fmt.Sprint(account.UID)}}, nil
	}
	jobs := map[int]*enterpriseHookWorkerJob{}
	for uid := 1000; uid < 1012; uid++ {
		jobs[uid] = &enterpriseHookWorkerJob{Account: enterpriseHookWorkerAccount{UID: uid}}
	}
	outcomes := runEnterpriseHookWorkerPool(context.Background(), sortedWorkerJobs(jobs), enterpriseHookWorkerParallelism)
	if peak > enterpriseHookWorkerParallelism || peak < 2 {
		t.Fatalf("peak parallelism = %d, want 2..%d", peak, enterpriseHookWorkerParallelism)
	}
	for i, outcome := range outcomes {
		if want := fmt.Sprint(1000 + i); outcome.Response.Versions["uid"] != want {
			t.Fatalf("outcome %d is for uid %s, want %s", i, outcome.Response.Versions["uid"], want)
		}
	}
}

func TestDispatchEnterpriseHookStandaloneJobsDistrustsWorkerAnswers(t *testing.T) {
	origRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = origRunner })
	account := enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "alice", Home: "/home/alice"}
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{Targets: []enterpriseHookWorkerTargetResult{
			{Index: 0, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 1, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/bob"}},
			{Index: 2, OK: true, Result: &enterprisehooks.InstallResult{Connector: "cursor", UserHome: "/home/alice"}},
			{Index: 3, OK: true},
			{Index: 4, Pending: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 5, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 5, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 7, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice", HookScripts: []string{strings.Repeat("x", enterpriseHookWorkerResultMaxBytes)}}},
			{Index: 8, Pending: true},
			{Index: 42, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
		}}, nil
	}
	request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply}
	for index := 0; index <= 8; index++ {
		request.Targets = append(request.Targets, workerTarget(account, index, enterpriseHookWorkerModeVerify, "codex", true))
	}
	outcomes := dispatchEnterpriseHookStandaloneJobs(context.Background(), map[int]*enterpriseHookWorkerJob{account.UID: {Account: account, Request: request}})
	if !outcomes[0].ok {
		t.Fatalf("a well-formed answer must succeed: %+v", outcomes[0])
	}
	for _, index := range []int{1, 2, 3, 4, 5, 6, 7} {
		if outcomes[index].ok || outcomes[index].pending || outcomes[index].err == "" {
			t.Fatalf("target %d: a forged, missing or inconsistent answer must fail: %+v", index, outcomes[index])
		}
	}
	if !outcomes[8].pending {
		t.Fatalf("a canonical pending answer must stay pending: %+v", outcomes[8])
	}
	if _, ok := outcomes[42]; ok {
		t.Fatal("an answer for a target that was never requested must be ignored")
	}
}

// standaloneTestDir returns a directory whose ancestors the home trust
// checks accept (t.TempDir() is below /tmp or the macOS /var symlink).
func standaloneTestDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(wd, ".m4-standalone-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if check := enterprisehooks.CheckUnixTargetHome(resolved, os.Getuid()); check.State == enterprisehooks.HomeUntrusted {
		t.Skipf("test working directory is not a trusted home parent: %s", check.Reason)
	}
	return resolved
}

type standaloneTestResolver struct {
	accounts  map[string]unixidentity.Account
	transient map[string]bool
}

func (r standaloneTestResolver) LookupUser(name string) (unixidentity.Account, error) {
	if r.transient[name] {
		return unixidentity.Account{}, errors.New("sssd: backend offline")
	}
	if account, ok := r.accounts[name]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r standaloneTestResolver) LookupUID(uid int) (unixidentity.Account, error) {
	for name, account := range r.accounts {
		if account.UID == uid {
			return r.LookupUser(name)
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) LookupGroup(string) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) LookupGroupID(int) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) GroupIDs(account unixidentity.Account) ([]int, error) {
	return []int{account.GID}, nil
}

func (standaloneTestResolver) ListUsers() ([]unixidentity.Account, bool, error) {
	return nil, false, nil
}

type standaloneFixture struct {
	root, homes, dataDir, authDir, manifest string
	mu                                      sync.Mutex
	requests                                []enterpriseHookWorkerRequest
}

// newStandaloneFixture puts the CLI into the standalone Unix profile with
// the root-only trust checks stubbed so the reconcile logic can run as an
// unprivileged user.
func newStandaloneFixture(t *testing.T, resolver unixidentity.Resolver) *standaloneFixture {
	t.Helper()
	root := standaloneTestDir(t)
	f := &standaloneFixture{
		root:     root,
		homes:    filepath.Join(root, "home"),
		dataDir:  filepath.Join(root, "data"),
		authDir:  filepath.Join(root, "auth"),
		manifest: filepath.Join(root, "targets.yaml"),
	}
	for _, dir := range []string{f.homes, f.dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, f.authDir)
	origCfg, origManifest := cfg, enterpriseHookManifest
	origPreflight, origManifestTrust, origRuntime := enterpriseHooksMutationIdentityPreflight, enterpriseHookManifestFileTrustCheck, enterpriseHookStandaloneRuntimeCheck
	origOwner, origDirTrust, origFileTrust, origStateTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookGuardianStateFileTrustCheck
	origToken, origOTLP, origRunner, origLog := enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter, enterpriseHookWorkerRunner, enterpriseHookWorkerLog
	origUserToken, origUserTokenLoader, origTransport := enterpriseHookUserTokenMinter, enterpriseHookUserTokenLoader, enterpriseHookStandaloneHookTransport
	origCheckHome := enterpriseHookCheckHome
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = origCfg, origManifest
		enterpriseHooksMutationIdentityPreflight, enterpriseHookManifestFileTrustCheck, enterpriseHookStandaloneRuntimeCheck = origPreflight, origManifestTrust, origRuntime
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookGuardianStateFileTrustCheck = origOwner, origDirTrust, origFileTrust, origStateTrust
		enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter, enterpriseHookWorkerRunner, enterpriseHookWorkerLog = origToken, origOTLP, origRunner, origLog
		enterpriseHookUserTokenMinter, enterpriseHookUserTokenLoader, enterpriseHookStandaloneHookTransport = origUserToken, origUserTokenLoader, origTransport
		enterpriseHookCheckHome = origCheckHome
		enterprisehooks.SetStandaloneUnix(false)
		enterprisehooks.SetStandaloneResolver(nil)
	})
	cfg = standaloneTestConfig(f.dataDir)
	enterpriseHookManifest = f.manifest
	noop := func() error { return nil }
	noopPath := func(string) error { return nil }
	enterpriseHooksMutationIdentityPreflight = noop
	enterpriseHookStandaloneRuntimeCheck = noop
	enterpriseHookManifestFileTrustCheck = noopPath
	enterpriseHookAuthorizationOwnershipSetter = noopPath
	enterpriseHookAuthorizationDirTrustCheck = noopPath
	enterpriseHookAuthorizationFileTrustCheck = noopPath
	enterpriseHookGuardianStateFileTrustCheck = noopPath
	// The standalone guardian must not mint the connector-scoped
	// credentials every user would share.
	enterpriseHookScopedTokenMinter = func(string, string) (string, error) {
		t.Error("standalone reconcile minted a connector-scoped hook token")
		return "", errors.New("connector-scoped token")
	}
	enterpriseHookScopedOTLPTokenMinter = func(string, string) (string, error) {
		t.Error("standalone reconcile minted a connector-scoped OTLP token")
		return "", errors.New("connector-scoped token")
	}
	enterpriseHookUserTokenMinter = standaloneTestUserTokens
	enterpriseHookUserTokenLoader = standaloneTestUserTokens
	enterpriseHookStandaloneHookTransport = func() (string, int, error) {
		return "/run/defenseclaw-hook/hook.sock", 995, nil
	}
	enterpriseHookWorkerLog = io.Discard
	enterprisehooks.SetStandaloneUnix(true)
	enterprisehooks.SetStandaloneResolver(resolver)
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		f.mu.Lock()
		f.requests = append(f.requests, request)
		f.mu.Unlock()
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index,
				OK:    true,
				Result: &enterprisehooks.InstallResult{
					Connector:                  target.Options.ConnectorName,
					UserHome:                   target.Options.UserHome,
					HookContractLockUpdatedAt:  "2026-09-26T00:00:00Z",
					HookContractEntryUpdatedAt: "2026-09-26T00:00:01Z",
				},
			})
		}
		return response, nil
	}
	return f
}

// standaloneTestUserTokens stands in for the per-user credential
// derivation: distinct, recognizable values per connector and identity.
func standaloneTestUserTokens(_, connectorName, identity string) (string, string, error) {
	return "hook-" + connectorName + "-" + identity, "otlp-" + connectorName + "-" + identity, nil
}

func standaloneTestConfig(dataDir string) *config.Config {
	c := &config.Config{DataDir: dataDir, DeploymentMode: "managed_enterprise"}
	c.Enterprise.Profile = "standalone"
	c.Gateway.APIPort = 18970
	c.Guardrail.Port = 4000
	return c
}

func (f *standaloneFixture) home(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	home := filepath.Join(f.homes, name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, mode); err != nil {
		t.Fatal(err)
	}
	return home
}

func (f *standaloneFixture) writeManifest(t *testing.T, targets ...enterprisehooks.ManifestTarget) {
	t.Helper()
	enabled := true
	for i := range targets {
		targets[i].Enabled = &enabled
	}
	data, err := enterprisehooks.MarshalUnixTargetsManifest(enterprisehooks.Manifest{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) writeLedger(t *testing.T, protected ...enterpriseHookReconcileRow) {
	t.Helper()
	if err := os.MkdirAll(f.authDir, 0o750); err != nil {
		t.Fatal(err)
	}
	ledger := enterpriseHookGuardianAuthorization{
		Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), OK: true,
		TargetCount: len(protected), SuccessCount: len(protected), ProtectedTargets: protected,
	}
	data, _ := json.MarshalIndent(ledger, "", "  ")
	if err := os.WriteFile(filepath.Join(f.authDir, hookGuardianAuthorizationFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) writeBindings(t *testing.T, bindings map[string]enterpriseHookUnixBinding) {
	t.Helper()
	if err := os.MkdirAll(f.authDir, 0o750); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(enterpriseHookUnixBindings{Version: enterpriseHookUnixBindingsVersion, Bindings: bindings})
	if err := os.WriteFile(filepath.Join(f.authDir, enterpriseHookUnixBindingsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) ledger(t *testing.T) enterpriseHookGuardianAuthorization {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.authDir, hookGuardianAuthorizationFile))
	if err != nil {
		t.Fatal(err)
	}
	var ledger enterpriseHookGuardianAuthorization
	if err := json.Unmarshal(data, &ledger); err != nil {
		t.Fatal(err)
	}
	return ledger
}

func (f *standaloneFixture) workerTargets() map[string]enterpriseHookWorkerTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]enterpriseHookWorkerTarget{}
	for _, request := range f.requests {
		for _, target := range request.Targets {
			out[target.Options.ConnectorName+"@"+target.Options.UserHome] = target
		}
	}
	return out
}

func protectedRow(userName, home, connectorName string) enterpriseHookReconcileRow {
	return enterpriseHookReconcileRow{
		User: userName, UserHome: home, Connector: connectorName, OK: true,
		Result: &enterprisehooks.InstallResult{Connector: connectorName, UserHome: home},
	}
}

// requireLedgerOrStateTrust tolerates the one check an unprivileged test
// cannot stub: the service-runtime trust check on the state file.
func requireLedgerOrStateTrust(t *testing.T, err error) {
	t.Helper()
	if err != nil && (os.Geteuid() == 0 || !strings.Contains(err.Error(), "hook guardian state")) {
		t.Fatalf("state error = %v", err)
	}
}

func TestStandaloneReconcileSeparatesPendingFromTrustFailures(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := filepath.Join(f.homes, "bob") // not created yet: pam_mkhomedir has not run
	carolReal := f.home(t, "carol-real", 0o700)
	carol := filepath.Join(f.homes, "carol")
	if err := os.Symlink(carolReal, carol); err != nil {
		t.Fatal(err)
	}
	for name, home := range map[string]string{"alice": alice, "bob": bob, "carol": carol} {
		resolver.accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "carol", Connector: "codex"},
	)
	// bob was protected before his home went away.
	f.writeLedger(t, protectedRow("bob", bob, "codex"))
	bobKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "bob", Connector: "codex"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{bobKey: {UID: uid, Home: bob, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 4 || run.Pending != 1 || run.Failures != 1 {
		t.Fatalf("rows = %+v pending=%d failures=%d", run.Rows, run.Pending, run.Failures)
	}
	if !run.Rows[0].OK || !run.Rows[1].OK {
		t.Fatalf("alice must be protected: %+v", run.Rows[:2])
	}
	if !run.Rows[2].Pending || run.Rows[2].Error != "" {
		t.Fatalf("a missing home is pending, not a failure: %+v", run.Rows[2])
	}
	if run.Rows[3].OK || !strings.Contains(run.Rows[3].Error, "symlink") {
		t.Fatalf("a symlinked home is a trust failure: %+v", run.Rows[3])
	}
	if got := len(f.requests); got != 1 {
		t.Fatalf("one worker per user expected, got %d requests", got)
	}
	ledger := f.ledger(t)
	if len(ledger.ProtectedTargets) != 2 || ledger.SuccessCount != 2 || ledger.PendingCount != 1 || ledger.FailureCount != 1 {
		t.Fatalf("a pending target must leave the ledger, keeping SuccessCount == len(protected): %+v", ledger)
	}
	for _, row := range ledger.ProtectedTargets {
		if row.User != "alice" {
			t.Fatalf("unexpected protected target %+v", row)
		}
		if row.UID != uid || row.HomeInode == 0 {
			t.Fatalf("a protected Unix target must carry its uid and home inode for peer authorization: %+v", row)
		}
	}
	bindings := loadEnterpriseHookUnixBindings()
	if len(bindings.Bindings) != 3 || bindings.Bindings[bobKey].LockUpdatedAt != "L" {
		t.Fatalf("bindings must record alice and keep bob's repair rights: %+v", bindings.Bindings)
	}
}

// Disabling a connector removes its manifest rows and the gateway then
// refuses those users' hooks, so a registration left in a home stops the
// agent at a hook that fails closed. The guardian removes it as the user,
// records a home that is not available until the removal can run, and
// leaves the home of a machine-policy row alone: it installed nothing there.
func TestStandaloneReconcileRemovesRegistrationsTheManifestNoLongerEnrolls(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := filepath.Join(f.homes, "bob") // not mounted yet
	for name, home := range map[string]string{"alice": alice, "bob": bob} {
		resolver.accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	}
	protected := func(userName, home, connectorName string) enterpriseHookReconcileRow {
		row := protectedRow(userName, home, connectorName)
		row.UID = uid
		return row
	}
	machineRow := enterpriseHookReconcileRow{User: "alice", UserHome: alice, Connector: "claudecode", OK: true, UID: uid}
	f.writeLedger(t, protected("alice", alice, "codex"), protected("alice", alice, "kiro"), protected("bob", bob, "kiro"), machineRow)
	// kiro is disabled: the enumerator keeps only alice's codex row.
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"})

	reconcile := func() {
		t.Helper()
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireLedgerOrStateTrust(t, run.StateErr)
	}
	reconcile()
	targets := f.workerTargets()
	if _, machine := targets["claudecode@"+alice]; machine || targets["kiro@"+alice].Mode != enterpriseHookWorkerModeRemove ||
		targets["codex@"+alice].Mode != enterpriseHookWorkerModeVerifyOrRepair {
		t.Fatalf("alice's kiro registration must be removed, her codex kept and her machine-policy row left alone: %+v", targets)
	}
	pending, err := loadEnterpriseHookUserCleanups(f.dataDir)
	if err != nil || len(pending) != 1 || pending[0].Connector != "kiro" || pending[0].User != "bob" || pending[0].UID != uid {
		t.Fatalf("bob's unavailable home must be recorded for cleanup: %+v, %v", pending, err)
	}

	f.home(t, "bob", 0o700)
	reconcile()
	if f.workerTargets()["kiro@"+bob].Mode != enterpriseHookWorkerModeRemove {
		t.Fatalf("bob's kiro registration was not removed once his home is available: %+v", f.workerTargets())
	}
	if pending, err := loadEnterpriseHookUserCleanups(f.dataDir); err != nil || len(pending) != 0 {
		t.Fatalf("a done cleanup must leave the ledger: %+v, %v", pending, err)
	}
}

func TestStandaloneReconcileBindingsDetectUIDReuseAndKeepRepairRights(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
	)
	codexKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "codex"})
	claudeKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "claudecode"})
	// codex was protected for a previous owner of this name (uid reuse);
	// claudecode was protected before a pending cycle revoked its row.
	f.writeLedger(t, protectedRow("alice", alice, "codex"))
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{
		codexKey:  {UID: uid + 1, Home: alice},
		claudeKey: {UID: uid, Home: alice, LockUpdatedAt: "lock-at", EntryUpdatedAt: "entry-at"},
	})
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	targets := f.workerTargets()
	codex := targets["codex@"+alice]
	if codex.PreviouslyProtected || codex.Options.AllowMissingHookConfigRepair {
		t.Fatalf("a reused uid must not inherit repair rights: %+v", codex)
	}
	claude := targets["claudecode@"+alice]
	if !claude.PreviouslyProtected || !claude.Options.AllowMissingHookConfigRepair ||
		claude.Options.RecoveryHookContractLockUpdatedAt != "lock-at" || claude.Options.RecoveryHookContractEntryUpdatedAt != "entry-at" {
		t.Fatalf("a matching binding must keep repair rights: %+v", claude)
	}
	bindings := loadEnterpriseHookUnixBindings()
	if bindings.Bindings[codexKey].UID != uid || bindings.Bindings[codexKey].HomeInode == 0 {
		t.Fatalf("a successful install must rebind to the current account: %+v", bindings.Bindings[codexKey])
	}

	// alice was deleted and bob created with her reused uid: the failed row
	// carried alice's previous ledger entry, which still names that uid, so
	// bob's hook calls matched it. A reassigned identity now revokes the
	// carried protection; an account that is merely not found (what a
	// directory outage also looks like) keeps it.
	t.Run("reassigned uid", func(t *testing.T) {
		resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
			"bob":  {Name: "bob", UID: 5001, GID: 5001, Home: "/home/bob", Shell: "/bin/bash"},
			"dave": {Name: "dave", UID: 7002, GID: 7002, Home: "/home/dave", Shell: "/bin/bash"},
		}}
		f := newStandaloneFixture(t, resolver)
		row := func(name string, uid int) enterprisehooks.ManifestTarget {
			home := filepath.Join(f.homes, name)
			return enterprisehooks.ManifestTarget{User: name, UserHome: home, UID: &uid, GID: &uid, Connector: "opencode"}
		}
		f.writeManifest(t, row("alice", 5001), row("carol", 6001), row("dave", 7001), row("erin", 8001))
		var protected []enterpriseHookReconcileRow
		bindings := map[string]enterpriseHookUnixBinding{}
		for name, uid := range map[string]int{"alice": 5001, "carol": 6001, "dave": 7001, "erin": 0} {
			home := filepath.Join(f.homes, name)
			prior := protectedRow(name, home, "opencode")
			prior.UID = uid
			protected = append(protected, prior)
			if uid > 0 {
				bindings[enterpriseHookProtectedTargetKey(prior)] = enterpriseHookUnixBinding{UID: uid, Home: home}
			}
		}
		// erin's manifest row names uid 8001, but her binding recorded uid 5001.
		erinKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "erin", Connector: "opencode"})
		bindings[erinKey] = enterpriseHookUnixBinding{UID: 5001, Home: filepath.Join(f.homes, "erin")}
		f.writeLedger(t, protected...)
		f.writeBindings(t, bindings)

		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireLedgerOrStateTrust(t, run.StateErr)
		if run.Failures != 4 || len(f.requests) != 0 {
			t.Fatalf("every row fails before dispatch: %+v", run.Rows)
		}
		kept := map[string]bool{}
		for _, target := range f.ledger(t).ProtectedTargets {
			kept[target.User] = true
		}
		if kept["alice"] || kept["dave"] || kept["erin"] {
			t.Fatalf("a reassigned uid must not inherit the old authorization: %v", kept)
		}
		if !kept["carol"] {
			t.Fatalf("an account that is only not found keeps its protection: %v", kept)
		}
		saved := loadEnterpriseHookUnixBindings().Bindings
		if _, ok := saved[enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "opencode"})]; ok {
			t.Fatalf("a reassigned identity's repair binding must be dropped: %v", saved)
		}
		if _, ok := saved[enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "carol", Connector: "opencode"})]; !ok {
			t.Fatalf("carol's binding must be kept: %v", saved)
		}
	})

	// frank was protected under an old uid (his binding and the prior ledger
	// row carry it) and now resolves to a new one. If this pass fails, the old
	// uid, which may already belong to someone else, must not stay authorized.
	t.Run("name moved to a new uid", func(t *testing.T) {
		uid, gid := os.Getuid(), os.Getgid()
		resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
		f := newStandaloneFixture(t, resolver)
		real := f.home(t, "frank-real", 0o700)
		frank := filepath.Join(f.homes, "frank")
		if err := os.Symlink(real, frank); err != nil { // untrusted: this pass fails
			t.Fatal(err)
		}
		resolver.accounts["frank"] = unixidentity.Account{Name: "frank", UID: uid, GID: gid, Home: frank, Shell: "/bin/bash"}
		f.writeManifest(t, enterprisehooks.ManifestTarget{User: "frank", UserHome: frank, UID: &uid, GID: &gid, Connector: "opencode"})
		prior := protectedRow("frank", frank, "opencode")
		prior.UID = uid + 1
		f.writeLedger(t, prior)
		f.writeBindings(t, map[string]enterpriseHookUnixBinding{enterpriseHookProtectedTargetKey(prior): {UID: uid + 1, Home: frank}})
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireLedgerOrStateTrust(t, run.StateErr)
		if run.Failures != 1 {
			t.Fatalf("rows = %+v", run.Rows)
		}
		if got := f.ledger(t).ProtectedTargets; len(got) != 0 {
			t.Fatalf("the old uid must not stay authorized: %+v", got)
		}
	})
}

func TestStandaloneReconcileHonorsManifestIdentityDuringDirectoryOutage(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{"ldapuser": true, "other": true}}
	f := newStandaloneFixture(t, resolver)
	ldap := f.home(t, "ldapuser", 0o700)
	other := f.home(t, "other", 0o700)
	resolver.accounts["ldapuser"] = unixidentity.Account{Name: "ldapuser", UID: uid, GID: gid, Home: ldap}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "ldapuser", UserHome: ldap, UID: &uid, GID: &gid, Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "other", UserHome: other, Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "deleted", Connector: "codex"},
	)
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if !run.Rows[0].OK {
		t.Fatalf("an explicit manifest identity must be honored during an NSS outage: %+v", run.Rows[0])
	}
	if !run.Rows[1].Pending {
		t.Fatalf("an NSS outage without explicit identity is pending, never deleted: %+v", run.Rows[1])
	}
	if run.Rows[2].OK || run.Rows[2].Pending || !strings.Contains(run.Rows[2].Error, "does not exist") {
		t.Fatalf("a definitive not-found is a failure: %+v", run.Rows[2])
	}
}

func TestStandaloneReconcileTreatsHungHomeAsPending(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	nfs := f.home(t, "nfsuser", 0o700)
	resolver.accounts["nfsuser"] = unixidentity.Account{Name: "nfsuser", UID: uid, GID: gid, Home: nfs}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "nfsuser", Connector: "codex"})
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending, Reason: "user home " + home + " did not respond"}
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Rows) != 1 || !run.Rows[0].Pending || len(f.requests) != 0 {
		t.Fatalf("a hung home must be pending without starting a worker: %+v (%d requests)", run.Rows, len(f.requests))
	}
}

func TestMergeProtectedTargetsDropsPendingOnlyForStandalone(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() { cfg = origCfg })
	previous := []enterpriseHookReconcileRow{protectedRow("bob", "/home/bob", "codex")}
	current := []enterpriseHookReconcileRow{{User: "bob", UserHome: "/home/bob", Connector: "codex", Pending: true}}

	cfg = standaloneTestConfig("/var/lib/defenseclaw")
	if merged := mergeProtectedEnterpriseHookTargets(previous, current); len(merged) != 0 {
		t.Fatalf("standalone must revoke a pending target: %+v", merged)
	}
	// Secure Client keeps its historical carry-over.
	cfg = &config.Config{DataDir: "/var/lib/defenseclaw", DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if merged := mergeProtectedEnterpriseHookTargets(previous, current); len(merged) != 1 {
		t.Fatalf("secure_client carry-over changed: %+v", merged)
	}
}

func TestStandaloneReconcileLockSerializesReconciles(t *testing.T) {
	_ = newStandaloneFixture(t, standaloneTestResolver{})
	unlock, err := lockEnterpriseHookReconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	origWait := enterpriseHookReconcileLockWait
	enterpriseHookReconcileLockWait = 200 * time.Millisecond
	t.Cleanup(func() { enterpriseHookReconcileLockWait = origWait })
	if _, err := lockEnterpriseHookReconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "another reconcile holds") {
		t.Fatalf("a second reconcile must wait and then fail: %v", err)
	}
	unlock()
	second, err := lockEnterpriseHookReconcile(context.Background())
	if err != nil {
		t.Fatalf("the lock must be free after unlock: %v", err)
	}
	second()
}

func TestEnterpriseHookCheckWorkerCapabilities(t *testing.T) {
	full := "Name:\tdefenseclaw\nCapEff:\t000001ffffffffff\n"
	if err := enterpriseHookCheckWorkerCapabilities(full); err != nil {
		t.Fatalf("full root capabilities: %v", err)
	}
	for name, status := range map[string]string{
		"no setuid": "CapEff:\t0000000000000040\n",
		"no setgid": "CapEff:\t0000000000000080\n",
		"none":      "CapEff:\t0000000000000000\n",
		"missing":   "Name:\tx\n",
		"garbage":   "CapEff:\tzz\n",
	} {
		if err := enterpriseHookCheckWorkerCapabilities(status); err == nil {
			t.Fatalf("%s: capabilities must be refused", name)
		}
	}
}

func TestEnterpriseHookStandaloneMutationPreflightIsStandaloneOnly(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() { cfg = origCfg })
	cfg = &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if err := enterpriseHookStandaloneMutationPreflight(); err != nil {
		t.Fatalf("secure_client must keep its preflight unchanged: %v", err)
	}
	cfg = standaloneTestConfig(t.TempDir())
	err := enterpriseHookStandaloneMutationPreflight()
	if os.Geteuid() != 0 && (err == nil || !strings.Contains(err.Error(), "must run as root")) {
		t.Fatalf("an unprivileged standalone guardian must be refused: %v", err)
	}
}

func TestEnterpriseHookSessionUIDsFrom(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"1000", "1001", "0", "abc", "01002"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := fmt.Sprint(enterpriseHookSessionUIDsFrom(dir)); got != "[1000 1001]" {
		t.Fatalf("session uids = %s", got)
	}
	if got := enterpriseHookSessionUIDsFrom(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("missing dir = %v", got)
	}
}

func TestEnterpriseHookStandaloneConfigChangeExitsOnlyForValidConfig(t *testing.T) {
	origCfg, origValidator := cfg, enterpriseHookStandaloneConfigValidator
	t.Cleanup(func() { cfg, enterpriseHookStandaloneConfigValidator = origCfg, origValidator })
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = standaloneTestConfig(t.TempDir())
	cfg.ConfigFilePath = path
	startup := enterpriseHookStandaloneConfigFingerprint()
	if startup == "" || enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("an unchanged config must not restart the guardian")
	}
	if err := os.WriteFile(path, []byte("a: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enterpriseHookStandaloneConfigValidator = func(string) error { return errors.New("typo") }
	if enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("an invalid config must not stop repair")
	}
	enterpriseHookStandaloneConfigValidator = func(string) error { return nil }
	if !enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("a valid config change must restart the guardian")
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if enterpriseHookStandaloneConfigFingerprint() != "" || enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("secure_client watchers never restart on config changes")
	}
}

func TestWriteGuardianStateStandaloneUsesAuthorizationDir(t *testing.T) {
	f := newStandaloneFixture(t, standaloneTestResolver{})
	writeGuardianStateOrLog(io.Discard, guardianstate.StateReady)
	path := filepath.Join(f.authDir, guardianstate.FileName)
	if got := guardianstate.ReadState(path); got != guardianstate.StateReady {
		t.Fatalf("state at %s = %q", path, got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("state file mode = %v (%v), want 0640 for the gateway group", info.Mode(), err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.manifest), guardianstate.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("standalone must not write the state beside the manifest: %v", err)
	}
	if want := guardianstate.PathForPlatform(enterpriseHooksStandaloneUnixActive(), cfg.DataDir, managed.HookGuardianAuthorizationDir(cfg.DataDir)); want != path {
		t.Fatalf("gateway reader path %s differs from the writer path %s", want, path)
	}
}

func TestStandaloneVerifyAcceptsOnlyRecordedPendingTargets(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := filepath.Join(f.homes, "bob")
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	resolver.accounts["bob"] = unixidentity.Account{Name: "bob", UID: uid, GID: gid, Home: bob}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "codex"},
	)
	_, sha, err := enterprisehooks.LoadManifestWithSHA256(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(rows []enterpriseHookReconcileRow) {
		t.Helper()
		// Publish the records as an unmanaged writer: the final state
		// trust check needs a root- or service-owned file.
		standalone := cfg
		cfg = &config.Config{DataDir: f.dataDir}
		defer func() { cfg = standalone }()
		if err := writeEnterpriseHookGuardianState(f.dataDir, f.manifest, sha, rows, 0, true); err != nil {
			t.Fatal(err)
		}
	}
	publish([]enterpriseHookReconcileRow{protectedRow("alice", alice, "codex"), {User: "bob", UserHome: bob, Connector: "codex", Pending: true}})
	run, err := runEnterpriseHookVerifyAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.AuthorizationErr != nil || run.Failures != 0 || run.Pending != 1 || !run.Rows[0].OK || !run.Rows[1].Pending {
		t.Fatalf("recorded pending target: rows=%+v failures=%d pending=%d auth=%v", run.Rows, run.Failures, run.Pending, run.AuthorizationErr)
	}
	// Verification expects alice's own per-user credentials.
	verified := f.workerTargets()["codex@"+alice].Options
	if verified.APIToken != "hook-codex-"+strconv.Itoa(uid) || verified.HookCredentialIdentity != strconv.Itoa(uid) {
		t.Fatalf("verify options are not bound to alice's uid: %+v", verified)
	}

	// The guardian never recorded bob pending: an unavailable home now is
	// a failure, not a free pass.
	publish([]enterpriseHookReconcileRow{protectedRow("alice", alice, "codex"), protectedRow("bob", bob, "codex")})
	run, err = runEnterpriseHookVerifyAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Failures != 1 || run.Rows[1].OK || !strings.Contains(run.Rows[1].Error, "has not recorded it pending") {
		t.Fatalf("unrecorded pending target: rows=%+v failures=%d", run.Rows, run.Failures)
	}
}

func TestResolveEnterpriseHookTargetFallsBackToTheDirectory(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"ldap-only-user": {Name: "ldap-only-user", UID: 1234567, GID: 1234567, Home: "/home/ldap-only-user"},
	}}
	_ = newStandaloneFixture(t, resolver)
	target, err := resolveEnterpriseHookTargetValues("ldap-only-user", "", -1, -1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.uid != 1234567 || target.gid != 1234567 || target.home != "/home/ldap-only-user" {
		t.Fatalf("target = %+v", target)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if _, err := resolveEnterpriseHookTargetValues("ldap-only-user", "", -1, -1, "", ""); err == nil {
		t.Fatal("secure_client must keep resolving through os/user only")
	}
}

// With unenrolled_users: deny the enumerator writes rows for connectors the
// lifecycle published through machine policy. Those rows only mark the uid
// as enrolled: running the per-user installer for them failed live on RHEL
// (Codex refuses user hooks under allow_managed_hooks_only, Claude Code
// verification trips over the managed settings). They succeed when the
// machine policy is in place and never reach a worker.
func TestStandaloneReconcileMachinePolicyRowsOnlyRecordEnrollment(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "amp"},
	)
	previousSet, previousCovered := enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered
	t.Cleanup(func() {
		enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered = previousSet, previousCovered
	})
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} {
		return map[string]struct{}{"codex": {}, "claudecode": {}}
	}
	covered := map[string]bool{"codex": true, "claudecode": false}
	enterpriseHookStandaloneMachinePolicyCovered = func(name string) (bool, error) { return covered[name], nil }

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	byConnector := map[string]enterpriseHookReconcileRow{}
	for _, row := range run.Rows {
		byConnector[row.Connector] = row
	}
	if row := byConnector["codex"]; !row.OK || row.UID != uid || row.HomeInode == 0 {
		t.Fatalf("a covered machine-policy row must be an enrolled target: %+v", row)
	}
	if row := byConnector["claudecode"]; row.OK || !strings.Contains(row.Error, "machine policy is not in place") {
		t.Fatalf("an uncovered machine-policy row must fail: %+v", row)
	}
	if row := byConnector["amp"]; !row.OK {
		t.Fatalf("the per-user connector must still be installed: %+v", row)
	}
	for _, request := range f.requests {
		for _, target := range request.Targets {
			if target.Options.ConnectorName == "codex" || target.Options.ConnectorName == "claudecode" {
				t.Fatalf("a machine-policy row reached the per-user worker: %+v", target)
			}
		}
	}
}

// A home that could be inspected when its target was protected and now
// refuses the guardian (for example a filesystem the user mounted over it)
// is a failure; staying pending stopped every repair for that user.
func TestStandaloneReconcileFailsAProtectedHomeThatNowRefusesInspection(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := f.home(t, "bob", 0o700)
	for name, home := range map[string]string{"alice": alice, "bob": bob} {
		resolver.accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "codex"},
	)
	aliceKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "codex"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{aliceKey: {UID: uid, Home: alice}})
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending, AccessDenied: true, Reason: "user home " + home + " refused inspection: permission denied"}
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 2 || len(f.requests) != 0 {
		t.Fatalf("rows = %+v (%d worker requests)", run.Rows, len(f.requests))
	}
	if row := run.Rows[0]; row.OK || row.Pending || !strings.Contains(row.Error, "was available when this target was protected") {
		t.Fatalf("a protected home that now refuses inspection must fail: %+v", row)
	}
	if row := run.Rows[1]; !row.Pending || row.Error != "" {
		t.Fatalf("a never-protected home that refuses inspection stays pending: %+v", row)
	}
}

func TestEnterpriseHookWorkerTightensTheUsersOwnHome(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "ok")
	account := selfWorkerAccount(t)
	if err := os.Chmod(account.Home, 0o772); err != nil {
		t.Fatal(err)
	}
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation:   enterpriseHookWorkerOpApply,
		Standalone:  true,
		TightenHome: true,
		Targets:     []enterpriseHookWorkerTarget{workerTarget(account, 0, enterpriseHookWorkerModeVerifyOrRepair, "opencode", true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets; len(got) != 1 || !got[0].OK {
		t.Fatalf("targets = %+v", got)
	}
	info, err := os.Stat(account.Home)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("home mode = %v (%v), want 0750", info.Mode().Perm(), err)
	}
	// A home path that is a symlink is refused, not followed.
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(account.Home, link); err != nil {
		t.Fatal(err)
	}
	linked := account
	linked.Home = link
	response, err = runEnterpriseHookWorker(context.Background(), linked, enterpriseHookWorkerRequest{
		Operation:   enterpriseHookWorkerOpApply,
		Standalone:  true,
		TightenHome: true,
		Targets:     []enterpriseHookWorkerTarget{workerTarget(linked, 0, enterpriseHookWorkerModeVerifyOrRepair, "opencode", true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets; len(got) != 1 || got[0].OK || !strings.Contains(got[0].Error, "remove group/other write") {
		t.Fatalf("a symlinked home must not be tightened or repaired: %+v", got)
	}

	// A user who loosened their own home (chmod g+w ~) made every reconcile
	// fail the row before dispatch, so nothing ever repaired their hooks. The
	// user's own worker now removes group/other write and repairs.
	t.Run("the reconcile asks for it", func(t *testing.T) {
		uid, gid := os.Getuid(), os.Getgid()
		resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
		f := newStandaloneFixture(t, resolver)
		dave := f.home(t, "dave", 0o770)
		resolver.accounts["dave"] = unixidentity.Account{Name: "dave", UID: uid, GID: gid, Home: dave, Shell: "/bin/bash"}
		f.writeManifest(t, enterprisehooks.ManifestTarget{User: "dave", Connector: "opencode"})
		var log bytes.Buffer
		enterpriseHookWorkerLog = &log
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireLedgerOrStateTrust(t, run.StateErr)
		if len(run.Rows) != 1 || !run.Rows[0].OK || run.Failures != 0 {
			t.Fatalf("a loosened enrolled home must be repaired: %+v failures=%d", run.Rows, run.Failures)
		}
		if len(f.requests) != 1 || !f.requests[0].TightenHome {
			t.Fatalf("the worker must be asked to remove group/other write first: %+v", f.requests)
		}
		if !strings.Contains(log.String(), "group/other writable") {
			t.Fatalf("the loosened mode must still be reported: %q", log.String())
		}
	})
}

type supplementaryGroupResolver struct {
	standaloneTestResolver
	groups []int
	err    error
}

func (r supplementaryGroupResolver) GroupIDs(unixidentity.Account) ([]int, error) {
	return r.groups, r.err
}

// The worker's credential carried only the primary group, so an agent
// under an administrator prefix readable only by a group (or a config
// reachable only through one) was invisible to discovery and repair.
func TestEnterpriseHookWorkerCredentialKeepsSupplementaryGroups(t *testing.T) {
	account := enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "alice", Home: "/home/alice"}
	cred := enterpriseHookWorkerCredential(account, []int{1001, 2000, 2000, -1, 3000}, 16)
	if cred.Uid != 1001 || cred.Gid != 1001 || fmt.Sprint(cred.Groups) != "[1001 2000 3000]" {
		t.Fatalf("credential = %+v", cred)
	}
	if cred := enterpriseHookWorkerCredential(account, []int{1, 2, 3, 4, 5}, 3); fmt.Sprint(cred.Groups) != "[1001 1 2]" {
		t.Fatalf("the group list must respect the platform limit with the primary group first: %v", cred.Groups)
	}
	if enterpriseHookWorkerMaxGroups < 8 || enterpriseHookWorkerMaxGroups > 65536 {
		t.Fatalf("implausible group limit %d", enterpriseHookWorkerMaxGroups)
	}
	t.Cleanup(func() { enterprisehooks.SetStandaloneResolver(nil) })
	enterprisehooks.SetStandaloneResolver(supplementaryGroupResolver{groups: []int{1001, 2000}})
	if got := enterpriseHookWorkerGroupIDs(account); fmt.Sprint(got) != "[1001 2000]" {
		t.Fatalf("supplementary groups must come from the account resolver: %v", got)
	}
	origLog := enterpriseHookWorkerLog
	t.Cleanup(func() { enterpriseHookWorkerLog = origLog })
	enterpriseHookWorkerLog = io.Discard
	enterprisehooks.SetStandaloneResolver(supplementaryGroupResolver{err: errors.New("sssd: backend offline")})
	if got := enterpriseHookWorkerGroupIDs(account); got != nil {
		t.Fatalf("an unavailable directory falls back to the primary group only: %v", got)
	}
}

// The guardian spools each enrolled user's AI Discovery scan with the
// account it started the worker for, whatever the worker's report claims,
// strips the raw paths the administrator did not keep, and drops the record
// of a user the manifest no longer enrolls.
func TestStandaloneAIDiscoveryPassSpoolsEachScanAsItsAccount(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	if err := os.MkdirAll(filepath.Join(alice, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alice, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AIDiscovery.Enabled = true
	dir := inventory.UserScanDirForConfig(cfg)
	stale := filepath.Join(dir, "4242.json")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if request.Operation != enterpriseHookWorkerOpAIDiscovery || request.AIDiscovery == nil || account.User != "alice" {
			t.Errorf("unexpected worker request %+v for %+v", request, account)
			return enterpriseHookWorkerResponse{}, errors.New("unexpected request")
		}
		options := request.AIDiscovery.Options
		options.StoreRawLocalPaths = true // a worker that keeps paths anyway
		report := inventory.ScanUserHome(ctx, account.Home, account.User, account.UID, options, request.AIDiscovery.Catalog)
		for i := range report.Signals {
			report.Signals[i].UserName, report.Signals[i].UserID = "mallory", "0"
		}
		return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, AIDiscovery: &report}, nil
	}

	runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
		{User: "alice", UserHome: alice, Connector: "codex", OK: true, UID: uid},
	})

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the record of an account the manifest does not enroll must go: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, strconv.Itoa(uid)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record inventory.UserScanRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.UID != uid || record.User != "alice" || len(record.Report.Signals) == 0 {
		t.Fatalf("record = uid %d user %q with %d signals, want alice's scan", record.UID, record.User, len(record.Report.Signals))
	}
	if strings.Contains(string(data), alice) || strings.Contains(string(data), "mallory") {
		t.Fatalf("the spooled report kept a raw path or the worker's account claim: %s", data)
	}
}

// A home whose scan keeps failing pauses after three failed passes in a
// row, so the guardian stops starting a worker for it on every pass
// (GAP-0694); the pass after the pause tries again and a good scan closes
// the breaker.
func TestStandaloneAIDiscoveryPassPausesAHomeWhoseScanKeepsFailing(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	cfg.AIDiscovery.Enabled = true
	dir := inventory.UserScanDirForConfig(cfg)
	previous := enterpriseHookAIDiscoveryBreaker
	t.Cleanup(func() { enterpriseHookAIDiscoveryBreaker = previous })
	enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)
	workers, fail := 0, true
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		workers++
		if fail {
			return enterpriseHookWorkerResponse{}, errors.New("worker for uid timed out: context deadline exceeded")
		}
		report := inventory.ScanUserHome(ctx, account.Home, account.User, account.UID, request.AIDiscovery.Options, request.AIDiscovery.Catalog)
		return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, AIDiscovery: &report}, nil
	}
	pass := func() {
		runEnterpriseHookAIDiscoveryPass(context.Background(), io.Discard, dir, []enterpriseHookReconcileRow{
			{User: "alice", UserHome: alice, Connector: "codex", OK: true, UID: uid},
		})
	}
	for range 4 {
		pass()
	}
	if workers != 3 {
		t.Fatalf("workers = %d, want 3: the fourth pass must skip the paused home", workers)
	}
	enterpriseHookAIDiscoveryBreaker.accounts[uid].until = time.Now().Add(-time.Second)
	fail = false
	pass()
	pass()
	if workers != 5 || len(enterpriseHookAIDiscoveryBreaker.accounts) != 0 {
		t.Fatalf("workers = %d, breaker = %+v: after the pause a good scan closes the breaker", workers, enterpriseHookAIDiscoveryBreaker.accounts)
	}
}

// A worker error ends with its cause. The remove-all report cut it at 256
// bytes, in the middle of a path, so the uninstall never said why a
// registration stayed. An oversized error keeps its start and its cause.
func TestRemoveAllReportKeepsTheWorkerErrorCause(t *testing.T) {
	path := "/Users/alice/.openhands/" + strings.Repeat("nested/", 60) + "hooks.json"
	cause := "enterprise hooks: connector openhands teardown failed: restore config backup: rename " + path + ".tmp \u2192 " + path + ": operation not permitted"
	got := boundedWorkerError(cause)
	if len(got) > workerErrorMaxBytes || !utf8.ValidString(got) || !strings.HasPrefix(got, "enterprise hooks: connector openhands") || !strings.HasSuffix(got, ": operation not permitted") {
		t.Fatalf("bounded worker error = %q", got)
	}
}

// A deployment that selects only machine-policy connectors has no manifest
// rows; the guardian still writes identity records and per-user scans for
// every eligible account the enumerator published (GAP-0021).
func TestStandaloneGuardianCoversEligibleAccountsWithoutRows(t *testing.T) {
	previous, previousConfig := enterpriseHookLoadEligibleAccounts, cfg
	t.Cleanup(func() { enterpriseHookLoadEligibleAccounts, cfg = previous, previousConfig })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	enterpriseHookLoadEligibleAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		if path != enterprisehooks.UnixEligibleAccountsPath("/etc/defenseclaw/hooks/manifest.json") {
			t.Errorf("eligible accounts read from %q", path)
		}
		return []enterprisehooks.UnixEligibleAccount{
			{User: "alice", UID: 1001, Home: "/home/alice"},
			{User: "bob@corp.example", UID: 94401104, Home: "/home/bob@corp.example"},
		}, nil
	}
	rows := enterpriseHookEnrolledAccountRows(io.Discard, enterpriseHookReconcileRun{
		Manifest: "/etc/defenseclaw/hooks/manifest.json",
		Rows:     []enterpriseHookReconcileRow{{User: "alice", UserHome: "/home/alice", Connector: "opencode", OK: true, UID: 1001}},
	})
	if len(rows) != 2 || rows[0].Connector != "opencode" || rows[1].UID != 94401104 || rows[1].User != "bob@corp.example" || rows[1].UserHome != "/home/bob@corp.example" {
		t.Fatalf("rows = %+v, want the manifest row and one row for the eligible account without one", rows)
	}
	cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
	rows = enterpriseHookEnrolledAccountRows(io.Discard, enterpriseHookReconcileRun{
		Manifest: "/etc/defenseclaw/hooks/manifest.json",
		Rows:     []enterpriseHookReconcileRow{{User: "alice", UserHome: "/home/alice", Connector: "opencode", OK: true, UID: 1001}},
	})
	if len(rows) != 1 || rows[0].UID != 1001 {
		t.Fatalf("manifest mode scanned stale eligible accounts: %+v", rows)
	}
	// Nor does it publish their identity records (GAP-0761): the record the
	// last auto pass left still names bob, whom the manifest no longer
	// enrolls; carol is enrolled by name and has no row yet.
	previousIdentity := enterpriseHookLoadIdentityAccounts
	t.Cleanup(func() { enterpriseHookLoadIdentityAccounts = previousIdentity })
	enterpriseHookLoadIdentityAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{
			{User: "alice", UID: 1001}, {User: "bob@corp.example", UID: 94401104}, {User: "carol", UID: 1003},
		}, nil
	}
	alice := 1001
	accounts, _ := enterpriseHookIdentitySpoolAccounts(io.Discard, enterpriseHookReconcileRun{
		Manifest: "/etc/defenseclaw/hooks/manifest.json",
		Targets:  []enterprisehooks.ManifestTarget{{User: "alice", UID: &alice, Connector: "opencode"}, {User: "carol", Connector: "opencode"}},
		Rows:     []enterpriseHookReconcileRow{{User: "alice", UserHome: "/home/alice", Connector: "opencode", OK: true, UID: 1001}},
	})
	if len(accounts) != 2 || accounts[0].UID != 1001 || accounts[1].UID != 1003 {
		t.Fatalf("manifest mode published identity records for %+v, want alice and carol only", accounts)
	}
}

// GAP-0775: a deleted local account may remain in the guardian state until
// the enumerator drops it. An unavailable directory can give the same NSS
// not-found answer for a logged-in account, so its failed row must stay red.
func TestStandaloneUnixRemovedAccountRowIsExcused(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLocal, previousDirectory := enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured = previousLocal, previousDirectory
		enterprisehooks.SetStandaloneResolver(nil)
	})
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	if err := enterprisehooks.SaveUnixEnumeratorState(enterpriseHookEnumeratorStatePath(enterpriseHookManifest),
		&enterprisehooks.UnixEnumeratorState{Version: 1, Sources: map[string]string{"carol": "files"}}); err != nil {
		t.Fatal(err)
	}
	enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) {
		return map[string]int{"alice": 4242}, nil
	}
	enterpriseHooksEnumerateDirectoryConfigured = func() bool { return true }
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"alice": {Name: "alice", UID: 4242, GID: 4242},
	}})
	state := enterpriseHookGuardianState{FailureCount: 1, Results: []enterpriseHookReconcileRow{
		{User: "carol", Connector: "claudecode", Error: `enterprise hooks: target account "carol" does not exist: no such account`},
	}}
	if got := enterpriseHookRemovedAccountFailures(state); got != 1 {
		t.Fatalf("deleted local account: excused = %d, want 1", got)
	}
	state.Results[0] = enterpriseHookReconcileRow{User: "okta-carol", Connector: "claudecode", Error: "enterprise hooks: hook config is group/other writable"}
	if got := enterpriseHookRemovedAccountFailures(state); got != 0 {
		t.Fatalf("directory outage with failed hook: excused = %d, want 0", got)
	}
	state.Results[0].Error = `enterprise hooks: target account "okta-carol" does not exist: no such account`
	if got := enterpriseHookRemovedAccountFailures(state); got != 0 {
		t.Fatalf("directory outage with missing-account error: excused = %d, want 0", got)
	}
	state.Results[0] = enterpriseHookReconcileRow{User: "alice", Connector: "codex", Error: "enterprise hooks: hook config is group/other writable"}
	if got := enterpriseHookRemovedAccountFailures(state); got != 0 {
		t.Fatalf("account that resolves: excused = %d, want 0", got)
	}
}

// A manifest alias is only an enrollment spelling. The spool must use the
// account name returned for its UID, or a failed privileged refresh can erase
// the previous verified UPN before the gateway expires it.
func TestIdentitySpoolCanonicalizesManifestAlias(t *testing.T) {
	t.Cleanup(func() { enterprisehooks.SetStandaloneResolver(nil) })
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"canonical": {Name: "canonical", UID: 4242, GID: 4242},
	}})
	accounts, _ := enterpriseHookIdentitySpoolAccounts(io.Discard, enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{{UID: 4242, User: "accepted-alias", Connector: "codex", OK: true}},
	})
	if len(accounts) != 1 || accounts[0].User != "canonical" {
		t.Fatalf("identity spool accounts = %+v; want canonical UID name", accounts)
	}
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: "4242", User: "canonical", UpdatedAt: time.Now().UTC(),
		Facts: useridentity.DirectoryFacts{UPN: "alice@example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "4242.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = enterprisehooks.WriteIdentitySpool(canceled, dir, accounts, nil, nil)
	record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, "4242", nil)
	if err != nil || record.Facts.UPN != "alice@example.test" {
		t.Fatalf("failed refresh lost the verified UPN: record=%+v err=%v", record, err)
	}
}

// A home-only manifest target has a verified uid after reconciliation but
// no User field. The macOS identity collector needs the uid's account name.
func TestIdentitySpoolNamesHomeOnlyTarget(t *testing.T) {
	t.Cleanup(func() { enterprisehooks.SetStandaloneResolver(nil) })
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"alice": {Name: "alice", UID: 4242, GID: 4242, Home: "/Users/alice"},
	}})
	accounts, _ := enterpriseHookIdentitySpoolAccounts(io.Discard, enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{{UID: 4242, UserHome: "/Users/alice", Connector: "codex", OK: true}},
	})
	if len(accounts) != 1 || accounts[0].UID != 4242 || accounts[0].User != "alice" {
		t.Fatalf("identity spool accounts = %+v; want alice for uid 4242", accounts)
	}
}
