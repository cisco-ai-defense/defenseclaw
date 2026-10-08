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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Standalone Unix guardian. Reconcile and verify dispatch every user-home
// operation to the per-user apply-target worker, classify unavailable
// homes as pending rather than failures, remember the uid and home inode
// each target was protected under, and serialize reconciles with an
// exclusive lock. None of this runs for the Secure Client profile: every
// entry point is gated on enterpriseHooksStandaloneUnixActive.

const (
	enterpriseHookReconcileLockFile    = managed.HookGuardianReconcileLockFile
	enterpriseHookUnixBindingsFile     = "unix_target_bindings.json"
	enterpriseHookUnixBindingsMaxBytes = 4 << 20
	enterpriseHookUnixBindingsVersion  = 1
	enterpriseHookHomeCheckTimeout     = 5 * time.Second
	enterpriseHookWorkerResultMaxBytes = 64 << 10

	enterpriseHookCapSetgid = 6
	enterpriseHookCapSetuid = 7
)

var (
	enterpriseHookProcStatusPath = "/proc/self/status"
	// enterpriseHookReconcileLockWait bounds how long a reconcile waits
	// for another one to finish.
	enterpriseHookReconcileLockWait = 2 * time.Minute
	// enterpriseHookStandaloneRuntimeCheck validates the managed data and
	// authorization directories; replaceable in unprivileged tests.
	enterpriseHookStandaloneRuntimeCheck = validateEnterpriseHookManagedRuntime
)

// enterpriseHooksStandaloneUnixActive reports the standalone profile on a
// Unix host.
func enterpriseHooksStandaloneUnixActive() bool {
	return cfg != nil && cfg.StandaloneEnterprise()
}

// configureEnterpriseHooksStandaloneUnix switches the enterprisehooks
// package to the standalone Unix rules once the config is loaded.
func configureEnterpriseHooksStandaloneUnix(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	active := enterpriseHooksStandaloneUnixActive()
	enterprisehooks.SetStandaloneUnix(active)
	if active {
		enterprisehooks.SetStandaloneResolver(unixidentity.Default(ctx))
	}
}

// enterpriseHookStandaloneLookupFallback resolves a user os/user could not
// (directory-backed accounts on CGO_ENABLED=0 Linux builds).
func enterpriseHookStandaloneLookupFallback(name string, lookupErr error) (*user.User, error) {
	if !enterpriseHooksStandaloneUnixActive() {
		return nil, lookupErr
	}
	account, err := enterprisehooks.StandaloneResolver().LookupUser(name)
	if err != nil {
		return nil, fmt.Errorf("%w (directory: %v)", lookupErr, err)
	}
	return &user.User{
		Uid:      strconv.Itoa(account.UID),
		Gid:      strconv.Itoa(account.GID),
		Username: account.Name,
		Name:     account.Gecos,
		HomeDir:  account.Home,
	}, nil
}

// enterpriseHookStandaloneMutationPreflight requires a root guardian that
// still holds CAP_SETUID and CAP_SETGID; without them it cannot start the
// per-user worker.
func enterpriseHookStandaloneMutationPreflight() error {
	if !enterpriseHooksStandaloneUnixActive() {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("enterprise hooks: the standalone guardian must run as root (euid=%d)", os.Geteuid())
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	status, err := os.ReadFile(enterpriseHookProcStatusPath)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read process capabilities: %w", err)
	}
	return enterpriseHookCheckWorkerCapabilities(string(status))
}

func enterpriseHookCheckWorkerCapabilities(status string) error {
	for _, line := range strings.Split(status, "\n") {
		value, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return fmt.Errorf("enterprise hooks: parse process capabilities: %w", err)
		}
		if mask&(1<<enterpriseHookCapSetuid) == 0 || mask&(1<<enterpriseHookCapSetgid) == 0 {
			return errors.New("enterprise hooks: the standalone guardian needs CAP_SETUID and CAP_SETGID to start per-user workers")
		}
		return nil
	}
	return errors.New("enterprise hooks: process capabilities are unavailable")
}

// lockEnterpriseHookReconcile takes the exclusive reconcile lock inside the
// root-owned authorization directory so the watcher and a manual
// reconcile never interleave ledger writes.
func lockEnterpriseHookReconcile(ctx context.Context) (func(), error) {
	dir := managed.HookGuardianAuthorizationDir(cfg.DataDir)
	if err := ensureEnterpriseHookStandaloneAuthDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, enterpriseHookReconcileLockFile)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open reconcile lock: %w", err)
	}
	deadline := time.Now().Add(enterpriseHookReconcileLockWait)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("enterprise hooks: another reconcile holds %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// ensureEnterpriseHookStandaloneAuthDir creates or re-hardens the
// root-owned authorization directory the gateway reads.
func ensureEnterpriseHookStandaloneAuthDir(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("hook guardian authorization path is not a trusted directory: %s", dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect hook guardian authorization directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create hook guardian authorization directory: %w", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return fmt.Errorf("harden hook guardian authorization directory: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(dir); err != nil {
		return fmt.Errorf("set hook guardian authorization directory ownership: %w", err)
	}
	return enterpriseHookAuthorizationDirTrustCheck(dir)
}

// Identity bindings remember the uid, home inode and recovery timestamps
// each target was protected under. They are root-only (0600) and separate
// from the ledger, whose schema the gateway parses strictly. A binding
// keeps a target's repair rights while its home is temporarily pending,
// and a mismatch (uid reuse, recreated home) drops them so the next
// install follows first-install rules.

type enterpriseHookUnixBinding struct {
	UID            int    `json:"uid"`
	Home           string `json:"home"`
	HomeInode      uint64 `json:"home_inode,omitempty"`
	LockUpdatedAt  string `json:"hook_contract_lock_updated_at,omitempty"`
	EntryUpdatedAt string `json:"hook_contract_entry_updated_at,omitempty"`
}

type enterpriseHookUnixBindings struct {
	Version  int                                  `json:"version"`
	Bindings map[string]enterpriseHookUnixBinding `json:"bindings"`
}

func enterpriseHookUnixBindingsPath() string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(cfg.DataDir), enterpriseHookUnixBindingsFile)
}

func loadEnterpriseHookUnixBindings() enterpriseHookUnixBindings {
	empty := enterpriseHookUnixBindings{Version: enterpriseHookUnixBindingsVersion, Bindings: map[string]enterpriseHookUnixBinding{}}
	path := enterpriseHookUnixBindingsPath()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > enterpriseHookUnixBindingsMaxBytes {
		return empty
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var parsed enterpriseHookUnixBindings
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&parsed) != nil || parsed.Version != enterpriseHookUnixBindingsVersion || parsed.Bindings == nil {
		return empty
	}
	return parsed
}

func saveEnterpriseHookUnixBindings(bindings enterpriseHookUnixBindings) error {
	bindings.Version = enterpriseHookUnixBindingsVersion
	data, err := json.MarshalIndent(bindings, "", "  ")
	if err != nil {
		return err
	}
	path := enterpriseHookUnixBindingsPath()
	if err := writeEnterpriseHookProtectedFile(path, append(data, '\n')); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// lookup returns the binding for key. ok is false when none exists; match
// is false on uid reuse or a recreated home.
func (b enterpriseHookUnixBindings) lookup(key string, uid int, home string, inode uint64) (binding enterpriseHookUnixBinding, ok, match bool) {
	binding, ok = b.Bindings[key]
	if !ok {
		return binding, false, false
	}
	match = binding.UID == uid && filepath.Clean(binding.Home) == filepath.Clean(home) &&
		(binding.HomeInode == 0 || inode == 0 || binding.HomeInode == inode)
	return binding, true, match
}

// resolveEnterpriseHookStandaloneAccount resolves a manifest row to the
// account its worker runs as. pendingReason is set when the directory
// cannot answer right now and the row carries no complete identity.
func resolveEnterpriseHookStandaloneAccount(
	target enterprisehooks.ManifestTarget,
	resolver unixidentity.Resolver,
) (enterpriseHookWorkerAccount, string, error) {
	name := strings.TrimSpace(target.User)
	home := strings.TrimSpace(target.UserHome)
	explicit := target.UID != nil && target.GID != nil && home != ""
	var account unixidentity.Account
	var lookupErr error
	switch {
	case name != "":
		account, lookupErr = resolver.LookupUser(name)
	case target.UID != nil:
		account, lookupErr = resolver.LookupUID(*target.UID)
	case home != "":
		uid, err := enterpriseHookHomeOwner(home)
		if err != nil {
			if enterprisehooks.PendingTargetError(err) {
				return enterpriseHookWorkerAccount{}, fmt.Sprintf("user home %s is not available: %v", home, err), nil
			}
			return enterpriseHookWorkerAccount{}, "", err
		}
		account, lookupErr = resolver.LookupUID(uid)
	default:
		return enterpriseHookWorkerAccount{}, "", errors.New("enterprise hooks: target requires user, uid or user_home")
	}
	label := firstNonEmpty(name, home)
	if lookupErr != nil {
		if unixidentity.IsNotFound(lookupErr) {
			return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: target account %q does not exist: %w", label, errEnterpriseHookTargetNotFound)
		}
		if explicit {
			// Honor the administrator-published identity while the
			// directory is unreachable; an NSS error never means the
			// account is gone.
			return enterpriseHookWorkerAccount{UID: *target.UID, GID: *target.GID, User: firstNonEmpty(name, strconv.Itoa(*target.UID)), Home: filepath.Clean(home)}, "", nil
		}
		return enterpriseHookWorkerAccount{}, fmt.Sprintf("directory lookup for %q is unavailable: %v", label, lookupErr), nil
	}
	if target.UID != nil && *target.UID != account.UID {
		return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: target %q uid %d no longer matches the directory uid %d: %w", account.Name, *target.UID, account.UID, errEnterpriseHookTargetUIDChanged)
	}
	if target.GID != nil && *target.GID != account.GID {
		return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: target %q gid %d no longer matches the directory primary gid %d", account.Name, *target.GID, account.GID)
	}
	if home == "" {
		home = account.Home
	}
	if strings.TrimSpace(account.Home) != "" && filepath.Clean(home) != filepath.Clean(account.Home) {
		return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: target %q home %s no longer matches the directory home %s", account.Name, home, account.Home)
	}
	if account.UID <= 0 {
		return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: refusing to target uid %d", account.UID)
	}
	if !filepath.IsAbs(home) {
		return enterpriseHookWorkerAccount{}, "", fmt.Errorf("enterprise hooks: target %q has no absolute home", account.Name)
	}
	return enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.Name, Home: filepath.Clean(home)}, "", nil
}

var (
	errEnterpriseHookTargetNotFound   = errors.New("no such account")
	errEnterpriseHookTargetUIDChanged = errors.New("the account's uid changed")
)

// enterpriseHookStandaloneIdentityReassigned reports a failed resolution
// after which the uid the target was last protected under may belong to
// someone else: its name now maps to another uid, or its name is gone and
// that uid now resolves to another account. A name that is gone while its
// uid resolves to nobody keeps its protection: that is also what a
// directory outage looks like, and no other account can hold the uid.
func enterpriseHookStandaloneIdentityReassigned(err error, target enterprisehooks.ManifestTarget, binding *enterpriseHookUnixBinding, resolver unixidentity.Resolver) bool {
	if errors.Is(err, errEnterpriseHookTargetUIDChanged) {
		return true
	}
	if !errors.Is(err, errEnterpriseHookTargetNotFound) {
		return false
	}
	name := strings.TrimSpace(target.User)
	var uids []int
	if target.UID != nil {
		uids = append(uids, *target.UID)
	}
	if binding != nil {
		uids = append(uids, binding.UID)
	}
	for _, uid := range uids {
		if uid <= 0 {
			continue
		}
		if holder, lookupErr := resolver.LookupUID(uid); lookupErr == nil && holder.Name != name {
			return true
		}
	}
	return false
}

func enterpriseHookHomeOwner(home string) (int, error) {
	info, err := enterprisehooks.BoundedLstat(home, enterpriseHookHomeCheckTimeout)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: inspect user home %s: %w", home, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("enterprise hooks: cannot inspect user home %s owner", home)
	}
	return int(st.Uid), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// enterpriseHookCheckHome classifies a home without letting a hung network
// filesystem stall the guardian: a check that does not answer in time is
// pending, and while it is still blocked no further blocking check of that
// home is started, so rows, passes and reconciles cannot pile up blocked
// threads.
var enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
	return enterprisehooks.BoundedCheckUnixTargetHome(home, uid, enterpriseHookHomeCheckTimeout)
}

// validateEnterpriseHookWorkerResult treats the worker's answer as
// untrusted: the worker runs as the target user, who may be able to
// ptrace it. A success must name exactly the requested connector and home
// and stay small enough for the gateway's bounded ledger read.
func validateEnterpriseHookWorkerResult(target enterpriseHookWorkerTarget, result enterpriseHookWorkerTargetResult) error {
	if !result.OK {
		if result.Result != nil {
			return errors.New("worker reported a failed target with a result")
		}
		if len(result.Error) > enterpriseHookWorkerResultMaxBytes {
			return errors.New("worker error message is too large")
		}
		return nil
	}
	if result.Pending || result.Result == nil || strings.TrimSpace(result.Error) != "" {
		return errors.New("worker reported an inconsistent successful target")
	}
	if !strings.EqualFold(strings.TrimSpace(result.Result.Connector), strings.TrimSpace(target.Options.ConnectorName)) {
		return fmt.Errorf("worker result names connector %q, want %q", result.Result.Connector, target.Options.ConnectorName)
	}
	if filepath.Clean(result.Result.UserHome) != filepath.Clean(target.Options.UserHome) {
		return fmt.Errorf("worker result names home %q, want %q", result.Result.UserHome, target.Options.UserHome)
	}
	encoded, err := json.Marshal(result.Result)
	if err != nil || len(encoded) > enterpriseHookWorkerResultMaxBytes {
		return errors.New("worker result is too large")
	}
	return nil
}

// enterpriseHookStandaloneOutcome is one row's worker disposition.
type enterpriseHookStandaloneOutcome struct {
	ok       bool
	pending  bool
	repaired bool
	err      string
	result   *enterprisehooks.InstallResult
}

// dispatchEnterpriseHookStandaloneJobs runs the worker pool and maps every
// dispatched row index to its validated outcome. A row without a valid
// answer is a failure, never a success.
func dispatchEnterpriseHookStandaloneJobs(
	ctx context.Context,
	jobs map[int]*enterpriseHookWorkerJob,
) map[int]enterpriseHookStandaloneOutcome {
	outcomes := map[int]enterpriseHookStandaloneOutcome{}
	for _, run := range runEnterpriseHookWorkerPool(ctx, sortedWorkerJobs(jobs), enterpriseHookWorkerParallelism) {
		byIndex := map[int]enterpriseHookWorkerTargetResult{}
		duplicate := map[int]bool{}
		for _, result := range run.Response.Targets {
			if _, seen := byIndex[result.Index]; seen {
				duplicate[result.Index] = true
			}
			byIndex[result.Index] = result
		}
		for _, target := range run.Job.Request.Targets {
			result, answered := byIndex[target.Index]
			switch {
			case duplicate[target.Index]:
				outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: "worker answered this target more than once"}
			case !answered && run.Err != nil:
				if errors.Is(run.Err, context.DeadlineExceeded) &&
					enterpriseHookCheckHome(target.Options.UserHome, target.Options.OwnerUID).State == enterprisehooks.HomePending {
					outcomes[target.Index] = enterpriseHookStandaloneOutcome{pending: true}
					continue
				}
				outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: run.Err.Error()}
			case !answered:
				outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: errEnterpriseHookWorkerNoResult.Error()}
			case result.Pending:
				if result.OK || result.Result != nil {
					outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: "worker reported an inconsistent pending target"}
					continue
				}
				outcomes[target.Index] = enterpriseHookStandaloneOutcome{pending: true}
			default:
				if err := validateEnterpriseHookWorkerResult(target, result); err != nil {
					outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: err.Error()}
					continue
				}
				if !result.OK {
					outcomes[target.Index] = enterpriseHookStandaloneOutcome{err: firstNonEmpty(result.Error, "worker reported an unspecified failure")}
					continue
				}
				outcomes[target.Index] = enterpriseHookStandaloneOutcome{ok: true, repaired: result.Repaired, result: result.Result}
			}
		}
	}
	return outcomes
}

// enterpriseHookStandaloneSlot tracks one dispatched manifest row.
type enterpriseHookStandaloneSlot struct {
	key     string
	account enterpriseHookWorkerAccount
	inode   uint64
	binding *enterpriseHookUnixBinding
	// verifiable: the worker verifies the target before repairing it (a
	// target that was not protected before is installed without a verify).
	verifiable bool
	// credentialID fingerprints the hook credential rendered for the
	// target (connector.UserScopedCredentialKeyID).
	credentialID string
}

// runEnterpriseHookReconcileOnceStandaloneUnix is the standalone Unix
// reconcile. The Secure Client reconcile is untouched.
func runEnterpriseHookReconcileOnceStandaloneUnix(ctx context.Context) (enterpriseHookReconcileRun, error) {
	run := enterpriseHookReconcileRun{Manifest: enterpriseHookManifest}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return run, err
	}
	if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
		return run, fmt.Errorf("enterprise hooks reconcile: manifest trust check failed: %w", err)
	}
	if err := enterpriseHookStandaloneRuntimeCheck(); err != nil {
		return run, err
	}
	unlock, err := lockEnterpriseHookReconcile(ctx)
	if err != nil {
		return run, err
	}
	defer unlock()
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	run.ManifestSHA256 = manifestSHA256
	apiAddr, proxyAddr := enterpriseHookListenAddrs()
	hookSocket, serviceUID, transportErr := enterpriseHookStandaloneHookTransport()
	resolver := enterprisehooks.StandaloneResolver()
	if caching, ok := resolver.(*unixidentity.CachingResolver); ok {
		caching.Reset()
	}
	registry := newEnterpriseHooksConnectorRegistry()
	bindings := loadEnterpriseHookUnixBindings()
	machinePolicy := enterpriseHookStandaloneMachinePolicySet()
	// Remove DefenseClaw's own registrations from the homes of targets the
	// manifest no longer enrolls, as each user, before this run's state
	// drops their rows. A ledger that cannot be written is reported with
	// the state: the revoked rows must still leave the authorization.
	cleanupErr := reconcileEnterpriseHookStandaloneUnixCleanups(ctx, enterpriseHookWorkerLog, manifest, bindings, machinePolicy, resolver, time.Now())
	next := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}
	carryBinding := func(key string) {
		if previous, ok := bindings.Bindings[key]; ok && key != "" {
			next.Bindings[key] = previous
		}
	}

	rows := make([]enterpriseHookReconcileRow, 0, len(manifest.Targets))
	jobs := map[int]*enterpriseHookWorkerJob{}
	slots := map[int]enterpriseHookStandaloneSlot{}
	watchDirs := map[string]struct{}{}
	exclusiveFiles := map[string]struct{}{}
	sharedFiles := map[string]struct{}{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			Connector: strings.TrimSpace(target.Connector),
		}
		pendingRow := func(reason string) {
			row.Pending = true
			rows = append(rows, row)
			carryBinding(enterpriseHookProtectedTargetKey(row))
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] %s pending: %s\n", enterpriseHookTargetLabel(row), reason)
		}
		failRow := func(err error) {
			row.Error = err.Error()
			rows = append(rows, row)
			if !row.RevokeProtection {
				carryBinding(enterpriseHookProtectedTargetKey(row))
			}
		}
		account, pendingReason, err := resolveEnterpriseHookStandaloneAccount(target, resolver)
		if err != nil {
			var binding *enterpriseHookUnixBinding
			if previous, ok := bindings.Bindings[enterpriseHookProtectedTargetKey(row)]; ok {
				binding = &previous
			}
			if enterpriseHookStandaloneIdentityReassigned(err, target, binding, resolver) {
				row.RevokeProtection = true
				fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] %s: the account's uid was reassigned; revoking its previous protection\n", enterpriseHookTargetLabel(row))
			}
			failRow(err)
			continue
		}
		if pendingReason != "" {
			pendingRow(pendingReason)
			continue
		}
		if protected, ok := bindings.Bindings[enterpriseHookProtectedTargetKey(row)]; ok && protected.UID != account.UID {
			// The name was protected under another uid, which the prior
			// ledger row still carries: if this pass fails, that uid must
			// not stay authorized.
			row.RevokeProtection = true
		}
		tightenHome := false
		row.UserHome = account.Home
		row.UID = account.UID
		check := enterpriseHookCheckHome(account.Home, account.UID)
		row.HomeInode = check.Inode
		switch check.State {
		case enterprisehooks.HomePending:
			if _, protectedBefore := bindings.Bindings[enterpriseHookProtectedTargetKey(row)]; check.AccessDenied && protectedBefore {
				// A home the guardian could inspect when it protected the
				// target now refuses it: that is a change on the host (for
				// example a filesystem the user mounted over it), not a
				// home that is still being created.
				failRow(fmt.Errorf("enterprise hooks: %s; it was available when this target was protected", check.Reason))
				continue
			}
			pendingRow(check.Reason)
			continue
		case enterprisehooks.HomeUntrusted:
			if _, published := machinePolicy[strings.ToLower(row.Connector)]; !check.LooseMode || published {
				failRow(errors.New("enterprise hooks: " + check.Reason))
				continue
			}
			// An enrolled user loosened their own home's mode. Failing the
			// row stopped every repair of their hooks; the user's own
			// worker removes group/other write (as the owner may) and then
			// repairs as usual.
			tightenHome = true
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: %s: %s; the user's worker removes group/other write before repair\n", enterpriseHookTargetLabel(row), check.Reason)
		}
		if target.HomeInode != 0 && check.Inode != target.HomeInode {
			pendingRow(fmt.Sprintf("home %s was recreated after enumeration; waiting for the enumerator to re-enroll it", account.Home))
			continue
		}
		if _, published := machinePolicy[strings.ToLower(row.Connector)]; published {
			// Machine policy already hooks this connector for every user;
			// with unenrolled_users: deny the row only records that this
			// uid is enrolled. Installing per-user hooks as well would
			// fight the managed-hooks lock the policy sets.
			covered, err := enterpriseHookStandaloneMachinePolicyCovered(row.Connector)
			switch {
			case err != nil:
				failRow(fmt.Errorf("enterprise hooks: %s machine policy is unreadable: %w", row.Connector, err))
			case !covered:
				failRow(fmt.Errorf("enterprise hooks: %s machine policy is not in place", row.Connector))
			default:
				row.OK = true
				rows = append(rows, row)
				next.Bindings[enterpriseHookProtectedTargetKey(row)] = enterpriseHookUnixBinding{
					UID: account.UID, Home: account.Home, HomeInode: check.Inode,
				}
			}
			continue
		}
		previousProtection, err := previousEnterpriseHookProtection(cfg.DataDir, target.User, account.Home, "", target.Connector)
		if err != nil {
			failRow(err)
			continue
		}
		key := enterpriseHookProtectedTargetKey(row)
		binding, hasBinding, bindingMatches := bindings.lookup(key, account.UID, account.Home, check.Inode)
		switch {
		case hasBinding && !bindingMatches:
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] %s: uid or home changed since it was protected; installing with first-install rules\n", enterpriseHookTargetLabel(row))
			previousProtection = enterpriseHookPreviousProtection{}
		case hasBinding && !previousProtection.PreviouslyProtected:
			// Protected before its home went pending: the ledger revoked
			// the row, the binding keeps its repair rights.
			previousProtection = enterpriseHookPreviousProtection{
				PreviouslyProtected:        true,
				HookContractLockUpdatedAt:  binding.LockUpdatedAt,
				HookContractEntryUpdatedAt: binding.EntryUpdatedAt,
			}
		}
		if transportErr != nil {
			// Per-user hooks and plugins reach the gateway only through the
			// hook socket; without it there is nothing safe to render.
			failRow(transportErr)
			continue
		}
		identity := strconv.Itoa(account.UID)
		token, otlpToken, err := enterpriseHookUserTokenMinter(cfg.DataDir, target.Connector, identity)
		if err != nil {
			failRow(err)
			continue
		}
		opts := enterprisehooks.InstallOptions{
			ConnectorName:                      target.Connector,
			UserHome:                           account.Home,
			OwnerUID:                           account.UID,
			OwnerGID:                           account.GID,
			DataDir:                            strings.TrimSpace(target.DataDir),
			APIAddr:                            apiAddr,
			ProxyAddr:                          proxyAddr,
			APIToken:                           token,
			OTLPPathToken:                      otlpToken,
			HookFailMode:                       cfg.EffectiveHookFailModeForConnector(target.Connector),
			GuardrailMode:                      cfg.EffectiveGuardrailModeForConnector(target.Connector),
			HILTEnabled:                        cfg.EffectiveHILTForConnector(target.Connector).Enabled,
			AgentVersion:                       strings.TrimSpace(target.AgentVersion),
			WorkspaceDir:                       cfg.ConnectorWorkspaceDir(),
			Registry:                           registry,
			AllowMissingHookConfigRepair:       previousProtection.PreviouslyProtected,
			RecoveryHookContractLockUpdatedAt:  previousProtection.HookContractLockUpdatedAt,
			RecoveryHookContractEntryUpdatedAt: previousProtection.HookContractEntryUpdatedAt,
			ManagedHookSocket:                  hookSocket,
			ManagedServiceUID:                  serviceUID,
			HookCredentialIdentity:             identity,
			ForeignHookGuardBinary:             standaloneForeignHookGuardBinary(target.Connector),
			ManagedHookBinary:                  standaloneManagedHookBinary(),
		}
		if dirs, watchErr := enterprisehooks.WatchDirs(opts); watchErr == nil {
			for _, dir := range dirs {
				watchDirs[dir] = struct{}{}
			}
		}
		if own, filesErr := enterprisehooks.WatchOwnedFiles(opts); filesErr == nil {
			for _, f := range own.ExclusiveWriter {
				exclusiveFiles[f] = struct{}{}
			}
			for _, f := range own.SharedWriter {
				sharedFiles[f] = struct{}{}
			}
		}
		index := len(rows)
		rows = append(rows, row)
		slot := enterpriseHookStandaloneSlot{
			key: key, account: account, inode: check.Inode, verifiable: previousProtection.PreviouslyProtected,
			credentialID: connector.UserScopedCredentialKeyID(token),
		}
		if hasBinding && bindingMatches {
			slot.binding = &binding
		}
		slots[index] = slot
		job, ok := jobs[account.UID]
		if !ok {
			job = &enterpriseHookWorkerJob{Account: account, Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true}}
			jobs[account.UID] = job
		}
		job.Request.TightenHome = job.Request.TightenHome || tightenHome
		job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
			Index:               index,
			Mode:                enterpriseHookWorkerModeVerifyOrRepair,
			PreviouslyProtected: previousProtection.PreviouslyProtected,
			Options:             enterpriseHookWorkerOptionsFrom(opts),
		})
	}

	outcomes := dispatchEnterpriseHookStandaloneJobs(ctx, jobs)
	repairs := 0
	var repaired []enterpriseHookGuardianRepair
	verified := map[int]bool{}
	for index, slot := range slots {
		row := rows[index]
		outcome, ok := outcomes[index]
		switch {
		case !ok:
			row.Error = errEnterpriseHookWorkerNoResult.Error()
		case outcome.pending:
			row.Pending = true
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] %s pending: its home became unavailable during repair\n", enterpriseHookTargetLabel(row))
		case outcome.ok:
			row.OK = true
			row.Result = outcome.result
			row.UserHome = outcome.result.UserHome
			row.Connector = outcome.result.Connector
			if outcome.repaired {
				repaired = append(repaired, enterpriseHookGuardianRepair{User: row.User, Connector: row.Connector})
				repairs++
			}
			verified[index] = slot.verifiable && !outcome.repaired
		default:
			row.Error = outcome.err
		}
		rows[index] = row
		if row.OK {
			next.Bindings[slot.key] = enterpriseHookUnixBinding{
				UID:            slot.account.UID,
				Home:           slot.account.Home,
				HomeInode:      slot.inode,
				LockUpdatedAt:  strings.TrimSpace(row.Result.HookContractLockUpdatedAt),
				EntryUpdatedAt: strings.TrimSpace(row.Result.HookContractEntryUpdatedAt),
			}
		} else if slot.binding != nil {
			next.Bindings[slot.key] = *slot.binding
		}
	}
	failures, pending := 0, 0
	for _, row := range rows {
		switch {
		case row.Pending:
			pending++
		case !row.OK:
			failures++
		}
	}

	bindingsErr := saveEnterpriseHookUnixBindings(next)
	writeEnterpriseHookGuardianRepairs(cfg.DataDir, repaired)
	stateErr := writeEnterpriseHookGuardianState(cfg.DataDir, enterpriseHookManifest, manifestSHA256, rows, failures, true)
	if stateErr == nil && bindingsErr != nil {
		stateErr = fmt.Errorf("persist protected target identity bindings: %w", bindingsErr)
	}
	if stateErr == nil && cleanupErr != nil {
		stateErr = fmt.Errorf("persist the per-user cleanup ledger: %w", cleanupErr)
	}
	if err := writeEnterpriseHookCredentialAttestation(manifestSHA256, rows, slots, verified, stateErr == nil); err != nil && stateErr == nil {
		stateErr = fmt.Errorf("publish the guardian credential attestation: %w", err)
	}
	run.Rows = rows
	run.Failures = failures
	run.Pending = pending
	run.Repairs = repairs
	run.StateErr = stateErr
	run.WatchDirs = sortedEnterpriseHookWatchDirs(watchDirs)
	run.WatchExclusiveFiles = sortedEnterpriseHookWatchDirs(exclusiveFiles)
	run.WatchSharedFiles = sortedEnterpriseHookWatchDirs(sharedFiles)
	runEnterpriseHookStandaloneForeignCleanup(ctx, os.Stderr, time.Now(), enterpriseHookPerUserEnrolled(manifest, machinePolicy))
	return run, nil
}

// enterpriseHookCredentialKeyID names the per-user credential key a
// reconcile rendered from; a seam for tests, whose minter reads no key.
var enterpriseHookCredentialKeyID = currentEnterpriseHookUserTokenKeyID

// writeEnterpriseHookCredentialAttestation publishes what this reconcile did
// to each enabled target (enterprisehooks.CredentialAttestation), root-only
// next to the ledger. When this run persisted the ledger and the rest of its
// state (bound), the record is bound to the ledger bytes in place; an
// unbound record is never taken as current readiness. It runs under the
// reconcile lock, which a credential rotation also takes to stage or commit
// a key, so neither the key nor the ledger can change between rendering the
// targets and naming them here.
func writeEnterpriseHookCredentialAttestation(
	manifestSHA256 string,
	rows []enterpriseHookReconcileRow,
	slots map[int]enterpriseHookStandaloneSlot,
	verified map[int]bool,
	bound bool,
) error {
	keyID, err := enterpriseHookCredentialKeyID(cfg.DataDir)
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	attestation := enterprisehooks.CredentialAttestation{
		Version:        enterprisehooks.CredentialAttestationVersion,
		ID:             hex.EncodeToString(id),
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		ManifestSHA256: manifestSHA256,
		KeyID:          keyID,
		Targets:        make([]enterprisehooks.CredentialAttestationTarget, 0, len(rows)),
	}
	// Name the rotation this run acted under, so the rotation takes only a
	// reconcile of its own phase as proof. The record cannot change while
	// this run holds the reconcile lock.
	if transaction, err := loadEnterpriseHookCredentialTransaction(cfg.DataDir); err == nil && transaction != nil {
		attestation.OperationID, attestation.Phase = transaction.OperationID, transaction.Phase
	} else if err != nil {
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: ignoring the credential transaction record: %v\n", err)
	}
	ledgerPath := managed.HookGuardianAuthorizationPath(cfg.DataDir)
	if info, err := os.Lstat(ledgerPath); bound && err == nil {
		if ledger, err := readEnterpriseHookBoundedFile(ledgerPath, info, enterprisehooks.CredentialAttestationMaxBytes, "hook guardian authorization"); err == nil {
			sum := sha256.Sum256(ledger)
			attestation.AuthorizationSHA256 = hex.EncodeToString(sum[:])
		}
	}
	for index, row := range rows {
		target := enterprisehooks.CredentialAttestationTarget{
			Connector: row.Connector,
			User:      row.User,
			UserHome:  row.UserHome,
			UID:       -1,
			State:     enterprisehooks.CredentialTargetFailed,
		}
		if row.UID > 0 {
			target.UID = row.UID
		}
		switch {
		case row.Pending:
			target.State = enterprisehooks.CredentialTargetPending
		case row.OK:
			target.State = enterprisehooks.CredentialTargetCurrent
			if slot, dispatched := slots[index]; dispatched && keyID != "" {
				target.UID = slot.account.UID
				target.Credentials = true
				target.Verified = verified[index]
				target.CredentialID = slot.credentialID
			}
		}
		attestation.Targets = append(attestation.Targets, target)
	}
	data, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(managed.HookGuardianAuthorizationDir(cfg.DataDir), managed.HookGuardianCredentialAttestationFile)
	if err := writeEnterpriseHookProtectedFile(path, append(data, '\n')); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func enterpriseHookListenAddrs() (string, string) {
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	return apiAddr, proxyAddr
}

// enterpriseHookInstallTarget routes the single-target install through the
// worker for the standalone profile, with the same hook socket transport and
// per-user credentials the guardian's reconcile renders.
func enterpriseHookInstallTarget(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
	if !enterpriseHooksStandaloneUnixActive() {
		return enterprisehooks.Install(ctx, opts)
	}
	account, err := enterpriseHookStandaloneInstallAccount(opts)
	if err != nil {
		return enterprisehooks.InstallResult{}, err
	}
	opts.UserHome, opts.OwnerUID, opts.OwnerGID = account.Home, account.UID, account.GID
	hookSocket, serviceUID, err := enterpriseHookStandaloneHookTransport()
	if err != nil {
		return enterprisehooks.InstallResult{}, err
	}
	identity := strconv.Itoa(account.UID)
	token, otlpToken, err := enterpriseHookUserTokenMinter(cfg.DataDir, opts.ConnectorName, identity)
	if err != nil {
		return enterprisehooks.InstallResult{}, err
	}
	opts.APIToken, opts.OTLPPathToken = token, otlpToken
	opts.ManagedHookSocket, opts.ManagedServiceUID = hookSocket, serviceUID
	opts.HookCredentialIdentity = identity
	target := enterpriseHookWorkerTarget{Index: 0, Mode: enterpriseHookWorkerModeInstall, PreviouslyProtected: opts.AllowMissingHookConfigRepair, Options: enterpriseHookWorkerOptionsFrom(opts)}
	outcomes := dispatchEnterpriseHookStandaloneJobs(ctx, map[int]*enterpriseHookWorkerJob{
		account.UID: {Account: account, Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true, Targets: []enterpriseHookWorkerTarget{target}}},
	})
	outcome := outcomes[0]
	switch {
	case outcome.ok:
		return *outcome.result, nil
	case outcome.pending:
		return enterprisehooks.InstallResult{}, fmt.Errorf("enterprise hooks: %s is not available right now; retry later", account.Home)
	default:
		return enterprisehooks.InstallResult{}, errors.New(firstNonEmpty(outcome.err, errEnterpriseHookWorkerNoResult.Error()))
	}
}

func enterpriseHookStandaloneInstallAccount(opts enterprisehooks.InstallOptions) (enterpriseHookWorkerAccount, error) {
	home := filepath.Clean(strings.TrimSpace(opts.UserHome))
	uid, gid := opts.OwnerUID, opts.OwnerGID
	var err error
	if uid < 0 {
		if uid, err = enterpriseHookHomeOwner(home); err != nil {
			return enterpriseHookWorkerAccount{}, err
		}
	}
	name := strconv.Itoa(uid)
	account, lookupErr := enterprisehooks.StandaloneResolver().LookupUID(uid)
	if lookupErr == nil {
		name = account.Name
	}
	if gid < 0 {
		if lookupErr != nil {
			return enterpriseHookWorkerAccount{}, fmt.Errorf("enterprise hooks: resolve uid %d: %w", uid, lookupErr)
		}
		gid = account.GID
	}
	if uid <= 0 {
		return enterpriseHookWorkerAccount{}, fmt.Errorf("enterprise hooks: refusing to target uid %d", uid)
	}
	if check := enterpriseHookCheckHome(home, uid); check.State != enterprisehooks.HomeAvailable {
		return enterpriseHookWorkerAccount{}, errors.New("enterprise hooks: " + check.Reason)
	}
	return enterpriseHookWorkerAccount{UID: uid, GID: gid, User: name, Home: home}, nil
}

// writeEnterpriseHookStandaloneGuardianStateOrLog writes the .state file
// inside the root-owned authorization directory, where the standalone
// gateway reads it through its group.
func writeEnterpriseHookStandaloneGuardianStateOrLog(w io.Writer, state string) {
	dir := managed.HookGuardianAuthorizationDir(cfg.DataDir)
	path := guardianstate.PathForPlatform(true, cfg.DataDir, dir)
	err := ensureEnterpriseHookStandaloneAuthDir(dir)
	if err == nil {
		err = guardianstate.WriteState(path, state)
	}
	if err == nil {
		err = os.Chmod(path, 0o640)
	}
	if err == nil {
		err = enterpriseHookAuthorizationOwnershipSetter(path)
	}
	if err != nil {
		fmt.Fprintf(w, "[hook-guardian] warn: could not write %s state file %s: %v\n", state, path, err)
	}
}

// enterpriseHookStandaloneServiceUser is the gateway account that reads
// the guardian's records: DEFENSECLAW_UNIX_SERVICE_ACCOUNT when packaging
// sets it (the same override the runtime trust checks honor), else the
// standalone layout's account.
func enterpriseHookStandaloneServiceUser() string {
	if name := strings.TrimSpace(os.Getenv(managed.UnixServiceAccountEnv)); name != "" {
		return name
	}
	if runtime.GOOS == "darwin" {
		return managed.StandaloneDarwinServiceUser
	}
	return managed.StandaloneLinuxServiceUser
}

// enterpriseHookStandaloneConfigFingerprint hashes the managed config so
// the watcher can exit (0) and let the service manager restart it with a
// changed config. It is empty outside the standalone profile.
func enterpriseHookStandaloneConfigFingerprint() string {
	if !enterpriseHooksStandaloneUnixActive() || strings.TrimSpace(cfg.ConfigFilePath) == "" {
		return ""
	}
	file, err := os.Open(cfg.ConfigFilePath)
	if err != nil {
		return ""
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, 8<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// enterpriseHookStandaloneConfigValidator is replaceable in tests.
var enterpriseHookStandaloneConfigValidator = func(path string) error {
	_, _, err := loadGatewayConfigV8(path)
	return err
}

// enterpriseHookStandaloneConfigChanged reports a changed config that
// still loads. An invalid edit is logged and ignored so a typo cannot stop
// repair.
func enterpriseHookStandaloneConfigChanged(startup string, w io.Writer) bool {
	if startup == "" || !enterpriseHooksStandaloneUnixActive() {
		return false
	}
	current := enterpriseHookStandaloneConfigFingerprint()
	if current == "" || current == startup {
		return false
	}
	if err := enterpriseHookStandaloneConfigValidator(cfg.ConfigFilePath); err != nil {
		fmt.Fprintf(w, "[hook-guardian] managed config changed but does not load; keeping the running config: %v\n", err)
		return false
	}
	fmt.Fprintf(w, "[hook-guardian] managed config changed; exiting so the service manager restarts the guardian with it\n")
	return true
}

// enterpriseHookStandaloneConfigRefresh is the Windows in-place config
// reload; the Unix guardian exits on a changed config instead
// (enterpriseHookStandaloneConfigChanged).
func enterpriseHookStandaloneConfigRefresh(io.Writer) {}

// enterpriseHookStandaloneHookTransport returns the gateway's unix hook socket
// and service uid from the root-owned runtime descriptor. Per-user hooks and
// in-agent plugins use only that peer-authorized socket: a descriptor that
// cannot be read or names no socket is an error, never a TCP fallback.
// Replaced in tests.
var enterpriseHookStandaloneHookTransport = func() (string, int, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return "", 0, fmt.Errorf("enterprise hooks: standalone layout: %w", err)
	}
	descriptor, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath)
	if err != nil {
		return "", 0, fmt.Errorf("enterprise hooks: the runtime descriptor that names the hook socket is unavailable: %w", err)
	}
	return standaloneHookTransportFromDescriptor(descriptor)
}

func standaloneHookTransportFromDescriptor(descriptor *managed.RuntimeDescriptor) (string, int, error) {
	if descriptor == nil {
		return "", 0, errors.New("enterprise hooks: the runtime descriptor is unavailable")
	}
	socket := strings.TrimSpace(descriptor.HookSocket)
	if socket == "" || !filepath.IsAbs(socket) {
		return "", 0, errors.New("enterprise hooks: the runtime descriptor names no hook socket; per-user hooks have no TCP fallback")
	}
	if descriptor.ServiceUID < 0 {
		return filepath.Clean(socket), 0, nil
	}
	return filepath.Clean(socket), descriptor.ServiceUID, nil
}

// enterpriseHookStandaloneMachinePolicySet names the connectors the
// lifecycle published through vendor machine policy, from the root-owned
// runtime descriptor. Replaced in tests.
var enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} {
	out := map[string]struct{}{}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return out
	}
	descriptor, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath)
	if err != nil {
		return out
	}
	for _, name := range descriptor.MachinePolicyConnectors {
		out[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	return out
}

// enterpriseHookStandaloneMachinePolicyCovered reports whether the
// DefenseClaw entries of connector machine policy are in place. Replaced
// in tests.
var enterpriseHookStandaloneMachinePolicyCovered = func(connectorName string) (bool, error) {
	opts, ok := standaloneMachinePolicyOptions(runtime.GOOS)
	if !ok {
		return false, errors.New("no standalone layout for this platform")
	}
	return enterprisepolicy.MachinePolicyPresent(opts, connectorName)
}

// hookGuardianRepairsFile lists the targets the last standalone Unix
// reconcile rewrote because they no longer verified, which the lifecycle's
// repair reports. It is its own file: the state and authorization files keep
// the schema a prior binary reads strictly.
const hookGuardianRepairsFile = "hook_guardian_repairs.json"

type enterpriseHookGuardianRepair struct {
	User      string `json:"user"`
	Connector string `json:"connector"`
}

// writeEnterpriseHookGuardianRepairs records this reconcile's repairs, if
// any, before its state report; a reconcile that repaired nothing keeps the
// last record, which the lifecycle reads only when it is newer than its
// change. It is best effort: only the repair report reads it.
func writeEnterpriseHookGuardianRepairs(dataDir string, repaired []enterpriseHookGuardianRepair) {
	if len(repaired) == 0 {
		return
	}
	data, err := json.Marshal(struct {
		UpdatedAt string                         `json:"updated_at"`
		Repaired  []enterpriseHookGuardianRepair `json:"repaired"`
	}{time.Now().UTC().Format(time.RFC3339Nano), repaired})
	if err != nil || strings.TrimSpace(dataDir) == "" {
		return
	}
	path := filepath.Join(dataDir, hookGuardianRepairsFile)
	if err := writeEnterpriseHookProtectedFile(path, append(data, '\n')); err != nil {
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: record repaired targets: %v\n", err)
	}
}
