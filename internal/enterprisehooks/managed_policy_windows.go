//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsClaudeManagedPolicyFile  = "90-defenseclaw.json"
	windowsClaudeManagedStateFile   = ".defenseclaw-managed-hooks.state"
	windowsClaudeManagedLockFile    = ".defenseclaw-managed-hooks.lock"
	windowsClaudeManagedStateLimit  = 64 << 10
	windowsClaudeManagedPolicyLimit = 4 << 20
)

var (
	windowsClaudeManagedPolicyPathResolver = defaultWindowsClaudeManagedPolicyPath
	windowsClaudeHigherPolicyCheck         = defaultWindowsClaudeHigherPolicyCheck
	windowsManagedPolicyOwnerSID           = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	windowsManagedPolicyDirTrustCheck = func(path string) error {
		return managed.ValidateTrustedRuntimeDir(path, "Claude Code managed policy directory")
	}
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "Claude Code managed policy file")
	}
	windowsManagedPolicyWriter              = writeWindowsManagedFile
	windowsClaudeManagedPolicyTransaction   = withWindowsClaudeManagedPolicyTransaction
	windowsClaudeManagedRuntimeVersionProbe = probeWindowsClaudeManagedRuntimeVersion
	windowsClaudeManagedRuntimeProbeTimeout = 10 * time.Second
	windowsClaudeManagedLockTimeout         = 10 * time.Second
	windowsClaudeManagedLockRetry           = 50 * time.Millisecond
	windowsEnterpriseProfilePathResolver    = func() (string, error) {
		return windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	}
)

type windowsClaudeManagedPolicyState struct {
	SchemaVersion      int      `json:"schema_version"`
	PolicySHA256       string   `json:"policy_sha256"`
	HookExecutable     string   `json:"hook_executable"`
	GatewayAddr        string   `json:"gateway_addr,omitempty"`
	GatewayServiceName string   `json:"gateway_service_name,omitempty"`
	TargetSIDs         []string `json:"target_sids"`
}

type windowsManagedFileSnapshot struct {
	path    string
	existed bool
	data    []byte
}

// WindowsClaudeManagedPolicyTeardownOptions binds the narrow installer
// teardown transaction to the exact policy identity already authenticated by
// the protected deployment. It deliberately has no policy-path field: the
// machine policy location is always resolved from the documented Claude
// enterprise location.
type WindowsClaudeManagedPolicyTeardownOptions struct {
	HookExecutable     string
	GatewayAddr        string
	GatewayServiceName string
	TargetSIDs         []string
}

// WindowsClaudeManagedPolicyTeardownSnapshot contains only the two
// administrator-owned Claude policy artifacts. Per-user DefenseClaw runtime
// is intentionally outside the teardown and rollback transaction.
type WindowsClaudeManagedPolicyTeardownSnapshot struct {
	PolicyExisted bool   `json:"policy_existed"`
	Policy        []byte `json:"policy,omitempty"`
	StateExisted  bool   `json:"state_existed"`
	State         []byte `json:"state,omitempty"`
}

type windowsClaudeManagedPolicyTarget struct {
	dataDir            string
	hookExecutable     string
	gatewayAddr        string
	gatewayServiceName string
	policyPath         string
	policyData         []byte
	targetSID          *windows.SID
	policyExists       bool
	registered         bool
}

// ResolveWindowsClaudeManagedHookRuntime validates the machine-managed hook
// registration for the current interactive SID and returns that user's
// protected DefenseClaw runtime. Once the global policy is active, a SID
// outside the administrator target set is a fail-closed enrollment error.
func ResolveWindowsClaudeManagedHookRuntime(hookExecutable string) (dataDir string, registered bool, err error) {
	runtime, err := resolveWindowsClaudeManagedHookRuntime(hookExecutable)
	if err != nil {
		return runtime.DataDir, false, err
	}
	return runtime.DataDir, runtime.Registered, nil
}

// ReadWindowsClaudeManagedPolicyTargets returns the canonical protected SID
// enrollment set. It never consults a target-owned runtime and treats a clean
// absence of both machine policy artifacts as inactive.
func ReadWindowsClaudeManagedPolicyTargets() ([]string, bool, error) {
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return nil, false, err
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	policyInfo, policyErr := os.Lstat(path)
	stateInfo, stateErr := os.Lstat(statePath)
	if errors.Is(policyErr, os.ErrNotExist) && errors.Is(stateErr, os.ErrNotExist) {
		return nil, false, nil
	}
	if policyErr == nil && (policyInfo.Mode()&os.ModeSymlink != 0 || !policyInfo.Mode().IsRegular()) {
		return nil, false, fmt.Errorf("enterprise hooks: unsafe Claude managed policy path: %s", path)
	}
	if stateErr == nil && (stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.Mode().IsRegular()) {
		return nil, false, fmt.Errorf("enterprise hooks: unsafe Claude managed state path: %s", statePath)
	}
	if policyErr != nil && !errors.Is(policyErr, os.ErrNotExist) {
		return nil, false, policyErr
	}
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, false, stateErr
	}

	var targets []string
	active := false
	err = windowsClaudeManagedPolicyTransaction(func() error {
		policy, err := snapshotWindowsManagedFile(path)
		if err != nil {
			return err
		}
		state, err := snapshotWindowsManagedFile(
			statePath,
		)
		if err != nil {
			return err
		}
		parsed, err := validateExistingWindowsManagedPolicyOwnership(policy, state)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		active = true
		targets = append([]string(nil), parsed.TargetSIDs...)
		return nil
	})
	return targets, active, err
}

// PublishWindowsClaudeManagedPolicyTargets narrows an already active policy to
// an exact canonical set. It cannot enroll a SID that is not already present;
// additions remain the responsibility of the per-target secure Install path,
// which publishes only after runtime verification.
func PublishWindowsClaudeManagedPolicyTargets(rawTargets []string) error {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	targets := []string(nil)
	var err error
	if len(rawTargets) > 0 {
		targets, err = canonicalWindowsClaudeTargetSIDs(rawTargets)
		if err != nil {
			return err
		}
	}
	return windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		policySnapshot, err := snapshotWindowsManagedFile(path)
		if err != nil {
			return err
		}
		stateSnapshot, err := snapshotWindowsManagedFile(statePath)
		if err != nil {
			return err
		}
		state, err := validateExistingWindowsManagedPolicyOwnership(
			policySnapshot,
			stateSnapshot,
		)
		if err != nil {
			return err
		}
		if !policySnapshot.existed {
			if len(targets) == 0 {
				return nil
			}
			return errors.New(
				"enterprise hooks: refusing to enroll Claude targets without an existing verified managed policy",
			)
		}
		if state.SchemaVersion != 2 {
			return errors.New(
				"enterprise hooks: legacy Claude managed policy state must be repaired before exact-set publication",
			)
		}
		existing := make(map[string]struct{}, len(state.TargetSIDs))
		for _, sid := range state.TargetSIDs {
			existing[sid] = struct{}{}
		}
		for _, sid := range targets {
			if _, ok := existing[sid]; !ok {
				return fmt.Errorf(
					"enterprise hooks: refusing to add unverified Claude target SID %s through exact-set publication",
					sid,
				)
			}
		}
		rollback := func(cause error) error {
			var failures []string
			for _, snapshot := range []windowsManagedFileSnapshot{policySnapshot, stateSnapshot} {
				if restoreErr := restoreWindowsManagedFile(snapshot); restoreErr != nil {
					failures = append(failures, restoreErr.Error())
				}
			}
			if len(failures) > 0 {
				return fmt.Errorf("%v (Claude exact-set rollback failed: %s)", cause, strings.Join(failures, "; "))
			}
			return cause
		}
		if len(targets) == 0 {
			if err := os.Remove(path); err != nil {
				return rollback(err)
			}
			if err := os.Remove(statePath); err != nil {
				return rollback(err)
			}
			return nil
		}
		state.TargetSIDs = targets
		body, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		body = append(body, '\n')
		if err := windowsManagedPolicyWriter(statePath, body, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, policySnapshot.data); err != nil {
			return rollback(err)
		}
		return nil
	})
}

// PrepareWindowsClaudeManagedPolicyTeardown authenticates and removes the
// exact Claude machine policy represented by opts. Elevated Administrators
// may invoke this only through the signed installer teardown path; the normal
// per-target Install and repair paths retain their LocalSystem-only gate.
func PrepareWindowsClaudeManagedPolicyTeardown(
	opts WindowsClaudeManagedPolicyTeardownOptions,
	persistJournal func(WindowsClaudeManagedPolicyTeardownSnapshot) error,
) (WindowsClaudeManagedPolicyTeardownSnapshot, error) {
	var result WindowsClaudeManagedPolicyTeardownSnapshot
	if persistJournal == nil {
		return result, errors.New(
			"enterprise hooks: Claude managed teardown requires protected journal publication",
		)
	}
	if err := requireWindowsClaudeTeardownAdministrator(); err != nil {
		return result, err
	}
	expected, err := validateWindowsClaudeManagedPolicyTeardownOptions(opts)
	if err != nil {
		return result, err
	}
	err = windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		policy, err := snapshotWindowsManagedFileWithLimit(
			path,
			windowsClaudeManagedPolicyLimit,
		)
		if err != nil {
			return err
		}
		state, err := snapshotWindowsManagedFileWithLimit(
			statePath,
			windowsClaudeManagedStateLimit,
		)
		if err != nil {
			return err
		}
		parsed, err := validateExistingWindowsManagedPolicyOwnership(policy, state)
		if err != nil {
			return err
		}
		if !policy.existed {
			if len(expected) != 0 {
				return errors.New(
					"enterprise hooks: expected Claude managed policy is absent during teardown",
				)
			}
			return persistJournal(result)
		}
		if err := validateWindowsClaudeManagedPolicyTeardownState(parsed, opts, expected); err != nil {
			return err
		}
		result = WindowsClaudeManagedPolicyTeardownSnapshot{
			PolicyExisted: true,
			Policy:        append([]byte(nil), policy.data...),
			StateExisted:  true,
			State:         append([]byte(nil), state.data...),
		}
		// The caller's protected journal must durably authenticate the
		// preimage before either active machine artifact is removed.
		if err := persistJournal(result); err != nil {
			return fmt.Errorf("persist Claude managed teardown journal: %w", err)
		}
		rollback := func(cause error) error {
			var failures []string
			for _, snapshot := range []windowsManagedFileSnapshot{state, policy} {
				if restoreErr := restoreWindowsManagedFile(snapshot); restoreErr != nil {
					failures = append(failures, restoreErr.Error())
				}
			}
			if len(failures) != 0 {
				return fmt.Errorf(
					"%v (Claude managed teardown rollback failed: %s)",
					cause,
					strings.Join(failures, "; "),
				)
			}
			return cause
		}
		// Removing the active policy first is fail-closed for a concurrent hook:
		// protected state without its policy is never treated as normal mode.
		if err := os.Remove(path); err != nil {
			return rollback(fmt.Errorf("remove Claude managed policy: %w", err))
		}
		if err := os.Remove(statePath); err != nil {
			return rollback(fmt.Errorf("remove Claude managed policy state: %w", err))
		}
		for _, removed := range []string{path, statePath} {
			if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
				if err == nil {
					err = errors.New("artifact still exists")
				}
				return rollback(fmt.Errorf("verify Claude teardown for %s: %w", removed, err))
			}
		}
		return nil
	})
	return result, err
}

// VerifyWindowsClaudeManagedPolicyTeardown is a read-only proof that no
// DefenseClaw-owned Claude machine policy or ownership sidecar remains.
func VerifyWindowsClaudeManagedPolicyTeardown() error {
	if err := requireWindowsClaudeTeardownAdministrator(); err != nil {
		return err
	}
	return windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		for _, candidate := range []string{path, statePath} {
			if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
				if err == nil {
					return fmt.Errorf(
						"enterprise hooks: Claude managed artifact survives teardown: %s",
						candidate,
					)
				}
				return err
			}
		}
		return nil
	})
}

// RestoreWindowsClaudeManagedPolicyTeardown restores only a snapshot that
// authenticates to the exact protected deployment identity and target set.
// It cannot add a connector, change a path, or enroll a different SID.
func RestoreWindowsClaudeManagedPolicyTeardown(
	opts WindowsClaudeManagedPolicyTeardownOptions,
	snapshot WindowsClaudeManagedPolicyTeardownSnapshot,
) error {
	if err := requireWindowsClaudeTeardownAdministrator(); err != nil {
		return err
	}
	expected, err := validateWindowsClaudeManagedPolicyTeardownOptions(opts)
	if err != nil {
		return err
	}
	if snapshot.PolicyExisted != snapshot.StateExisted {
		return errors.New("enterprise hooks: incomplete Claude managed teardown snapshot")
	}
	if !snapshot.PolicyExisted {
		if len(expected) != 0 || len(snapshot.Policy) != 0 || len(snapshot.State) != 0 {
			return errors.New("enterprise hooks: invalid empty Claude managed teardown snapshot")
		}
		return VerifyWindowsClaudeManagedPolicyTeardown()
	}
	if len(snapshot.Policy) == 0 ||
		len(snapshot.Policy) > windowsClaudeManagedPolicyLimit ||
		len(snapshot.State) == 0 ||
		len(snapshot.State) > windowsClaudeManagedStateLimit {
		return errors.New("enterprise hooks: Claude managed teardown snapshot exceeds bounded limits")
	}
	var authenticated windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(snapshot.State, &authenticated); err != nil {
		return fmt.Errorf("enterprise hooks: decode Claude managed teardown snapshot: %w", err)
	}
	if authenticated.PolicySHA256 != windowsManagedPolicyDigest(snapshot.Policy) {
		return errors.New("enterprise hooks: Claude managed teardown snapshot digest mismatch")
	}
	if err := validateWindowsClaudeManagedPolicyTeardownState(authenticated, opts, expected); err != nil {
		return err
	}

	return windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		currentPolicy, err := snapshotWindowsManagedFileWithLimit(
			path,
			windowsClaudeManagedPolicyLimit,
		)
		if err != nil {
			return err
		}
		currentState, err := snapshotWindowsManagedFileWithLimit(
			statePath,
			windowsClaudeManagedStateLimit,
		)
		if err != nil {
			return err
		}
		if currentPolicy.existed || currentState.existed {
			if currentPolicy.existed && currentState.existed &&
				bytes.Equal(currentPolicy.data, snapshot.Policy) &&
				bytes.Equal(currentState.data, snapshot.State) {
				return verifyWindowsClaudeManagedPolicy(path, snapshot.Policy)
			}
			return errors.New(
				"enterprise hooks: refusing Claude teardown rollback over a concurrent machine policy",
			)
		}
		rollback := func(cause error) error {
			_ = os.Remove(path)
			_ = os.Remove(statePath)
			return cause
		}
		// Publish authenticated ownership first. A concurrent hook remains
		// fail-closed until the matching policy arrives.
		if err := windowsManagedPolicyWriter(statePath, snapshot.State, true); err != nil {
			return rollback(err)
		}
		if err := windowsManagedPolicyWriter(path, snapshot.Policy, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, snapshot.Policy); err != nil {
			return rollback(err)
		}
		return nil
	})
}

func validateWindowsClaudeManagedPolicyTeardownOptions(
	opts WindowsClaudeManagedPolicyTeardownOptions,
) ([]string, error) {
	hook := strings.TrimSpace(opts.HookExecutable)
	if hook == "" || !filepath.IsAbs(hook) || filepath.Clean(hook) != hook ||
		!strings.EqualFold(filepath.Base(hook), "defenseclaw-hook.exe") {
		return nil, errors.New(
			"enterprise hooks: Claude teardown requires the exact installed defenseclaw-hook.exe",
		)
	}
	if err := windowsEnterpriseHookTrustCheck(hook); err != nil {
		return nil, fmt.Errorf("enterprise hooks: Claude teardown hook trust check: %w", err)
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(opts.GatewayAddr)
	if err != nil || gatewayAddr != opts.GatewayAddr {
		return nil, errors.New("enterprise hooks: Claude teardown gateway address is not canonical")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(opts.GatewayServiceName); err != nil {
		return nil, err
	}
	// A deployment with no Claude connector rows tears down an empty target
	// set, which reaches only the absent-policy branch. Every other caller
	// canonicalizes the metadata of a policy that exists, where empty means
	// that metadata is corrupt.
	var targets []string
	if len(opts.TargetSIDs) != 0 {
		canonical, err := canonicalWindowsClaudeTargetSIDs(opts.TargetSIDs)
		if err != nil {
			return nil, err
		}
		targets = canonical
	}
	if !equalWindowsClaudeTargetSIDs(opts.TargetSIDs, targets) {
		return nil, errors.New("enterprise hooks: Claude teardown target SIDs are not canonical")
	}
	return targets, nil
}

func validateWindowsClaudeManagedPolicyTeardownState(
	state windowsClaudeManagedPolicyState,
	opts WindowsClaudeManagedPolicyTeardownOptions,
	expected []string,
) error {
	if state.SchemaVersion != 2 ||
		state.HookExecutable != opts.HookExecutable ||
		state.GatewayAddr != opts.GatewayAddr ||
		state.GatewayServiceName != opts.GatewayServiceName ||
		!equalWindowsClaudeTargetSIDs(state.TargetSIDs, expected) {
		return errors.New(
			"enterprise hooks: Claude managed policy does not match the exact teardown identity",
		)
	}
	return nil
}

func requireWindowsClaudeTeardownAdministrator() error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil &&
		user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return errors.New(
		"enterprise hooks: managed policy teardown requires an elevated Administrator or LocalSystem token",
	)
}

// VerifyWindowsClaudeManagedLifecycleRuntime validates the per-user runtime
// claimed by the administrator-owned Claude policy. Lifecycle ownership and
// runtime health are deliberately separate: a damaged runtime must remain
// enterprise-owned so ordinary Setup can report the damage without ever
// downgrading to the per-user connector writer.
func VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, expectedVersion string) error {
	target, err := resolveWindowsClaudeManagedPolicyTarget()
	if err != nil {
		return err
	}
	if !target.policyExists || !target.registered {
		return errors.New("enterprise hooks: no administrator-managed Claude policy owns the current user")
	}
	expected, err := filepath.Abs(strings.TrimSpace(dataDir))
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve expected managed Claude data dir: %w", err)
	}
	if strings.TrimSpace(dataDir) == "" || !sameWindowsEnterprisePath(expected, target.dataDir) {
		return fmt.Errorf(
			"enterprise hooks: managed Claude policy owns data dir %s, not %s",
			target.dataDir,
			dataDir,
		)
	}
	if err := validateWindowsClaudeManagedRuntime(target); err != nil {
		return err
	}
	return validateWindowsClaudeManagedRuntimeVersion(target, expectedVersion)
}

func validateWindowsClaudeManagedRuntime(target windowsClaudeManagedPolicyTarget) error {
	if err := windowsEnterpriseHookTrustCheck(target.hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: current managed hook executable trust check failed: %w", err)
	}
	reg := newWindowsEnterpriseConnectorRegistry()
	conn, ok := reg.Get("claudecode")
	if !ok {
		return errors.New("enterprise hooks: Claude Code connector is unavailable for managed runtime verification")
	}
	provider, ok := conn.(connector.ManagedHookPolicyProvider)
	if !ok {
		return errors.New("enterprise hooks: Claude Code connector has no managed policy verifier")
	}
	opts := connector.SetupOpts{
		DataDir:           target.dataDir,
		ManagedEnterprise: true,
		HookExecutable:    target.hookExecutable,
	}
	if err := provider.VerifyManagedHookPolicy(target.policyData, opts); err != nil {
		return fmt.Errorf("enterprise hooks: current managed policy runtime identity is invalid: %w", err)
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		target.dataDir,
		"claudecode",
		true,
	)
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: load managed Claude hook contract: %w",
			err,
		)
	}
	if lock.Connector != "claudecode" || len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], target.policyPath) {
		return errors.New("enterprise hooks: managed Claude hook contract lock does not identify the active administrator policy")
	}
	hookDir := filepath.Join(target.dataDir, "hooks")
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{target.dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.lock"), false},
		{filepath.Join(hookDir, ".hookcfg.claudecode"), false},
		{filepath.Join(hookDir, ".hook-claudecode.token"), false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json"), false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json.lock"), false},
	} {
		if err := validateWindowsUserPathElement(item.path, target.targetSID, item.dir, item.dir, true); err != nil {
			return fmt.Errorf("enterprise hooks: current managed runtime trust check failed for %s: %w", item.path, err)
		}
		if !item.dir {
			info, err := os.Lstat(item.path)
			if err != nil {
				return fmt.Errorf("enterprise hooks: inspect current managed runtime %s: %w", item.path, err)
			}
			if info.Size() > windowsEnterpriseUserFileMaxBytes {
				return fmt.Errorf(
					"enterprise hooks: current managed runtime %s exceeds %d-byte limit",
					item.path,
					windowsEnterpriseUserFileMaxBytes,
				)
			}
		}
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		target.dataDir,
		target.gatewayAddr,
		"claudecode",
	); err != nil {
		return fmt.Errorf("enterprise hooks: current managed Claude runtime sidecars are invalid: %w", err)
	}
	return nil
}

type windowsClaudeManagedRuntimeVersionReport struct {
	SchemaVersion int    `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit,omitempty"`
	Built         string `json:"built,omitempty"`
}

func validateWindowsClaudeManagedRuntimeVersion(target windowsClaudeManagedPolicyTarget, expectedVersion string) error {
	if expectedVersion == "" || strings.TrimSpace(expectedVersion) != expectedVersion {
		return errors.New("enterprise hooks: required managed Claude runtime version is empty or malformed")
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		target.dataDir,
		"claudecode",
		true,
	)
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: load managed Claude hook contract: %w",
			err,
		)
	}
	if lock.Connector != "claudecode" || len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], target.policyPath) {
		return errors.New("enterprise hooks: managed Claude hook contract lock changed during runtime verification")
	}
	if lock.DefenseClawVersion == "" || strings.TrimSpace(lock.DefenseClawVersion) != lock.DefenseClawVersion {
		return errors.New("enterprise hooks: managed Claude hook contract lock has no valid DefenseClaw runtime version")
	}
	if lock.DefenseClawVersion != expectedVersion {
		return fmt.Errorf(
			"enterprise hooks: managed Claude contract runtime version %q does not match required Setup version %q",
			lock.DefenseClawVersion,
			expectedVersion,
		)
	}
	if !strings.EqualFold(filepath.Base(target.hookExecutable), "defenseclaw-hook.exe") {
		return fmt.Errorf("enterprise hooks: managed Claude policy names a noncanonical hook executable: %s", target.hookExecutable)
	}
	gatewayPath := filepath.Join(filepath.Dir(target.hookExecutable), "defenseclaw-gateway.exe")
	if err := windowsEnterpriseHookTrustCheck(gatewayPath); err != nil {
		return fmt.Errorf("enterprise hooks: managed Claude gateway executable trust check failed: %w", err)
	}
	if err := windowsClaudeManagedRuntimeVersionProbe(gatewayPath, expectedVersion); err != nil {
		return fmt.Errorf("enterprise hooks: managed Claude gateway runtime verification failed: %w", err)
	}
	return nil
}

func probeWindowsClaudeManagedRuntimeVersion(gatewayPath, expectedVersion string) error {
	if expectedVersion == "" || strings.TrimSpace(expectedVersion) != expectedVersion {
		return errors.New("required managed Claude gateway version is empty or malformed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowsClaudeManagedRuntimeProbeTimeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, gatewayPath, "--version-json")
	output, err := processutil.CombinedOutputTree(cmd, false)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("version probe timed out after %s", windowsClaudeManagedRuntimeProbeTimeout)
	}
	if len(output) > windowsClaudeManagedStateLimit {
		return fmt.Errorf("version probe emitted more than %d bytes", windowsClaudeManagedStateLimit)
	}
	if err != nil {
		return fmt.Errorf("version probe exited unsuccessfully: %w: %s", err, strings.TrimSpace(string(output)))
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var report windowsClaudeManagedRuntimeVersionReport
	if err := decoder.Decode(&report); err != nil {
		return fmt.Errorf("decode machine-readable version %q: %w", strings.TrimSpace(string(output)), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("machine-readable version contains trailing content")
	}
	if report.SchemaVersion != 1 || report.Name != "defenseclaw-gateway" {
		return fmt.Errorf("unexpected version identity schema=%d name=%q", report.SchemaVersion, report.Name)
	}
	if report.Version != expectedVersion {
		return fmt.Errorf("reported version %q does not exactly match required Setup version %q", report.Version, expectedVersion)
	}
	return nil
}

// OwnsWindowsClaudeManagedLifecycle reports whether the trusted machine policy
// registers the current interactive SID for the expected per-user runtime.
// It deliberately does not require the mutable per-user runtime files to be
// healthy: once an administrator-owned policy claims the target, only the
// enterprise guardian may install, repair, or remove that connector wiring.
func OwnsWindowsClaudeManagedLifecycle(dataDir string) (bool, error) {
	target, err := resolveWindowsClaudeManagedPolicyTarget()
	if err != nil {
		return false, err
	}
	if !target.policyExists || !target.registered {
		return false, nil
	}
	expected, err := filepath.Abs(strings.TrimSpace(dataDir))
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: resolve expected managed Claude data dir: %w", err)
	}
	if strings.TrimSpace(dataDir) == "" || !sameWindowsEnterprisePath(expected, target.dataDir) {
		return false, fmt.Errorf(
			"enterprise hooks: managed Claude policy owns data dir %s, not %s",
			target.dataDir,
			dataDir,
		)
	}
	return true, nil
}

func resolveWindowsClaudeManagedPolicyTarget() (windowsClaudeManagedPolicyTarget, error) {
	profile, profileErr := windowsEnterpriseProfilePathResolver()
	if profileErr != nil {
		return windowsClaudeManagedPolicyTarget{}, fmt.Errorf("enterprise hooks: resolve current Windows profile: %w", profileErr)
	}
	profile, profileErr = filepath.Abs(profile)
	if profileErr != nil {
		return windowsClaudeManagedPolicyTarget{}, fmt.Errorf("enterprise hooks: resolve current Windows profile path: %w", profileErr)
	}
	profile = filepath.Clean(profile)
	target := windowsClaudeManagedPolicyTarget{dataDir: filepath.Join(profile, ".defenseclaw")}

	policyPath, policyErr := windowsClaudeManagedPolicyPath()
	if policyErr != nil {
		return target, policyErr
	}
	statePath := filepath.Join(filepath.Dir(policyPath), windowsClaudeManagedStateFile)
	policySnapshot, policyErr := snapshotWindowsManagedFile(policyPath)
	if policyErr != nil {
		return target, policyErr
	}
	stateSnapshot, stateErr := snapshotWindowsManagedFile(statePath)
	if stateErr != nil {
		return target, stateErr
	}
	state, ownershipErr := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if ownershipErr != nil {
		return target, ownershipErr
	}
	if !policySnapshot.existed {
		return target, nil
	}
	target.policyExists = true
	target.hookExecutable = state.HookExecutable
	target.policyPath = policyPath
	target.policyData = append([]byte(nil), policySnapshot.data...)
	target.gatewayAddr = state.GatewayAddr
	target.gatewayServiceName = state.GatewayServiceName

	tokenUser, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
	if tokenErr != nil {
		return target, fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", tokenErr)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return target, fmt.Errorf("enterprise hooks: current Windows hook token has no user SID")
	}
	target.targetSID = tokenUser.User.Sid
	for _, rawSID := range state.TargetSIDs {
		if strings.EqualFold(rawSID, target.targetSID.String()) {
			target.registered = true
			break
		}
	}
	if !target.registered {
		return target, nil
	}
	if _, _, err := validateWindowsEnterpriseHome(profile, target.targetSID.String()); err != nil {
		return target, err
	}
	return target, nil
}

func sameWindowsEnterprisePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
}

func windowsClaudeManagedPolicyPath() (string, error) {
	path, err := windowsClaudeManagedPolicyPathResolver()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("enterprise hooks: Claude Code managed policy path is not absolute: %s", path)
	}
	path = filepath.Clean(path)
	if !strings.EqualFold(filepath.Base(path), windowsClaudeManagedPolicyFile) || !strings.EqualFold(filepath.Base(filepath.Dir(path)), "managed-settings.d") {
		return "", fmt.Errorf("enterprise hooks: refusing noncanonical Claude Code managed policy path: %s", path)
	}
	return path, nil
}

func defaultWindowsClaudeManagedPolicyPath() (string, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve Program Files known folder: %w", err)
	}
	return filepath.Join(programFiles, "ClaudeCode", "managed-settings.d", windowsClaudeManagedPolicyFile), nil
}

func defaultWindowsClaudeHigherPolicyCheck() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\ClaudeCode`, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Claude Code HKLM managed policy: %w", err)
	}
	defer key.Close()
	if err := validateWindowsClaudeRegistryPolicyKey(key); err != nil {
		return err
	}
	settings, _, err := key.GetStringValue("Settings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: read Claude Code HKLM Settings policy: %w", err)
	}
	if strings.TrimSpace(settings) != "" {
		return fmt.Errorf("enterprise hooks: Claude Code HKLM Settings policy has higher precedence than file-based policy; deploy the DefenseClaw hook matrix through the existing MDM/GPO source")
	}
	return nil
}

func validateWindowsClaudeRegistryPolicyKey(key registry.Key) error {
	sd, err := windows.GetSecurityInfo(
		windows.Handle(key),
		windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Claude Code HKLM policy key security: %w", err)
	}
	if sd == nil {
		return fmt.Errorf("enterprise hooks: Claude Code HKLM policy key has no security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Claude Code HKLM policy key owner: %w", err)
	}
	if !windowsEnterpriseAdminIdentity(owner) {
		return fmt.Errorf(
			"enterprise hooks: Claude Code HKLM policy key owner %s is not trusted",
			windowsSIDString(owner),
		)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Claude Code HKLM policy key DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("enterprise hooks: Claude Code HKLM policy key has a null DACL")
	}
	return rejectWindowsClaudeRegistryPolicyWriteACEs(`HKLM\SOFTWARE\Policies\ClaudeCode`, dacl)
}

func rejectWindowsClaudeRegistryPolicyWriteACEs(label string, dacl *windows.ACL) error {
	const (
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	writeLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			registry.SET_VALUE |
			registry.CREATE_SUB_KEY |
			registry.CREATE_LINK,
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect Windows registry ACE %d for %s: %w", index, label, err)
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&writeLike == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf(
				"enterprise hooks: unsupported Windows registry allow ACE type 0x%x on %s",
				ace.Header.AceType,
				label,
			)
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windowsEnterpriseAdminIdentity(sid) {
			return fmt.Errorf(
				"enterprise hooks: untrusted Windows principal %s has write-like registry access mask 0x%x on %s",
				windowsSIDString(sid),
				uint32(ace.Mask),
				label,
			)
		}
	}
	return nil
}

func withWindowsClaudeManagedPolicyTransaction(fn func() error) error {
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return err
	}
	policyDir := filepath.Dir(policyPath)
	if err := ensureWindowsManagedPolicyDirectory(policyDir); err != nil {
		return err
	}
	lockPath := filepath.Join(policyDir, windowsClaudeManagedLockFile)
	if info, statErr := os.Lstat(lockPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing non-regular managed policy transaction lock: %s", lockPath)
		}
		if err := windowsManagedPolicyFileTrustCheck(lockPath); err != nil {
			return fmt.Errorf("enterprise hooks: managed policy transaction lock is untrusted: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: inspect managed policy transaction lock: %w", statErr)
	}

	deadline := time.Now().Add(windowsClaudeManagedLockTimeout)
	for {
		lock, lockErr := openWindowsClaudeManagedPolicyLockFile(lockPath)
		if lockErr == nil {
			defer windows.CloseHandle(lock)
			if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
				return fmt.Errorf("enterprise hooks: harden managed policy transaction lock: %w", err)
			}
			if err := windowsManagedPolicyFileTrustCheck(lockPath); err != nil {
				return fmt.Errorf("enterprise hooks: verify managed policy transaction lock: %w", err)
			}
			return fn()
		}
		if lockErr != windows.ERROR_SHARING_VIOLATION && lockErr != windows.ERROR_LOCK_VIOLATION {
			return fmt.Errorf("enterprise hooks: acquire managed policy transaction lock: %w", lockErr)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"enterprise hooks: timed out after %s waiting for managed policy transaction lock",
				windowsClaudeManagedLockTimeout,
			)
		}
		delay := windowsClaudeManagedLockRetry
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

func openWindowsClaudeManagedPolicyLockFile(path string) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN,
		0,
	)
}

func installWindowsClaudeManagedPolicy(body []byte, opts connector.SetupOpts, targetSID *windows.SID) (path string, rollback func() error, err error) {
	var unlockedRollback func() error
	var installedState []byte
	err = windowsClaudeManagedPolicyTransaction(func() error {
		var transactionErr error
		path, unlockedRollback, transactionErr = installWindowsClaudeManagedPolicyUnlocked(body, opts, targetSID)
		if transactionErr == nil {
			installedState, transactionErr = os.ReadFile(filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile))
			if transactionErr != nil && unlockedRollback != nil {
				if rollbackErr := unlockedRollback(); rollbackErr != nil {
					transactionErr = fmt.Errorf("%v (managed policy rollback failed: %v)", transactionErr, rollbackErr)
				}
			}
		}
		return transactionErr
	})
	if err == nil && unlockedRollback != nil {
		rollback = func() error {
			return windowsClaudeManagedPolicyTransaction(func() error {
				currentPolicy, policyErr := os.ReadFile(path)
				currentState, stateErr := os.ReadFile(filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile))
				if policyErr != nil || stateErr != nil || !bytes.Equal(currentPolicy, body) || !bytes.Equal(currentState, installedState) {
					return fmt.Errorf("enterprise hooks: refusing managed policy rollback after a concurrent policy change")
				}
				return unlockedRollback()
			})
		}
	}
	return path, rollback, err
}

func installWindowsClaudeManagedPolicyUnlocked(body []byte, opts connector.SetupOpts, targetSID *windows.SID) (string, func() error, error) {
	if err := windowsClaudeHigherPolicyCheck(); err != nil {
		return "", nil, err
	}
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return "", nil, err
	}
	if err := inspectWindowsClaudeFilePolicyCompatibility(path); err != nil {
		return "", nil, err
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	policySnapshot, err := snapshotWindowsManagedFile(path)
	if err != nil {
		return "", nil, err
	}
	stateSnapshot, err := snapshotWindowsManagedFile(statePath)
	if err != nil {
		return "", nil, err
	}
	recoverMissingPolicy := !policySnapshot.existed && stateSnapshot.existed
	var existingState windowsClaudeManagedPolicyState
	if recoverMissingPolicy {
		existingState, err = validateWindowsClaudeMissingPolicyRecovery(
			body,
			opts,
			targetSID,
			policySnapshot,
			stateSnapshot,
		)
	} else {
		existingState, err = validateExistingWindowsManagedPolicyOwnership(
			policySnapshot,
			stateSnapshot,
		)
	}
	if err != nil {
		return "", nil, err
	}
	policyDir := filepath.Dir(path)
	policyRoot := filepath.Dir(policyDir)
	createdPolicyDir := !windowsPathExists(policyDir)
	createdPolicyRoot := !windowsPathExists(policyRoot)
	removeCreatedDirs := func() {
		if createdPolicyDir {
			_ = os.Remove(policyDir)
		}
		if createdPolicyRoot {
			_ = os.Remove(policyRoot)
		}
	}
	if err := ensureWindowsManagedPolicyDirectory(policyDir); err != nil {
		removeCreatedDirs()
		return "", nil, err
	}

	targets, err := canonicalWindowsClaudeTargetSIDs(
		append(append([]string(nil), existingState.TargetSIDs...), targetSID.String()),
	)
	if err != nil {
		return "", nil, err
	}
	if recoverMissingPolicy &&
		!equalWindowsClaudeTargetSIDs(targets, existingState.TargetSIDs) {
		return "", nil, errors.New(
			"enterprise hooks: missing-policy recovery cannot change Claude target enrollment",
		)
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(opts.APIAddr)
	if err != nil {
		return "", nil, err
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return "", nil, err
	}
	state := windowsClaudeManagedPolicyState{
		SchemaVersion:      2,
		PolicySHA256:       windowsManagedPolicyDigest(body),
		HookExecutable:     filepath.Clean(opts.HookExecutable),
		GatewayAddr:        gatewayAddr,
		GatewayServiceName: gatewayServiceName,
		TargetSIDs:         targets,
	}
	stateBody, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", nil, err
	}
	stateBody = append(stateBody, '\n')

	rollback := func() error {
		var failures []string
		for _, snapshot := range []windowsManagedFileSnapshot{policySnapshot, stateSnapshot} {
			if err := restoreWindowsManagedFile(snapshot); err != nil {
				failures = append(failures, err.Error())
			}
		}
		removeCreatedDirs()
		if len(failures) > 0 {
			return fmt.Errorf("%s", strings.Join(failures, "; "))
		}
		return nil
	}
	if err := windowsManagedPolicyWriter(path, body, true); err != nil {
		_ = rollback()
		return "", nil, err
	}
	// The sidecar contains only integrity metadata and the target SID allow-list.
	// Standard-user hook processes must be able to read it to decide whether the
	// invoking SID is registered; write access remains Administrator/System-only.
	if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
		_ = rollback()
		return "", nil, err
	}
	if err := verifyWindowsClaudeManagedPolicy(path, body); err != nil {
		_ = rollback()
		return "", nil, err
	}
	return path, rollback, nil
}

func removeWindowsClaudeManagedPolicyTarget(targetSID *windows.SID) error {
	return windowsClaudeManagedPolicyTransaction(func() error {
		return removeWindowsClaudeManagedPolicyTargetUnlocked(targetSID)
	})
}

func removeWindowsClaudeManagedPolicyTargetUnlocked(targetSID *windows.SID) error {
	if targetSID == nil {
		return fmt.Errorf("enterprise hooks: target SID is required for managed policy removal")
	}
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return err
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	policySnapshot, err := snapshotWindowsManagedFile(path)
	if err != nil {
		return err
	}
	stateSnapshot, err := snapshotWindowsManagedFile(statePath)
	if err != nil {
		return err
	}
	state, err := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if err != nil {
		return err
	}
	if !policySnapshot.existed {
		return nil
	}

	target := targetSID.String()
	remaining := make([]string, 0, len(state.TargetSIDs))
	found := false
	for _, sid := range state.TargetSIDs {
		if strings.EqualFold(strings.TrimSpace(sid), target) {
			found = true
			continue
		}
		remaining = append(remaining, sid)
	}
	if !found {
		return nil
	}
	remaining = sortedUnique(remaining)

	rollback := func(cause error) error {
		var failures []string
		for _, snapshot := range []windowsManagedFileSnapshot{policySnapshot, stateSnapshot} {
			if restoreErr := restoreWindowsManagedFile(snapshot); restoreErr != nil {
				failures = append(failures, restoreErr.Error())
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("%v (managed policy rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}

	if len(remaining) > 0 {
		state.TargetSIDs = remaining
		stateBody, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		stateBody = append(stateBody, '\n')
		if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, policySnapshot.data); err != nil {
			return rollback(err)
		}
		return nil
	}

	if err := os.Remove(path); err != nil {
		return rollback(fmt.Errorf("enterprise hooks: remove Claude Code managed hook policy: %w", err))
	}
	if err := os.Remove(statePath); err != nil {
		return rollback(fmt.Errorf("enterprise hooks: remove Claude Code managed hook ownership metadata: %w", err))
	}
	for _, removed := range []string{path, statePath} {
		if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("artifact still exists")
			}
			return rollback(fmt.Errorf("enterprise hooks: verify managed policy removal for %s: %w", removed, err))
		}
	}
	return nil
}

func validateExistingWindowsManagedPolicyOwnership(policy, state windowsManagedFileSnapshot) (windowsClaudeManagedPolicyState, error) {
	if policy.existed != state.existed {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata is incomplete; refusing to overwrite %s", policy.path)
	}
	if !policy.existed {
		return windowsClaudeManagedPolicyState{}, nil
	}
	if err := windowsManagedPolicyFileTrustCheck(policy.path); err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	if err := windowsManagedPolicyFileTrustCheck(state.path); err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	var parsed windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(state.data, &parsed); err != nil ||
		(parsed.SchemaVersion != 1 && parsed.SchemaVersion != 2) {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: invalid Claude Code managed policy ownership metadata")
	}
	if parsed.PolicySHA256 != windowsManagedPolicyDigest(policy.data) {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: Claude Code managed policy was changed outside DefenseClaw; refusing to overwrite administrator edits")
	}
	if !filepath.IsAbs(parsed.HookExecutable) || filepath.Clean(parsed.HookExecutable) != parsed.HookExecutable {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: invalid Claude Code managed policy hook executable ownership metadata")
	}
	if parsed.SchemaVersion == 2 {
		gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(parsed.GatewayAddr)
		if err != nil || gatewayAddr != parsed.GatewayAddr {
			return windowsClaudeManagedPolicyState{}, errors.New("enterprise hooks: invalid Claude managed gateway address")
		}
		if err := connector.ValidateWindowsManagedGatewayServiceName(parsed.GatewayServiceName); err != nil {
			return windowsClaudeManagedPolicyState{}, err
		}
	}
	targets, err := canonicalWindowsClaudeTargetSIDs(parsed.TargetSIDs)
	if err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	parsed.TargetSIDs = targets
	return parsed, nil
}

func validateWindowsClaudeMissingPolicyRecovery(
	expectedPolicy []byte,
	opts connector.SetupOpts,
	targetSID *windows.SID,
	policy windowsManagedFileSnapshot,
	state windowsManagedFileSnapshot,
) (windowsClaudeManagedPolicyState, error) {
	if policy.existed || !state.existed {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery requires an absent policy and existing ownership metadata",
		)
	}
	if targetSID == nil {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery requires an exact target SID",
		)
	}
	if err := windowsManagedPolicyFileTrustCheck(state.path); err != nil {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf(
			"enterprise hooks: missing-policy recovery state is untrusted: %w",
			err,
		)
	}
	var parsed windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(state.data, &parsed); err != nil ||
		parsed.SchemaVersion != 2 {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery requires strict schema-v2 ownership metadata",
		)
	}
	canonicalTargets, err := canonicalWindowsClaudeTargetSIDs(parsed.TargetSIDs)
	if err != nil || !equalWindowsClaudeTargetSIDs(parsed.TargetSIDs, canonicalTargets) {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery ownership metadata has a noncanonical target set",
		)
	}
	if parsed.PolicySHA256 != windowsManagedPolicyDigest(expectedPolicy) {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery ownership metadata does not authenticate the freshly rendered policy",
		)
	}
	expectedHook := filepath.Clean(opts.HookExecutable)
	if !filepath.IsAbs(expectedHook) ||
		parsed.HookExecutable != expectedHook {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery hook executable identity mismatch",
		)
	}
	expectedGatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(
		opts.APIAddr,
	)
	if err != nil || parsed.GatewayAddr != expectedGatewayAddr {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery gateway identity mismatch",
		)
	}
	expectedGatewayService := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(
		expectedGatewayService,
	); err != nil ||
		parsed.GatewayServiceName != expectedGatewayService {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery gateway service identity mismatch",
		)
	}
	targetEnrolled := false
	for _, sid := range canonicalTargets {
		if sid == targetSID.String() {
			targetEnrolled = true
			break
		}
	}
	if !targetEnrolled {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery target SID is not already enrolled",
		)
	}
	canonicalState, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	canonicalState = append(canonicalState, '\n')
	if !bytes.Equal(state.data, canonicalState) {
		return windowsClaudeManagedPolicyState{}, errors.New(
			"enterprise hooks: missing-policy recovery ownership metadata is not canonical",
		)
	}
	return parsed, nil
}

func decodeWindowsClaudeManagedPolicyState(data []byte, state *windowsClaudeManagedPolicyState) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func canonicalWindowsClaudeTargetSIDs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata has no target SIDs")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, rawSID := range values {
		sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
		if err != nil || sid == nil || windowsEnterpriseSystemIdentity(sid) {
			return nil, fmt.Errorf(
				"enterprise hooks: invalid target SID %q in Claude Code managed policy ownership metadata",
				rawSID,
			)
		}
		canonical := sid.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func inspectWindowsClaudeFilePolicyCompatibility(policyPath string) error {
	root := filepath.Dir(filepath.Dir(policyPath))
	rootExists, err := validateExistingWindowsManagedPolicyDirectory(root)
	if err != nil {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy root is untrusted: %w", err)
	}
	paths := []string{filepath.Join(root, "managed-settings.json")}
	dropin := filepath.Dir(policyPath)
	dropinExists, err := validateExistingWindowsManagedPolicyDirectory(dropin)
	if err != nil {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy drop-in is untrusted: %w", err)
	}
	if dropinExists {
		entries, readErr := os.ReadDir(dropin)
		if readErr != nil {
			return fmt.Errorf("enterprise hooks: inspect Claude Code managed policy drop-ins: %w", readErr)
		}
		dropins := make([]string, 0, len(entries))
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".json") || strings.EqualFold(name, windowsClaudeManagedPolicyFile) {
				continue
			}
			dropins = append(dropins, filepath.Join(dropin, name))
		}
		sort.Slice(dropins, func(i, j int) bool {
			return strings.ToLower(filepath.Base(dropins[i])) < strings.ToLower(filepath.Base(dropins[j]))
		})
		paths = append(paths, dropins...)
	}
	_ = rootExists
	disableAllHooks := false
	policyHelper := false
	for _, path := range paths {
		data, exists, err := readTrustedWindowsManagedPolicyFile(path)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		settings := map[string]interface{}{}
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("enterprise hooks: parse Claude Code managed policy %s: %w", path, err)
		}
		if raw, exists := settings["disableAllHooks"]; exists {
			value, ok := raw.(bool)
			if !ok {
				return fmt.Errorf("enterprise hooks: Claude Code managed disableAllHooks is not boolean in %s", path)
			}
			disableAllHooks = value
		}
		if raw, exists := settings["policyHelper"]; exists && raw != nil {
			policyHelper = true
		}
	}
	if policyHelper {
		return fmt.Errorf("enterprise hooks: Claude Code policyHelper supersedes file-based managed hooks; add DefenseClaw hooks to the helper output")
	}
	if disableAllHooks {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy disables all hooks")
	}
	return nil
}

func validateExistingWindowsManagedPolicyDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("expected a regular directory: %s", path)
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		return false, err
	}
	if err := windowsManagedPolicyDirTrustCheck(path); err != nil {
		return false, err
	}
	return true, nil
}

func readTrustedWindowsManagedPolicyFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("enterprise hooks: inspect Claude Code managed policy %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("enterprise hooks: refusing non-regular Claude Code managed policy: %s", path)
	}
	if info.Size() > windowsClaudeManagedPolicyLimit {
		return nil, false, fmt.Errorf("enterprise hooks: Claude Code managed policy is too large: %s", path)
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		return nil, false, err
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return nil, false, fmt.Errorf("enterprise hooks: untrusted Claude Code managed policy source %s: %w", path, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("enterprise hooks: open Claude Code managed policy %s: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("enterprise hooks: inspect opened Claude Code managed policy %s: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() > windowsClaudeManagedPolicyLimit {
		return nil, false, fmt.Errorf("enterprise hooks: Claude Code managed policy changed type or exceeds the size limit: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsClaudeManagedPolicyLimit+1))
	if err != nil {
		return nil, false, fmt.Errorf("enterprise hooks: read Claude Code managed policy %s: %w", path, err)
	}
	if len(data) > windowsClaudeManagedPolicyLimit {
		return nil, false, fmt.Errorf("enterprise hooks: Claude Code managed policy is too large: %s", path)
	}
	return data, true, nil
}

func ensureWindowsManagedPolicyDirectory(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve Claude Code managed policy directory: %w", err)
	}
	path = filepath.Clean(absolute)
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	missing := make([]string, 0, 2)
	current := path
	for {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("enterprise hooks: managed policy ancestor is not a regular directory: %s", current)
			}
			// Validate before creating anything. The production trust check
			// validates this directory and its complete existing ancestor chain.
			if err := windowsManagedPolicyDirTrustCheck(current); err != nil {
				return fmt.Errorf("enterprise hooks: managed policy ancestor is untrusted: %w", err)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("enterprise hooks: inspect managed policy ancestor %s: %w", current, statErr)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("enterprise hooks: no existing trusted ancestor for managed policy directory %s", path)
		}
		current = parent
	}
	if len(missing) == 0 {
		return windowsManagedPolicyDirTrustCheck(path)
	}
	attributes, err := windowsManagedPolicyDirectorySecurityAttributes()
	if err != nil {
		return fmt.Errorf("enterprise hooks: build protected managed policy directory ACL: %w", err)
	}
	created := make([]string, 0, len(missing))
	cleanupCreated := func(cause error) error {
		var cleanupErrors []error
		for index := len(created) - 1; index >= 0; index-- {
			if removeErr := os.Remove(created[index]); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove %s: %w", created[index], removeErr))
			}
		}
		if len(cleanupErrors) > 0 {
			return fmt.Errorf("%v (managed policy directory cleanup failed: %v)", cause, errors.Join(cleanupErrors...))
		}
		return cause
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		parent := filepath.Dir(directory)
		if err := rejectWindowsReparseChain(parent); err != nil {
			return cleanupCreated(err)
		}
		if err := windowsManagedPolicyDirTrustCheck(parent); err != nil {
			return cleanupCreated(fmt.Errorf("enterprise hooks: managed policy parent changed trust before creation: %w", err))
		}
		ptr, err := winpath.UTF16Ptr(directory)
		if err != nil {
			return cleanupCreated(err)
		}
		createErr := windows.CreateDirectory(ptr, attributes)
		if createErr == nil {
			created = append(created, directory)
		} else if createErr != windows.ERROR_ALREADY_EXISTS {
			return cleanupCreated(fmt.Errorf("enterprise hooks: create protected managed policy directory %s: %w", directory, createErr))
		}
		if err := rejectWindowsReparseChain(directory); err != nil {
			return cleanupCreated(err)
		}
		if err := windowsManagedPolicyDirTrustCheck(directory); err != nil {
			return cleanupCreated(fmt.Errorf("enterprise hooks: verify managed policy directory %s: %w", directory, err))
		}
	}
	return nil
}

func windowsManagedPolicyDirectorySecurityAttributes() (*windows.SecurityAttributes, error) {
	owner, err := windowsManagedPolicyOwnerSID()
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, fmt.Errorf("enterprise hooks: managed policy directory owner SID is unavailable")
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)(A;OICI;GRGX;;;BU)",
		owner.String(),
		owner.String(),
	))
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func writeWindowsManagedFile(path string, data []byte, userReadable bool) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing non-regular managed policy file: %s", path)
		}
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return err
		}
		if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-policy-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := func() { _ = os.Remove(tempPath) }
	defer cleanup()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := setWindowsManagedPolicyProtection(tempPath, false, userReadable); err != nil {
		return err
	}
	if err := safefile.ReplaceFile(tempPath, path); err != nil {
		return fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
	}
	if err := setWindowsManagedPolicyProtection(path, false, userReadable); err != nil {
		return err
	}
	return windowsManagedPolicyFileTrustCheck(path)
}

func setWindowsManagedPolicyProtection(path string, directory, userReadable bool) error {
	owner, err := windowsManagedPolicyOwnerSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, sid := range []*windows.SID{owner, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	if directory || userReadable {
		permission := windows.ACCESS_MASK(windows.GENERIC_READ)
		if directory {
			permission |= windows.GENERIC_EXECUTE
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: permission,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(users)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func verifyWindowsClaudeManagedPolicy(path string, expected []byte) error {
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("enterprise hooks: persisted Claude Code managed policy bytes differ from the verified render")
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	if err := windowsManagedPolicyFileTrustCheck(statePath); err != nil {
		return err
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var state windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateData, &state); err != nil ||
		state.SchemaVersion != 2 ||
		state.PolicySHA256 != windowsManagedPolicyDigest(data) ||
		!filepath.IsAbs(state.HookExecutable) ||
		filepath.Clean(state.HookExecutable) != state.HookExecutable {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata does not match the policy")
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(state.GatewayAddr)
	if err != nil || gatewayAddr != state.GatewayAddr {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata has an invalid protected gateway address")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(state.GatewayServiceName); err != nil {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata has an invalid protected gateway service: %w", err)
	}
	targets, err := canonicalWindowsClaudeTargetSIDs(state.TargetSIDs)
	if err != nil || !equalWindowsClaudeTargetSIDs(state.TargetSIDs, targets) {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata has noncanonical target SIDs")
	}
	return nil
}

func equalWindowsClaudeTargetSIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func snapshotWindowsManagedFile(path string) (windowsManagedFileSnapshot, error) {
	return snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedStateLimit)
}

func snapshotWindowsManagedFileWithLimit(
	path string,
	limit int,
) (windowsManagedFileSnapshot, error) {
	snapshot := windowsManagedFileSnapshot{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > int64(limit) {
		return snapshot, fmt.Errorf("enterprise hooks: refusing unsafe managed policy artifact: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = true
	snapshot.data = data
	return snapshot, nil
}

func restoreWindowsManagedFile(snapshot windowsManagedFileSnapshot) error {
	if snapshot.existed {
		return writeWindowsManagedFile(snapshot.path, snapshot.data, true)
	}
	if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func windowsManagedPolicyDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func windowsPathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
