// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsCopilotManagedStateFile = ".defenseclaw-managed-copilot.state"
	windowsCopilotManagedLockFile  = ".defenseclaw-managed-copilot.lock"
	windowsCopilotManagedLimit     = 4 << 20
)

var windowsCopilotManagedRootResolver = defaultWindowsCopilotManagedRoot

type WindowsCopilotManagedRuntimeTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

// WindowsCopilotManagedPolicyTeardownOptions authenticates the exact
// machine-policy enrollment owned by one installer lifecycle transaction.
type WindowsCopilotManagedPolicyTeardownOptions struct {
	HookExecutable     string
	GatewayAddr        string
	GatewayServiceName string
	Targets            []WindowsCopilotManagedRuntimeTarget
}

// WindowsCopilotManagedPolicyTeardownSnapshot is rollback material. It is
// serialized only inside the protected installer journal.
type WindowsCopilotManagedPolicyTeardownSnapshot struct {
	PolicyExisted bool   `json:"policy_existed"`
	Policy        []byte `json:"policy,omitempty"`
	StateExisted  bool   `json:"state_existed"`
	State         []byte `json:"state,omitempty"`
}

type windowsCopilotManagedPolicyState struct {
	SchemaVersion      int                                  `json:"schema_version"`
	PolicySHA256       string                               `json:"policy_sha256"`
	HookExecutable     string                               `json:"hook_executable"`
	GatewayAddr        string                               `json:"gateway_addr"`
	GatewayServiceName string                               `json:"gateway_service_name"`
	Targets            []WindowsCopilotManagedRuntimeTarget `json:"targets"`
}

type windowsCopilotManagedPaths struct {
	Root   string
	Policy string
	State  string
	Lock   string
}

type windowsCopilotManagedPolicyTarget struct {
	dataDir            string
	hookExecutable     string
	gatewayAddr        string
	gatewayServiceName string
	targetSID          *windows.SID
	registered         bool
	active             bool
}

func defaultWindowsCopilotManagedRoot() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData for Copilot: %w", err)
	}
	return filepath.Join(programData, "GitHub", "Copilot", "policy.d"), nil
}

func windowsCopilotManagedPathsResolve() (windowsCopilotManagedPaths, error) {
	root, err := windowsCopilotManagedRootResolver()
	if err != nil {
		return windowsCopilotManagedPaths{}, err
	}
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || !strings.EqualFold(filepath.Base(root), "policy.d") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(root)), "Copilot") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(filepath.Dir(root))), "GitHub") {
		return windowsCopilotManagedPaths{}, fmt.Errorf("enterprise hooks: refusing noncanonical Copilot policy root: %s", root)
	}
	return windowsCopilotManagedPaths{
		Root:   root,
		Policy: filepath.Join(root, connector.CopilotEnterprisePolicyFileName),
		State:  filepath.Join(root, windowsCopilotManagedStateFile),
		Lock:   filepath.Join(root, windowsCopilotManagedLockFile),
	}, nil
}

func withWindowsCopilotManagedTransaction(fn func() error) error {
	paths, err := windowsCopilotManagedPathsResolve()
	if err != nil {
		return err
	}
	if err := ensureWindowsManagedPolicyDirectory(paths.Root); err != nil {
		return err
	}
	if err := rejectWindowsReparseChain(paths.Root); err != nil {
		return err
	}
	deadline := time.Now().Add(windowsClaudeManagedLockTimeout)
	for {
		lock, lockErr := openWindowsClaudeManagedPolicyLockFile(paths.Lock)
		if lockErr == nil {
			defer windows.CloseHandle(lock)
			if err := setWindowsManagedPolicyProtection(paths.Lock, false, false); err != nil {
				return fmt.Errorf("enterprise hooks: harden Copilot policy lock: %w", err)
			}
			if err := windowsManagedPolicyFileTrustCheck(paths.Lock); err != nil {
				return fmt.Errorf("enterprise hooks: verify Copilot policy lock: %w", err)
			}
			return fn()
		}
		if !errors.Is(lockErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("enterprise hooks: acquire Copilot policy lock: %w", lockErr)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("enterprise hooks: timed out waiting for Copilot policy lock")
		}
		time.Sleep(windowsClaudeManagedLockRetry)
	}
}

func canonicalWindowsCopilotTargets(targets []WindowsCopilotManagedRuntimeTarget) ([]WindowsCopilotManagedRuntimeTarget, error) {
	result := make([]WindowsCopilotManagedRuntimeTarget, 0, len(targets))
	seen := make(map[string]string, len(targets))
	for _, target := range targets {
		sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
		if err != nil || sid == nil {
			return nil, errors.New("enterprise hooks: Copilot managed target has an invalid SID")
		}
		dataDir := filepath.Clean(strings.TrimSpace(target.DataDir))
		if !filepath.IsAbs(dataDir) || dataDir == "." {
			return nil, errors.New("enterprise hooks: Copilot managed target has a noncanonical data directory")
		}
		key := strings.ToUpper(sid.String())
		if previous, duplicate := seen[key]; duplicate {
			if !sameWindowsEnterprisePath(previous, dataDir) {
				return nil, errors.New("enterprise hooks: Copilot managed target SID is bound to multiple runtime directories")
			}
			continue
		}
		seen[key] = dataDir
		result = append(result, WindowsCopilotManagedRuntimeTarget{SID: sid.String(), DataDir: dataDir})
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToUpper(result[i].SID) < strings.ToUpper(result[j].SID) })
	return result, nil
}

func renderWindowsCopilotManagedState(state windowsCopilotManagedPolicyState) ([]byte, error) {
	targets, err := canonicalWindowsCopilotTargets(state.Targets)
	if err != nil {
		return nil, err
	}
	state.Targets = targets
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func readWindowsCopilotManagedState(paths windowsCopilotManagedPaths) (windowsManagedFileSnapshot, windowsManagedFileSnapshot, windowsCopilotManagedPolicyState, error) {
	policy, err := snapshotWindowsManagedFileWithLimit(paths.Policy, windowsCopilotManagedLimit)
	if err != nil {
		return policy, windowsManagedFileSnapshot{}, windowsCopilotManagedPolicyState{}, err
	}
	state, err := snapshotWindowsManagedFileWithLimit(paths.State, windowsCopilotManagedLimit)
	if err != nil {
		return policy, state, windowsCopilotManagedPolicyState{}, err
	}
	if policy.existed != state.existed {
		return policy, state, windowsCopilotManagedPolicyState{}, errors.New("enterprise hooks: Copilot managed policy/state pair is incomplete")
	}
	if !policy.existed {
		return policy, state, windowsCopilotManagedPolicyState{}, nil
	}
	for _, path := range []string{paths.Policy, paths.State} {
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return policy, state, windowsCopilotManagedPolicyState{}, fmt.Errorf("enterprise hooks: Copilot managed artifact is untrusted: %w", err)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(state.data))
	decoder.DisallowUnknownFields()
	var parsed windowsCopilotManagedPolicyState
	if err := decoder.Decode(&parsed); err != nil {
		return policy, state, parsed, fmt.Errorf("enterprise hooks: parse Copilot managed state: %w", err)
	}
	if parsed.SchemaVersion != 1 || parsed.PolicySHA256 != windowsManagedPolicyDigest(policy.data) {
		return policy, state, parsed, errors.New("enterprise hooks: Copilot managed state does not authenticate the policy")
	}
	if !filepath.IsAbs(parsed.HookExecutable) || filepath.Clean(parsed.HookExecutable) != parsed.HookExecutable {
		return policy, state, parsed, errors.New("enterprise hooks: Copilot managed state has a noncanonical hook executable")
	}
	addr, err := connector.NormalizeWindowsManagedGatewayAddr(parsed.GatewayAddr)
	if err != nil || addr != parsed.GatewayAddr {
		return policy, state, parsed, errors.New("enterprise hooks: Copilot managed state has an invalid gateway address")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(parsed.GatewayServiceName); err != nil {
		return policy, state, parsed, fmt.Errorf("enterprise hooks: Copilot managed state has an invalid gateway service: %w", err)
	}
	canonical, err := canonicalWindowsCopilotTargets(parsed.Targets)
	if err != nil || !equalWindowsCopilotTargets(canonical, parsed.Targets) {
		return policy, state, parsed, errors.New("enterprise hooks: Copilot managed targets are noncanonical")
	}
	provider := connector.NewCopilotEnterpriseConnector()
	setup := connector.SetupOpts{
		ManagedEnterprise: true,
		AgentVersion:      connector.CopilotEnterpriseMinVersion,
		HookContractID:    connector.CopilotEnterpriseHookContractID,
		HookExecutable:    parsed.HookExecutable,
	}
	if err := provider.VerifyManagedHookPolicy(policy.data, setup); err != nil {
		return policy, state, parsed, fmt.Errorf("enterprise hooks: verify Copilot managed policy: %w", err)
	}
	return policy, state, parsed, nil
}

func equalWindowsCopilotTargets(left, right []WindowsCopilotManagedRuntimeTarget) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index].SID, right[index].SID) || !sameWindowsEnterprisePath(left[index].DataDir, right[index].DataDir) {
			return false
		}
	}
	return true
}

// recoverWindowsCopilotMissingPolicyUnlocked completes the only publication
// asymmetry intentionally produced by this implementation: a protected state
// sidecar may be durable before the public machine policy after a process
// crash. The sidecar must authenticate the exact policy bytes, deployment
// identity, and current target before the policy name is published.
//
// The caller must hold the Copilot managed transaction lock.
func recoverWindowsCopilotMissingPolicyUnlocked(
	paths windowsCopilotManagedPaths,
	setup connector.SetupOpts,
	targetSID *windows.SID,
	dataDir string,
	policyBody []byte,
) error {
	policy, err := snapshotWindowsManagedFileWithLimit(paths.Policy, windowsCopilotManagedLimit)
	if err != nil {
		return err
	}
	state, err := snapshotWindowsManagedFileWithLimit(paths.State, windowsCopilotManagedLimit)
	if err != nil {
		return err
	}
	if policy.existed || !state.existed {
		return nil
	}
	if targetSID == nil {
		return errors.New("enterprise hooks: Copilot recovery target SID is unavailable")
	}
	if err := windowsManagedPolicyFileTrustCheck(paths.State); err != nil {
		return fmt.Errorf("enterprise hooks: Copilot recovery state is untrusted: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(state.data))
	decoder.DisallowUnknownFields()
	var parsed windowsCopilotManagedPolicyState
	if err := decoder.Decode(&parsed); err != nil {
		return fmt.Errorf("enterprise hooks: parse Copilot recovery state: %w", err)
	}
	canonical, err := canonicalWindowsCopilotTargets(parsed.Targets)
	if err != nil || !equalWindowsCopilotTargets(canonical, parsed.Targets) {
		return errors.New("enterprise hooks: Copilot recovery targets are noncanonical")
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if parsed.SchemaVersion != 1 ||
		parsed.PolicySHA256 != windowsManagedPolicyDigest(policyBody) ||
		!sameWindowsEnterprisePath(parsed.HookExecutable, setup.HookExecutable) ||
		parsed.GatewayAddr != setup.APIAddr ||
		!strings.EqualFold(parsed.GatewayServiceName, gatewayServiceName) {
		return errors.New("enterprise hooks: Copilot recovery state belongs to another policy or gateway deployment")
	}
	targetPresent := false
	for _, target := range parsed.Targets {
		if strings.EqualFold(target.SID, targetSID.String()) &&
			sameWindowsEnterprisePath(target.DataDir, dataDir) {
			targetPresent = true
			break
		}
	}
	if !targetPresent {
		return errors.New("enterprise hooks: Copilot recovery state does not contain the current target")
	}
	provider := connector.NewCopilotEnterpriseConnector()
	if err := provider.VerifyManagedHookPolicy(policyBody, setup); err != nil {
		return fmt.Errorf("enterprise hooks: verify Copilot recovery policy: %w", err)
	}
	if err := windowsManagedPolicyWriter(paths.Policy, policyBody, true); err != nil {
		return fmt.Errorf("enterprise hooks: complete Copilot policy publication: %w", err)
	}
	_, _, _, err = readWindowsCopilotManagedState(paths)
	return err
}

func installWindowsCopilotManagedPolicy(setup connector.SetupOpts, targetSID *windows.SID, dataDir string) (func() error, error) {
	if targetSID == nil {
		return nil, errors.New("enterprise hooks: Copilot managed target SID is unavailable")
	}
	provider := connector.NewCopilotEnterpriseConnector()
	policyBody, err := provider.ManagedHookPolicy(setup)
	if err != nil {
		return nil, err
	}
	var rollback func() error
	err = withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		if err := recoverWindowsCopilotMissingPolicyUnlocked(
			paths,
			setup,
			targetSID,
			dataDir,
			policyBody,
		); err != nil {
			return err
		}
		beforePolicy, beforeState, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if beforePolicy.existed {
			if !sameWindowsEnterprisePath(parsed.HookExecutable, setup.HookExecutable) || parsed.GatewayAddr != setup.APIAddr {
				return errors.New("enterprise hooks: existing Copilot policy belongs to a different executable or gateway")
			}
			if !strings.EqualFold(parsed.GatewayServiceName, os.Getenv(connector.WindowsGatewayServiceNameEnv)) {
				return errors.New("enterprise hooks: existing Copilot policy belongs to a different gateway service")
			}
		}
		parsed.SchemaVersion = 1
		parsed.PolicySHA256 = windowsManagedPolicyDigest(policyBody)
		parsed.HookExecutable = filepath.Clean(setup.HookExecutable)
		parsed.GatewayAddr = setup.APIAddr
		parsed.GatewayServiceName = os.Getenv(connector.WindowsGatewayServiceNameEnv)
		parsed.Targets = append(parsed.Targets, WindowsCopilotManagedRuntimeTarget{SID: targetSID.String(), DataDir: filepath.Clean(dataDir)})
		stateBody, err := renderWindowsCopilotManagedState(parsed)
		if err != nil {
			return err
		}
		// Publish the protected enrollment state before the machine-wide policy.
		// On a first install this keeps Copilot from observing an active hook
		// policy before the caller SID can be resolved to its prepared runtime.
		if err := windowsManagedPolicyWriter(paths.State, stateBody, false); err != nil {
			return err
		}
		if err := windowsManagedPolicyWriter(paths.Policy, policyBody, true); err != nil {
			_ = restoreWindowsManagedFile(beforeState)
			return err
		}
		rollback = func() error {
			return withWindowsCopilotManagedTransaction(func() error {
				currentPolicy, currentState, _, err := readWindowsCopilotManagedState(paths)
				if err != nil {
					return err
				}
				if !currentPolicy.existed || !currentState.existed || !bytes.Equal(currentPolicy.data, policyBody) || !bytes.Equal(currentState.data, stateBody) {
					return errors.New("enterprise hooks: refusing Copilot policy rollback after a concurrent change")
				}
				return errors.Join(restoreWindowsManagedFile(beforePolicy), restoreWindowsManagedFile(beforeState))
			})
		}
		return nil
	})
	return rollback, err
}

func ReadWindowsCopilotManagedPolicyTargets() ([]WindowsCopilotManagedRuntimeTarget, bool, error) {
	var targets []WindowsCopilotManagedRuntimeTarget
	active := false
	err := withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, _, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		active = true
		targets = append([]WindowsCopilotManagedRuntimeTarget(nil), parsed.Targets...)
		return nil
	})
	return targets, active, err
}

func removeWindowsCopilotManagedPolicyTarget(targetSID *windows.SID) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: Copilot managed target SID is unavailable")
	}
	return withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, state, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		kept := make([]WindowsCopilotManagedRuntimeTarget, 0, len(parsed.Targets))
		removed := false
		for _, target := range parsed.Targets {
			if strings.EqualFold(target.SID, targetSID.String()) {
				removed = true
				continue
			}
			kept = append(kept, target)
		}
		if !removed {
			return nil
		}
		if len(kept) == 0 {
			if err := os.Remove(paths.Policy); err != nil {
				return fmt.Errorf("enterprise hooks: remove Copilot managed policy: %w", err)
			}
			if err := os.Remove(paths.State); err != nil {
				_ = restoreWindowsManagedFile(policy)
				return fmt.Errorf("enterprise hooks: remove Copilot managed state: %w", err)
			}
			return nil
		}
		parsed.Targets = kept
		body, err := renderWindowsCopilotManagedState(parsed)
		if err != nil {
			return err
		}
		if err := windowsManagedPolicyWriter(paths.State, body, false); err != nil {
			_ = restoreWindowsManagedFile(state)
			return err
		}
		return nil
	})
}

func validateWindowsCopilotManagedPolicyTeardownOptions(
	opts WindowsCopilotManagedPolicyTeardownOptions,
) ([]WindowsCopilotManagedRuntimeTarget, error) {
	if !filepath.IsAbs(strings.TrimSpace(opts.HookExecutable)) ||
		filepath.Clean(opts.HookExecutable) != opts.HookExecutable {
		return nil, errors.New("enterprise hooks: Copilot teardown hook executable is noncanonical")
	}
	addr, err := connector.NormalizeWindowsManagedGatewayAddr(opts.GatewayAddr)
	if err != nil || addr != opts.GatewayAddr {
		return nil, errors.New("enterprise hooks: Copilot teardown gateway address is noncanonical")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(opts.GatewayServiceName); err != nil {
		return nil, err
	}
	return canonicalWindowsCopilotTargets(opts.Targets)
}

func windowsCopilotManagedStateMatchesOptions(
	state windowsCopilotManagedPolicyState,
	opts WindowsCopilotManagedPolicyTeardownOptions,
	expected []WindowsCopilotManagedRuntimeTarget,
) error {
	if !sameWindowsEnterprisePath(state.HookExecutable, opts.HookExecutable) ||
		state.GatewayAddr != opts.GatewayAddr ||
		!strings.EqualFold(state.GatewayServiceName, opts.GatewayServiceName) ||
		!equalWindowsCopilotTargets(state.Targets, expected) {
		return errors.New("enterprise hooks: Copilot machine enrollment does not match the protected transaction")
	}
	return nil
}

func CaptureWindowsCopilotManagedPolicySnapshot(
	opts WindowsCopilotManagedPolicyTeardownOptions,
) (WindowsCopilotManagedPolicyTeardownSnapshot, error) {
	var result WindowsCopilotManagedPolicyTeardownSnapshot
	expected, err := validateWindowsCopilotManagedPolicyTeardownOptions(opts)
	if err != nil {
		return result, err
	}
	err = withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, state, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			if len(expected) != 0 {
				return errors.New("enterprise hooks: expected Copilot managed policy is absent")
			}
			return nil
		}
		if err := windowsCopilotManagedStateMatchesOptions(parsed, opts, expected); err != nil {
			return err
		}
		result = WindowsCopilotManagedPolicyTeardownSnapshot{
			PolicyExisted: true,
			Policy:        append([]byte(nil), policy.data...),
			StateExisted:  true,
			State:         append([]byte(nil), state.data...),
		}
		return nil
	})
	return result, err
}

func PrepareWindowsCopilotManagedPolicyTeardown(
	opts WindowsCopilotManagedPolicyTeardownOptions,
	persist func(WindowsCopilotManagedPolicyTeardownSnapshot) error,
) (WindowsCopilotManagedPolicyTeardownSnapshot, error) {
	var captured WindowsCopilotManagedPolicyTeardownSnapshot
	if persist == nil {
		return captured, errors.New("enterprise hooks: Copilot teardown requires protected journal publication")
	}
	expected, err := validateWindowsCopilotManagedPolicyTeardownOptions(opts)
	if err != nil {
		return captured, err
	}
	err = withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, state, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			if len(expected) != 0 {
				return errors.New("enterprise hooks: expected Copilot managed policy is absent during teardown")
			}
			return persist(captured)
		}
		if err := windowsCopilotManagedStateMatchesOptions(parsed, opts, expected); err != nil {
			return err
		}
		captured = WindowsCopilotManagedPolicyTeardownSnapshot{
			PolicyExisted: true, Policy: append([]byte(nil), policy.data...),
			StateExisted: true, State: append([]byte(nil), state.data...),
		}
		if err := persist(captured); err != nil {
			return err
		}
		if err := os.Remove(paths.Policy); err != nil {
			return err
		}
		if err := os.Remove(paths.State); err != nil {
			_ = restoreWindowsManagedFile(policy)
			return err
		}
		return nil
	})
	return captured, err
}

func RestoreWindowsCopilotManagedPolicyTeardown(
	opts WindowsCopilotManagedPolicyTeardownOptions,
	snapshot WindowsCopilotManagedPolicyTeardownSnapshot,
) error {
	expected, err := validateWindowsCopilotManagedPolicyTeardownOptions(opts)
	if err != nil {
		return err
	}
	if snapshot.PolicyExisted != snapshot.StateExisted {
		return errors.New("enterprise hooks: incomplete Copilot managed teardown snapshot")
	}
	if !snapshot.PolicyExisted {
		if len(expected) != 0 || len(snapshot.Policy) != 0 || len(snapshot.State) != 0 {
			return errors.New("enterprise hooks: invalid empty Copilot managed teardown snapshot")
		}
		return VerifyWindowsCopilotManagedPolicyTeardown()
	}
	if len(snapshot.Policy) == 0 || len(snapshot.Policy) > windowsCopilotManagedLimit ||
		len(snapshot.State) == 0 || len(snapshot.State) > windowsCopilotManagedLimit {
		return errors.New("enterprise hooks: Copilot teardown snapshot exceeds bounded limits")
	}
	var parsed windowsCopilotManagedPolicyState
	decoder := json.NewDecoder(bytes.NewReader(snapshot.State))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	if parsed.PolicySHA256 != windowsManagedPolicyDigest(snapshot.Policy) {
		return errors.New("enterprise hooks: Copilot teardown snapshot digest mismatch")
	}
	if err := windowsCopilotManagedStateMatchesOptions(parsed, opts, expected); err != nil {
		return err
	}
	return withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, state, _, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if policy.existed {
			if bytes.Equal(policy.data, snapshot.Policy) && bytes.Equal(state.data, snapshot.State) {
				return nil
			}
			return errors.New("enterprise hooks: refusing Copilot rollback over a concurrent policy")
		}
		if err := windowsManagedPolicyWriter(paths.State, snapshot.State, false); err != nil {
			return err
		}
		if err := windowsManagedPolicyWriter(paths.Policy, snapshot.Policy, true); err != nil {
			_ = os.Remove(paths.State)
			return err
		}
		_, _, _, err = readWindowsCopilotManagedState(paths)
		return err
	})
}

// RestoreWindowsCopilotManagedPolicySnapshot replaces an authenticated
// current enrollment with an authenticated prior enrollment. It is used only
// for compensating a failed lifecycle transaction.
func RestoreWindowsCopilotManagedPolicySnapshot(
	priorOpts WindowsCopilotManagedPolicyTeardownOptions,
	currentOpts WindowsCopilotManagedPolicyTeardownOptions,
	snapshot WindowsCopilotManagedPolicyTeardownSnapshot,
) error {
	priorTargets, err := validateWindowsCopilotManagedPolicyTeardownOptions(priorOpts)
	if err != nil {
		return err
	}
	currentTargets, err := validateWindowsCopilotManagedPolicyTeardownOptions(currentOpts)
	if err != nil {
		return err
	}
	if !sameWindowsEnterprisePath(priorOpts.HookExecutable, currentOpts.HookExecutable) ||
		priorOpts.GatewayAddr != currentOpts.GatewayAddr ||
		!strings.EqualFold(priorOpts.GatewayServiceName, currentOpts.GatewayServiceName) {
		return errors.New("enterprise hooks: Copilot lifecycle snapshot changed the protected gateway identity")
	}
	if snapshot.PolicyExisted != snapshot.StateExisted ||
		(snapshot.PolicyExisted && (len(snapshot.Policy) == 0 || len(snapshot.State) == 0)) {
		return errors.New("enterprise hooks: invalid Copilot lifecycle snapshot")
	}
	if snapshot.PolicyExisted {
		var prior windowsCopilotManagedPolicyState
		decoder := json.NewDecoder(bytes.NewReader(snapshot.State))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&prior); err != nil {
			return err
		}
		if prior.PolicySHA256 != windowsManagedPolicyDigest(snapshot.Policy) {
			return errors.New("enterprise hooks: Copilot lifecycle snapshot digest mismatch")
		}
		if err := windowsCopilotManagedStateMatchesOptions(prior, priorOpts, priorTargets); err != nil {
			return err
		}
	} else if len(priorTargets) != 0 {
		return errors.New("enterprise hooks: empty Copilot lifecycle snapshot has prior targets")
	}
	return withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, state, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if policy.existed {
			if err := windowsCopilotManagedStateMatchesOptions(parsed, currentOpts, currentTargets); err != nil {
				return err
			}
		} else if len(currentTargets) != 0 {
			return errors.New("enterprise hooks: expected current Copilot policy is absent")
		}
		if policy.existed == snapshot.PolicyExisted &&
			state.existed == snapshot.StateExisted &&
			bytes.Equal(policy.data, snapshot.Policy) &&
			bytes.Equal(state.data, snapshot.State) {
			return nil
		}
		rollback := func(cause error) error {
			var failures []string
			for _, prior := range []windowsManagedFileSnapshot{state, policy} {
				if restoreErr := restoreWindowsManagedFile(prior); restoreErr != nil {
					failures = append(failures, restoreErr.Error())
				}
			}
			if len(failures) != 0 {
				return fmt.Errorf(
					"%v (Copilot lifecycle snapshot rollback failed: %s)",
					cause,
					strings.Join(failures, "; "),
				)
			}
			return cause
		}
		// Remove the policy first so a concurrent Copilot process cannot
		// observe an unauthenticated or mixed-generation replacement.
		if err := os.Remove(paths.Policy); err != nil && !errors.Is(err, os.ErrNotExist) {
			return rollback(err)
		}
		if err := os.Remove(paths.State); err != nil && !errors.Is(err, os.ErrNotExist) {
			return rollback(err)
		}
		if !snapshot.PolicyExisted {
			return nil
		}
		if err := windowsManagedPolicyWriter(paths.State, snapshot.State, false); err != nil {
			return rollback(err)
		}
		if err := windowsManagedPolicyWriter(paths.Policy, snapshot.Policy, true); err != nil {
			return rollback(err)
		}
		if _, _, _, err = readWindowsCopilotManagedState(paths); err != nil {
			return rollback(err)
		}
		return nil
	})
}

func VerifyWindowsCopilotManagedPolicyTeardown() error {
	return withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		for _, path := range []string{paths.Policy, paths.State} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				if err == nil {
					return fmt.Errorf("enterprise hooks: Copilot managed artifact survives teardown: %s", path)
				}
				return err
			}
		}
		return nil
	})
}

func verifyWindowsCopilotManagedPolicyTarget(setup connector.SetupOpts, targetSID *windows.SID, dataDir string) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: Copilot managed target SID is unavailable")
	}
	if err := windowsEnterpriseHookTrustCheck(setup.HookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Copilot machine-policy hook executable is untrusted: %w", err)
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return err
	}
	return withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, _, state, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			return errors.New("enterprise hooks: Copilot enterprise policy is inactive")
		}
		if !sameWindowsEnterprisePath(state.HookExecutable, setup.HookExecutable) ||
			state.GatewayAddr != setup.APIAddr ||
			!strings.EqualFold(state.GatewayServiceName, gatewayServiceName) {
			return errors.New("enterprise hooks: Copilot machine policy belongs to another protected gateway deployment")
		}
		for _, target := range state.Targets {
			if strings.EqualFold(target.SID, targetSID.String()) && sameWindowsEnterprisePath(target.DataDir, dataDir) {
				return nil
			}
		}
		return errors.New("enterprise hooks: Copilot target is absent from the protected machine enrollment")
	})
}

func resolveWindowsCopilotManagedPolicyTarget() (windowsCopilotManagedPolicyTarget, error) {
	var result windowsCopilotManagedPolicyTarget
	err := withWindowsCopilotManagedTransaction(func() error {
		paths, err := windowsCopilotManagedPathsResolve()
		if err != nil {
			return err
		}
		policy, _, parsed, err := readWindowsCopilotManagedState(paths)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		result.active = true
		result.hookExecutable = parsed.HookExecutable
		result.gatewayAddr = parsed.GatewayAddr
		result.gatewayServiceName = parsed.GatewayServiceName
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user == nil || user.User.Sid == nil {
			return errors.New("enterprise hooks: resolve current SID for Copilot managed policy")
		}
		result.targetSID = user.User.Sid
		for _, target := range parsed.Targets {
			if strings.EqualFold(target.SID, result.targetSID.String()) {
				result.dataDir = target.DataDir
				result.registered = true
				break
			}
		}
		return nil
	})
	return result, err
}
