// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// The per-user enrollment is the primary machine registration for a
// standalone per-user connector: the administrator-owned, user-readable list
// of SIDs whose hook invocations the gateway accepts. It plays the role the
// vendor machine policy plays for Codex, Claude Code and Cursor. The runtime
// generation selector beside it only augments this enrollment and can never
// enroll a user by itself.
const (
	windowsPerUserManagedRuntimeParent       = "hook-runtime"
	windowsPerUserManagedEnrollmentFile      = "enrollment.json"
	windowsPerUserManagedEnrollmentLockFile  = ".defenseclaw-enrollment.lock"
	windowsPerUserManagedEnrollmentSchema    = 1
	windowsPerUserManagedEnrollmentMaxBytes  = 1 << 20
	windowsPerUserManagedEnrollmentMaxTarget = 1024
)

var (
	windowsPerUserManagedRuntimeDirResolver = defaultWindowsPerUserManagedRuntimeDir
	windowsPerUserManagedEnrollmentLockWait = 10 * time.Second
)

type windowsPerUserManagedEnrollment struct {
	SchemaVersion  int                                     `json:"schema_version"`
	Connector      string                                  `json:"connector"`
	HookExecutable string                                  `json:"hook_executable"`
	Targets        []windowsPerUserManagedEnrollmentTarget `json:"targets"`
}

type windowsPerUserManagedEnrollmentTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

// RegisterWindowsStandalonePerUserConnectors adds the built-in per-user
// connectors to registry when, and only when, this process serves the
// standalone profile. Secure Client registries are unchanged.
func RegisterWindowsStandalonePerUserConnectors(registry *connector.Registry) {
	if registry == nil || !windowsEnterpriseStandaloneProcess() {
		return
	}
	registry.RegisterBuiltin(connector.NewCopilotConnector())
	registry.RegisterBuiltin(connector.NewAntigravityConnector())
	registry.RegisterBuiltin(connector.NewDevinConnector())
	registry.RegisterBuiltin(connector.NewHermesConnector())
	registry.RegisterBuiltin(connector.NewOpenCodeConnector())
	registry.RegisterBuiltin(connector.NewAMPConnector())
}

// certifyWindowsStandalonePerUserConnector admits a per-user connector only
// in a process pinned to the standalone profile and only as its built-in
// implementation.
func certifyWindowsStandalonePerUserConnector(name string, conn connector.Connector) error {
	if !windowsEnterpriseStandaloneProcess() {
		return fmt.Errorf(
			"enterprise hooks: connector %q is managed on native Windows only by the standalone enterprise profile",
			name,
		)
	}
	if !isWindowsStandalonePerUserBuiltin(name, conn) {
		return fmt.Errorf("enterprise hooks: connector %q is not the certified built-in Windows implementation", name)
	}
	return nil
}

// defaultWindowsPerUserManagedRuntimeDir places the enrollment and selector
// in the standalone hook runtime directory: administrator-written and
// readable by the standard users whose hooks resolve them. The state root
// is not readable by standard users.
func defaultWindowsPerUserManagedRuntimeDir(connectorName string) (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve the standalone hook runtime directory: %w", err)
	}
	return filepath.Join(layout.HookRuntimeDir, connectorName), nil
}

// windowsPerUserManagedRuntimeDir is the machine directory of one per-user
// connector. Plugin connectors never publish an enrollment or selector there;
// resolving their directory lets teardown prove that absence.
func windowsPerUserManagedRuntimeDir(connectorName string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if _, ok := windowsStandalonePerUserConnector(name); !ok || name != connectorName {
		return "", fmt.Errorf("enterprise hooks: %q is not a standalone per-user connector", connectorName)
	}
	directory, err := windowsPerUserManagedRuntimeDirResolver(name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!strings.EqualFold(filepath.Base(directory), name) {
		return "", fmt.Errorf("enterprise hooks: refusing noncanonical per-user runtime directory %s", directory)
	}
	return directory, nil
}

// windowsPerUserManagedRuntimeDirPresent reports whether the connector's
// machine directory exists, without creating it.
func windowsPerUserManagedRuntimeDirPresent(connectorName string) (bool, error) {
	directory, err := windowsPerUserManagedRuntimeDir(connectorName)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect %s enrollment directory: %w", connectorName, err)
	}
	return true, nil
}

func readWindowsPerUserManagedEnrollment(
	connectorName string,
) (windowsPerUserManagedEnrollment, bool, error) {
	var enrollment windowsPerUserManagedEnrollment
	directory, err := windowsPerUserManagedRuntimeDir(connectorName)
	if err != nil {
		return enrollment, false, err
	}
	path := filepath.Join(directory, windowsPerUserManagedEnrollmentFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return enrollment, false, nil
	}
	if err != nil {
		return enrollment, false, fmt.Errorf("enterprise hooks: inspect %s enrollment: %w", connectorName, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > windowsPerUserManagedEnrollmentMaxBytes {
		return enrollment, false, fmt.Errorf("enterprise hooks: %s enrollment is not a bounded regular file", connectorName)
	}
	if err := validateWindowsManagedRuntimeMachineFileProtection(path, true); err != nil {
		return enrollment, false, fmt.Errorf("enterprise hooks: %s enrollment is untrusted: %w", connectorName, err)
	}
	data, err := connector.ReadManagedHookRuntimeFile(
		path,
		"machine-protected per-user connector enrollment",
		windowsPerUserManagedEnrollmentMaxBytes,
	)
	if err != nil {
		return enrollment, false, err
	}
	if err := validateWindowsManagedRuntimeMachineFileProtection(path, true); err != nil {
		return enrollment, false, fmt.Errorf("enterprise hooks: %s enrollment changed protection: %w", connectorName, err)
	}
	enrollment, err = decodeWindowsPerUserManagedEnrollment(data, connectorName)
	if err != nil {
		return windowsPerUserManagedEnrollment{}, false, err
	}
	return enrollment, true, nil
}

func decodeWindowsPerUserManagedEnrollment(
	data []byte,
	connectorName string,
) (windowsPerUserManagedEnrollment, error) {
	var enrollment windowsPerUserManagedEnrollment
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollment); err != nil {
		return enrollment, fmt.Errorf("enterprise hooks: decode %s enrollment: %w", connectorName, err)
	}
	if enrollment.SchemaVersion != windowsPerUserManagedEnrollmentSchema ||
		enrollment.Connector != connectorName {
		return enrollment, fmt.Errorf("enterprise hooks: %s enrollment has an unexpected schema or connector", connectorName)
	}
	if err := validateWindowsManagedRuntimeGenerationPath(enrollment.HookExecutable, ""); err != nil ||
		!strings.EqualFold(filepath.Ext(enrollment.HookExecutable), ".exe") {
		return enrollment, fmt.Errorf("enterprise hooks: %s enrollment hook executable is invalid", connectorName)
	}
	if len(enrollment.Targets) == 0 || len(enrollment.Targets) > windowsPerUserManagedEnrollmentMaxTarget {
		return enrollment, fmt.Errorf("enterprise hooks: %s enrollment target count is invalid", connectorName)
	}
	seen := make(map[string]struct{}, len(enrollment.Targets))
	for _, target := range enrollment.Targets {
		sid, err := validateWindowsEnterpriseTargetSID(target.SID)
		if err != nil || sid.String() != target.SID {
			return enrollment, fmt.Errorf("enterprise hooks: %s enrollment SID is not canonical", connectorName)
		}
		if err := validateWindowsManagedRuntimeGenerationPath(target.DataDir, ".defenseclaw"); err != nil {
			return enrollment, fmt.Errorf("enterprise hooks: %s enrollment data directory is invalid: %w", connectorName, err)
		}
		key := strings.ToUpper(target.SID)
		if _, duplicate := seen[key]; duplicate {
			return enrollment, fmt.Errorf("enterprise hooks: %s enrollment repeats SID %s", connectorName, target.SID)
		}
		seen[key] = struct{}{}
	}
	return enrollment, nil
}

func marshalWindowsPerUserManagedEnrollment(enrollment windowsPerUserManagedEnrollment) ([]byte, error) {
	sort.Slice(enrollment.Targets, func(left, right int) bool {
		return enrollment.Targets[left].SID < enrollment.Targets[right].SID
	})
	data, err := json.MarshalIndent(enrollment, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// updateWindowsPerUserManagedEnrollment rewrites one connector's enrollment
// under its machine lock. An empty result removes the file, so a host with no
// enrolled user carries no active per-user policy for that connector.
func updateWindowsPerUserManagedEnrollment(
	connectorName string,
	hookExecutable string,
	mutate func([]windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget,
) error {
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	directory, err := windowsPerUserManagedRuntimeDir(connectorName)
	if err != nil {
		return err
	}
	if err := ensureWindowsManagedPolicyDirectory(directory); err != nil {
		return fmt.Errorf("enterprise hooks: prepare %s enrollment directory: %w", connectorName, err)
	}
	return withWindowsPerUserManagedEnrollmentLock(directory, func() error {
		current, exists, err := readWindowsPerUserManagedEnrollment(connectorName)
		if err != nil {
			return err
		}
		if exists && !sameWindowsEnterprisePath(current.HookExecutable, hookExecutable) {
			return fmt.Errorf(
				"enterprise hooks: %s enrollment belongs to hook executable %s, not %s",
				connectorName,
				current.HookExecutable,
				hookExecutable,
			)
		}
		next := mutate(append([]windowsPerUserManagedEnrollmentTarget(nil), current.Targets...))
		path := filepath.Join(directory, windowsPerUserManagedEnrollmentFile)
		if len(next) == 0 {
			if !exists {
				return nil
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("enterprise hooks: remove empty %s enrollment: %w", connectorName, err)
			}
			return nil
		}
		data, err := marshalWindowsPerUserManagedEnrollment(windowsPerUserManagedEnrollment{
			SchemaVersion:  windowsPerUserManagedEnrollmentSchema,
			Connector:      connectorName,
			HookExecutable: hookExecutable,
			Targets:        next,
		})
		if err != nil {
			return err
		}
		if _, err := decodeWindowsPerUserManagedEnrollment(data, connectorName); err != nil {
			return err
		}
		return writeWindowsManagedFile(path, data, true)
	})
}

func withWindowsPerUserManagedEnrollmentLock(directory string, fn func() error) error {
	if err := rejectWindowsReparseChain(directory); err != nil {
		return err
	}
	if err := windowsManagedPolicyDirTrustCheck(directory); err != nil {
		return fmt.Errorf("enterprise hooks: per-user enrollment directory is untrusted: %w", err)
	}
	lockPath := filepath.Join(directory, windowsPerUserManagedEnrollmentLockFile)
	if info, statErr := os.Lstat(lockPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("enterprise hooks: per-user enrollment lock is not a regular file")
		}
		if err := validateWindowsManagedRuntimeMachineFileProtection(lockPath, false); err != nil {
			return fmt.Errorf("enterprise hooks: per-user enrollment lock is untrusted: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	deadline := time.Now().Add(windowsPerUserManagedEnrollmentLockWait)
	for {
		lock, lockErr := openWindowsClaudeManagedPolicyLockFile(lockPath)
		if lockErr == nil {
			defer windows.CloseHandle(lock)
			if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
				return fmt.Errorf("enterprise hooks: harden per-user enrollment lock: %w", err)
			}
			return fn()
		}
		if !errors.Is(lockErr, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("enterprise hooks: acquire per-user enrollment lock: %w", lockErr)
		}
		if !time.Now().Before(deadline) {
			return errors.New("enterprise hooks: timed out waiting for the per-user enrollment lock")
		}
		time.Sleep(windowsManagedRuntimeSelectorLockRetry)
	}
}

func windowsPerUserManagedEnrollmentTargetForSID(
	enrollment windowsPerUserManagedEnrollment,
	sid string,
) (windowsPerUserManagedEnrollmentTarget, bool) {
	for _, target := range enrollment.Targets {
		if strings.EqualFold(target.SID, sid) {
			return target, true
		}
	}
	return windowsPerUserManagedEnrollmentTarget{}, false
}

// resolveWindowsPerUserManagedHookRuntime selects the administrator-authorized
// runtime for the calling user's SID. No target-owned file is trusted before
// the machine enrollment names this SID and the protected generation for it
// resolves.
func resolveWindowsPerUserManagedHookRuntime(
	hookExecutable string,
	connectorName string,
) (WindowsManagedHookRuntime, error) {
	result := WindowsManagedHookRuntime{Connector: connectorName}
	enrollment, exists, err := readWindowsPerUserManagedEnrollment(connectorName)
	if err != nil {
		result.PolicyActive = true
		return result, err
	}
	if !exists {
		return result, nil
	}
	result.PolicyActive = true
	if !sameWindowsEnterprisePath(enrollment.HookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"enterprise hooks: invoking hook executable %s does not match the %s enrollment executable %s",
			hookExecutable,
			connectorName,
			enrollment.HookExecutable,
		)
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return result, fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", err)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return result, errors.New("enterprise hooks: current Windows hook token has no user SID")
	}
	currentSID := tokenUser.User.Sid.String()
	target, ok := windowsPerUserManagedEnrollmentTargetForSID(enrollment, currentSID)
	if !ok {
		return result, fmt.Errorf(
			"%s: connector %s current SID %s is absent from the protected target set",
			WindowsManagedSIDUnregisteredReason,
			connectorName,
			currentSID,
		)
	}
	result.DataDir = target.DataDir
	generation, err := windowsManagedRuntimeGenerationResolve(
		WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               connectorName,
			TargetSID:               currentSID,
			DataDir:                 target.DataDir,
			HookExecutable:          hookExecutable,
			MachinePolicyRegistered: true,
		},
	)
	if err != nil {
		return result, err
	}
	result.GatewayAddr = generation.GatewayAddr
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.Registered = true
	return result, nil
}

// prepareWindowsPerUserManagedGeneration runs inside the target-SID
// impersonation, after the per-user footprint is hardened and verified, and
// prepares the immutable runtime generation the hook will resolve. Plugin
// connectors do not execute the hook binary and get none.
func prepareWindowsPerUserManagedGeneration(
	target windowsGenericManagedTarget,
	contractID string,
) (WindowsManagedRuntimeGenerationPublication, bool, error) {
	name := target.conn.Name()
	hookBinary, ok := windowsStandalonePerUserConnector(name)
	if !ok || !hookBinary {
		return WindowsManagedRuntimeGenerationPublication{}, false, nil
	}
	lockUpdatedAt, entryUpdatedAt, err := connector.ManagedHookContractTimestamps(target.dataDir, name)
	if err != nil {
		return WindowsManagedRuntimeGenerationPublication{}, true, fmt.Errorf(
			"enterprise hooks: load protected %s hook contract recovery state: %w", name, err,
		)
	}
	publication, err := prepareWindowsManagedRuntimeGenerationForInstall(
		name,
		target.sid,
		target.dataDir,
		target.hookExecutable,
		target.setup.APIAddr,
		target.setup.HookAPIToken,
		contractID,
		lockUpdatedAt,
		entryUpdatedAt,
	)
	if err != nil {
		return WindowsManagedRuntimeGenerationPublication{}, true, fmt.Errorf(
			"enterprise hooks: prepare immutable %s runtime generation: %w", name, err,
		)
	}
	return publication, true, nil
}

// commitWindowsPerUserManagedRegistration selects the prepared generation and
// then publishes the SID in the machine enrollment. The SID stays
// unregistered, so direct managed invocation fails closed, until both succeed.
func commitWindowsPerUserManagedRegistration(
	target windowsGenericManagedTarget,
	publication WindowsManagedRuntimeGenerationPublication,
) error {
	name := target.conn.Name()
	commit, err := windowsManagedRuntimeGenerationCommit(publication)
	if err != nil {
		return errors.Join(
			fmt.Errorf("enterprise hooks: select immutable %s runtime generation: %w", name, err),
			discardWindowsManagedRuntimeGeneration(publication),
		)
	}
	sid := target.sid.String()
	if err := updateWindowsPerUserManagedEnrollment(
		name,
		target.hookExecutable,
		func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
			next := make([]windowsPerUserManagedEnrollmentTarget, 0, len(current)+1)
			for _, entry := range current {
				if !strings.EqualFold(entry.SID, sid) {
					next = append(next, entry)
				}
			}
			return append(next, windowsPerUserManagedEnrollmentTarget{SID: sid, DataDir: target.dataDir})
		},
	); err != nil {
		return errors.Join(
			fmt.Errorf("enterprise hooks: publish %s enrollment: %w", name, err),
			rollbackWindowsManagedRuntimeGeneration(commit, publication),
		)
	}
	return nil
}

// verifyWindowsPerUserManagedRegistration proves the machine enrollment names
// this SID and data directory and that the selected generation still matches
// the target's protected runtime.
func verifyWindowsPerUserManagedRegistration(
	target windowsGenericManagedTarget,
	contractID string,
) error {
	name := target.conn.Name()
	hookBinary, ok := windowsStandalonePerUserConnector(name)
	if !ok || !hookBinary {
		return nil
	}
	enrollment, exists, err := readWindowsPerUserManagedEnrollment(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("enterprise hooks: %s enrollment is absent", name)
	}
	if !sameWindowsEnterprisePath(enrollment.HookExecutable, target.hookExecutable) {
		return fmt.Errorf("enterprise hooks: %s enrollment names a different hook executable", name)
	}
	entry, ok := windowsPerUserManagedEnrollmentTargetForSID(enrollment, target.sid.String())
	if !ok || !sameWindowsEnterprisePath(entry.DataDir, target.dataDir) {
		return fmt.Errorf("enterprise hooks: %s enrollment does not name SID %s at %s", name, target.sid, target.dataDir)
	}
	lockUpdatedAt, entryUpdatedAt, err := connector.ManagedHookContractTimestamps(target.dataDir, name)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load protected %s runtime generation timestamps: %w", name, err)
	}
	return verifyWindowsManagedRuntimeGenerationForInstall(
		name,
		target.sid,
		target.dataDir,
		target.hookExecutable,
		target.setup.APIAddr,
		target.setup.HookAPIToken,
		contractID,
		lockUpdatedAt,
		entryUpdatedAt,
	)
}

// revokeWindowsPerUserManagedRegistration removes the SID from the machine
// enrollment first, so its hook fails closed as unregistered, and then retires
// its generation selector entry.
func revokeWindowsPerUserManagedRegistration(
	connectorName string,
	targetSID *windows.SID,
	dataDir string,
	hookExecutable string,
) error {
	hookBinary, ok := windowsStandalonePerUserConnector(connectorName)
	if !ok || !hookBinary {
		return nil
	}
	// The enrollment and the selector share the connector's machine
	// directory. Without it there is nothing to revoke, and revocation (a
	// user removal, or the per-user cleanup after an uninstall retired the
	// enrollment) must not create the directory and its lock file.
	present, err := windowsPerUserManagedRuntimeDirPresent(connectorName)
	if err != nil || !present {
		return err
	}
	sid := targetSID.String()
	if err := updateWindowsPerUserManagedEnrollment(
		connectorName,
		hookExecutable,
		func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
			next := make([]windowsPerUserManagedEnrollmentTarget, 0, len(current))
			for _, entry := range current {
				if !strings.EqualFold(entry.SID, sid) {
					next = append(next, entry)
				}
			}
			return next
		},
	); err != nil {
		return fmt.Errorf("enterprise hooks: revoke %s enrollment for %s: %w", connectorName, sid, err)
	}
	commit, err := RemoveWindowsManagedRuntimeGenerationEnrollment(
		WindowsManagedRuntimeGenerationRemovalOptions{
			Connector:                connectorName,
			TargetSID:                sid,
			DataDir:                  dataDir,
			HookExecutable:           hookExecutable,
			PrimaryEnrollmentRemoved: true,
		},
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: remove %s runtime selector target %s: %w", connectorName, sid, err)
	}
	return commit.Finalize()
}

// windowsEnumeratorHookConnector reports whether the Windows enumerator
// emits rows for name: the machine-policy connectors always, the per-user
// connectors only in a standalone process.
func windowsEnumeratorHookConnector(name string) bool {
	if _, ok := windowsHookConnectors[name]; ok {
		return true
	}
	if _, perUser := windowsStandalonePerUserConnector(name); perUser {
		return windowsEnterpriseStandaloneProcess()
	}
	return false
}

// WindowsPerUserManagedEnrollmentTarget is one secretless enrollment row.
type WindowsPerUserManagedEnrollmentTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

// IsWindowsStandalonePerUserConnector reports whether name is a standalone
// per-user connector and whether its runtime is the hook binary.
func IsWindowsStandalonePerUserConnector(name string) (hookBinary, ok bool) {
	return windowsStandalonePerUserConnector(name)
}

// RemoveWindowsPerUserManagedEnrollments revokes the whole machine enrollment
// of each per-user hook-binary connector. Deployment teardown calls it
// before retiring the connectors' runtime selectors, so every enrolled SID
// fails closed as unregistered from this point.
func RemoveWindowsPerUserManagedEnrollments(hookExecutable string, connectors []string) error {
	for _, name := range connectors {
		if hookBinary, ok := windowsStandalonePerUserConnector(name); !ok || !hookBinary {
			continue
		}
		// A connector that never ran has no directory, so it has no
		// enrollment to revoke. Removal must not create the directory and its
		// lock file on a host that is being cleaned.
		present, err := windowsPerUserManagedRuntimeDirPresent(name)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if err := updateWindowsPerUserManagedEnrollment(
			name,
			hookExecutable,
			func([]windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget { return nil },
		); err != nil {
			return err
		}
	}
	return nil
}

// RestoreWindowsPerUserManagedEnrollment republishes enrollment rows during a
// teardown rollback, merged with any row still present.
func RestoreWindowsPerUserManagedEnrollment(
	connectorName string,
	hookExecutable string,
	targets []WindowsPerUserManagedEnrollmentTarget,
) error {
	if hookBinary, ok := windowsStandalonePerUserConnector(connectorName); !ok || !hookBinary {
		return fmt.Errorf("enterprise hooks: %q has no per-user enrollment", connectorName)
	}
	if len(targets) == 0 {
		return nil
	}
	return updateWindowsPerUserManagedEnrollment(
		connectorName,
		hookExecutable,
		func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
			next := append([]windowsPerUserManagedEnrollmentTarget(nil), current...)
			for _, target := range targets {
				present := false
				for index := range next {
					if strings.EqualFold(next[index].SID, target.SID) {
						next[index].DataDir = target.DataDir
						present = true
					}
				}
				if !present {
					next = append(next, windowsPerUserManagedEnrollmentTarget{SID: target.SID, DataDir: target.DataDir})
				}
			}
			return next
		},
	)
}

// ReadWindowsPerUserManagedEnrollmentTargets returns one connector's enrolled
// rows, or exists=false when the connector has no enrollment.
func ReadWindowsPerUserManagedEnrollmentTargets(
	connectorName string,
) ([]WindowsPerUserManagedEnrollmentTarget, bool, error) {
	if hookBinary, ok := windowsStandalonePerUserConnector(connectorName); !ok || !hookBinary {
		return nil, false, nil
	}
	enrollment, exists, err := readWindowsPerUserManagedEnrollment(connectorName)
	if err != nil || !exists {
		return nil, exists, err
	}
	targets := make([]WindowsPerUserManagedEnrollmentTarget, 0, len(enrollment.Targets))
	for _, target := range enrollment.Targets {
		targets = append(targets, WindowsPerUserManagedEnrollmentTarget{SID: target.SID, DataDir: target.DataDir})
	}
	return targets, true, nil
}

// PruneWindowsPerUserManagedEnrollments revokes enrolled SIDs that the
// current manifest no longer authorizes for each per-user hook-binary
// connector, then retires their runtime selector entries. keep reports
// whether (connector, SID) is still an enabled manifest target.
func PruneWindowsPerUserManagedEnrollments(hookExecutable string, keep func(connectorName, sid string) bool) error {
	var errs []error
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		if hookBinary, _ := windowsStandalonePerUserConnector(name); !hookBinary {
			continue
		}
		enrollment, exists, err := readWindowsPerUserManagedEnrollment(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !exists {
			continue
		}
		var revoked []windowsPerUserManagedEnrollmentTarget
		for _, target := range enrollment.Targets {
			if !keep(name, target.SID) {
				revoked = append(revoked, target)
			}
		}
		if len(revoked) == 0 {
			continue
		}
		if err := updateWindowsPerUserManagedEnrollment(name, enrollment.HookExecutable,
			func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
				next := make([]windowsPerUserManagedEnrollmentTarget, 0, len(current))
				for _, target := range current {
					if keep(name, target.SID) {
						next = append(next, target)
					}
				}
				return next
			}); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, target := range revoked {
			commit, err := RemoveWindowsManagedRuntimeGenerationEnrollment(WindowsManagedRuntimeGenerationRemovalOptions{
				Connector:                name,
				TargetSID:                target.SID,
				DataDir:                  target.DataDir,
				HookExecutable:           enrollment.HookExecutable,
				PrimaryEnrollmentRemoved: true,
			})
			if err == nil {
				err = commit.Finalize()
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("enterprise hooks: retire %s selector for revoked %s: %w", name, target.SID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// WindowsStandaloneProcess reports whether this process serves the
// standalone profile (the protected profile pin in its environment).
func WindowsStandaloneProcess() bool {
	return windowsEnterpriseStandaloneProcess()
}
