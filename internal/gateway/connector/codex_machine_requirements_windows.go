// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const windowsCodexMachineLockTimeout = 10 * time.Second

var (
	windowsCodexMachineProcessMu sync.Mutex

	windowsCodexMachineProgramData = func() (string, error) {
		return windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	}
	windowsCodexMachineTrustedDirCheck = func(path, label string) error {
		return managed.ValidateTrustedRuntimeDir(path, label)
	}
	windowsCodexMachineTrustedFileCheck = func(path, label string) error {
		return managed.ValidateTrustedFilePath(path, label)
	}
	windowsCodexMachineVolumeCheck = validateWindowsCodexMachineVolume
)

type windowsCodexStableFile struct {
	data    []byte
	existed bool
}

// InspectWindowsCodexMachineRequirements reports protected manifest-derived
// applicability without reading, creating, or changing any Codex artifact.
// The hidden lifecycle command performs identity and protected-layout
// validation before calling this helper.
func InspectWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	report := windowsCodexMachineReport("inspect", opts)
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.OK = true
	report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
	if opts.CodexTargetEnabled {
		report.Disposition = "enabled"
	} else {
		report.Disposition = "disabled_noop"
	}
	return report, nil
}

// ReconcileWindowsCodexMachineRequirements merges the exact DefenseClaw
// managed hook matrix into the protected system requirements source. It
// preserves unrelated administrator requirements and writes crash-recovery
// ownership intent before publishing the policy.
func ReconcileWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	if !opts.CodexTargetEnabled {
		present, err := windowsCodexMachineAnyArtifactPathExists(opts)
		if err != nil {
			report := windowsCodexMachineReport("reconcile", opts)
			report.Error = err.Error()
			return report, err
		}
		if !present {
			if err := requireWindowsCodexMachineAdministrator(); err != nil {
				report := windowsCodexMachineReport("reconcile", opts)
				report.Error = err.Error()
				return report, err
			}
			report := windowsCodexMachineReport("reconcile", opts)
			report.OK = true
			report.Disposition = "disabled_noop"
			report.SafeToRemoveBinary = true
			report.ManagedStateRemovedOrAbsent = true
			report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
			return report, nil
		}
		report, err := RemoveWindowsCodexMachineRequirements(opts)
		report.Action = "reconcile"
		report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
		if report.Disposition != "" {
			report.Disposition = "disabled_" + report.Disposition
		}
		return report, err
	}
	report := windowsCodexMachineReport("reconcile", opts)
	err := withWindowsCodexMachineMutation(opts, func() error {
		requirements, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			true,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		ownership, err := readWindowsCodexMachineFile(
			opts.OwnershipPath,
			windowsCodexMachineOwnershipLimit,
			true,
			"Codex requirements ownership",
		)
		if err != nil {
			return err
		}
		managedState, err := readWindowsCodexMachineFile(
			opts.ManagedStatePath,
			windowsCodexManagedStateLimit,
			true,
			"Codex managed runtime state",
		)
		if err != nil {
			return err
		}
		report.RequirementsExisted = requirements.existed
		report.OwnershipExisted = ownership.existed
		report.ManagedStateExisted = managedState.existed

		var state windowsCodexMachineOwnership
		if ownership.existed {
			state, err = parseWindowsCodexMachineOwnership(ownership.data)
			if err != nil {
				return fmt.Errorf("parse Codex requirements ownership: %w", err)
			}
			if err := validateWindowsCodexMachineOwnership(state, opts); err != nil {
				return err
			}
		} else {
			contains, markerErr := windowsCodexRequirementsContainExactManagedHook(requirements.data, opts)
			if markerErr != nil {
				return fmt.Errorf("inspect unowned Codex requirements: %w", markerErr)
			}
			if contains {
				return errors.New("Codex requirements contain an exact DefenseClaw hook without protected ownership metadata")
			}
			if managedState.existed {
				return errors.New("Codex managed runtime state exists without protected requirements ownership")
			}
			state = windowsCodexMachineOwnership{
				SchemaVersion:    windowsCodexMachineRequirementsSchema,
				RequirementsPath: opts.RequirementsPath,
				ManagedDir:       opts.ManagedDir,
				HookBinary:       opts.HookBinary,
				PreimageExisted:  requirements.existed,
				Preimage:         append([]byte(nil), requirements.data...),
				PreimageSHA256:   windowsCodexMachineHash(requirements.data),
			}
		}
		report.PreimageSHA256 = state.PreimageSHA256

		rendered, requirementsChanged, err := reconcileWindowsCodexRequirements(requirements.data, opts)
		if err != nil {
			return err
		}
		postHash := windowsCodexMachineHash(rendered)
		report.PostimageSHA256 = postHash

		var runtimeState windowsCodexManagedRuntimeState
		runtimeStateHealthy := false
		if managedState.existed {
			if parsed, parseErr := parseWindowsCodexManagedRuntimeState(managedState.data); parseErr == nil {
				runtimeState = parsed
				runtimeStateHealthy = validateWindowsCodexManagedRuntimeStateIdentity(runtimeState, opts) == nil
			}
		}
		if !runtimeStateHealthy {
			runtimeState = windowsCodexManagedRuntimeState{
				SchemaVersion:    windowsCodexMachineRequirementsSchema,
				RequirementsPath: opts.RequirementsPath,
				HookExecutable:   opts.HookBinary,
				Targets:          []WindowsCodexManagedRuntimeTarget{},
			}
		}
		runtimeState.RequirementsSHA256 = postHash
		runtimeState.GatewayAddr = opts.GatewayAddr
		runtimeState.GatewayServiceName = opts.GatewayServiceName
		runtimeBytes, err := marshalWindowsCodexManagedRuntimeState(runtimeState)
		if err != nil {
			return err
		}
		runtimeChanged := !managedState.existed || !bytes.Equal(managedState.data, runtimeBytes)

		finalState := state
		finalState.PostimageSHA256 = postHash
		finalState.Pending = false
		finalOwnership, err := marshalWindowsCodexMachineOwnership(finalState)
		if err != nil {
			return fmt.Errorf("marshal final Codex requirements ownership: %w", err)
		}
		ownershipAlreadyFinal := ownership.existed && bytes.Equal(ownership.data, finalOwnership)
		if !requirementsChanged && !runtimeChanged && ownershipAlreadyFinal {
			report.Disposition = "no_change"
			return verifyWindowsCodexMachineRequirementsLocked(opts, nil)
		}

		intent := finalState
		intent.Pending = true
		intentBytes, err := marshalWindowsCodexMachineOwnership(intent)
		if err != nil {
			return fmt.Errorf("marshal pending Codex requirements ownership: %w", err)
		}
		if err := writeWindowsCodexMachineFile(
			opts.OwnershipPath,
			intentBytes,
			windowsCodexMachineOwnershipLimit,
			"Codex requirements ownership",
		); err != nil {
			return err
		}
		if requirementsChanged {
			if err := writeWindowsCodexMachineFile(
				opts.RequirementsPath,
				rendered,
				windowsCodexMachineRequirementsLimit,
				"Codex machine requirements",
			); err != nil {
				return err
			}
		}
		if runtimeChanged {
			if err := writeWindowsCodexMachineFile(
				opts.ManagedStatePath,
				runtimeBytes,
				windowsCodexManagedStateLimit,
				"Codex managed runtime state",
			); err != nil {
				return err
			}
		}
		if err := writeWindowsCodexMachineFile(
			opts.OwnershipPath,
			finalOwnership,
			windowsCodexMachineOwnershipLimit,
			"Codex requirements ownership",
		); err != nil {
			return err
		}

		report.Changed = true
		if !requirements.existed {
			report.Disposition = "created"
		} else {
			report.Disposition = "reconciled"
		}
		return verifyWindowsCodexMachineRequirementsLocked(opts, nil)
	})
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.OK = true
	report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
	return report, nil
}

// VerifyWindowsCodexMachineRequirements performs a bounded, read-only live
// verification of policy bytes, protected ownership, and the adjacent
// non-secret runtime registry.
func VerifyWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	report := windowsCodexMachineReport("verify", opts)
	if !opts.CodexTargetEnabled {
		if err := requireWindowsCodexMachineAdministrator(); err != nil {
			report.Error = err.Error()
			return report, err
		}
		present, err := windowsCodexMachineAnyArtifactPathExists(opts)
		if err != nil {
			report.Error = err.Error()
			return report, err
		}
		if !present {
			report.OK = true
			report.Disposition = "disabled_noop"
			report.SafeToRemoveBinary = true
			report.ManagedStateRemovedOrAbsent = true
			report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
			return report, nil
		}
		err = withWindowsCodexMachineMutation(opts, func() error {
			requirements, readErr := readWindowsCodexMachineFile(
				opts.RequirementsPath,
				windowsCodexMachineRequirementsLimit,
				true,
				"Codex machine requirements",
			)
			if readErr != nil {
				return readErr
			}
			ownership, readErr := readWindowsCodexMachineFile(
				opts.OwnershipPath,
				windowsCodexMachineOwnershipLimit,
				true,
				"Codex requirements ownership",
			)
			if readErr != nil {
				return readErr
			}
			managedState, readErr := readWindowsCodexMachineFile(
				opts.ManagedStatePath,
				windowsCodexManagedStateLimit,
				true,
				"Codex managed runtime state",
			)
			if readErr != nil {
				return readErr
			}
			report.RequirementsExisted = requirements.existed
			report.OwnershipExisted = ownership.existed
			report.ManagedStateExisted = managedState.existed
			contains, markerErr := windowsCodexRequirementsContainExactManagedHook(requirements.data, opts)
			if markerErr != nil {
				return markerErr
			}
			references, referenceErr := windowsCodexOwnedPathReferenceCount(requirements.data, opts)
			if referenceErr != nil {
				return referenceErr
			}
			report.SurvivingOwnedPathReferences = references
			if ownership.existed || managedState.existed || contains || references != 0 {
				return errors.New("Codex is disabled but DefenseClaw-owned Codex machine artifacts remain")
			}
			report.SafeToRemoveBinary = true
			report.ManagedStateRemovedOrAbsent = true
			return nil
		})
		if err != nil {
			report.Error = err.Error()
			return report, err
		}
		report.OK = true
		report.Disposition = "disabled_verified"
		report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
		return report, nil
	}
	err := withWindowsCodexMachineMutation(opts, func() error {
		requirements, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			false,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		ownership, err := readWindowsCodexMachineFile(
			opts.OwnershipPath,
			windowsCodexMachineOwnershipLimit,
			false,
			"Codex requirements ownership",
		)
		if err != nil {
			return err
		}
		managedState, err := readWindowsCodexMachineFile(
			opts.ManagedStatePath,
			windowsCodexManagedStateLimit,
			false,
			"Codex managed runtime state",
		)
		if err != nil {
			return err
		}
		report.RequirementsExisted = requirements.existed
		report.OwnershipExisted = ownership.existed
		report.ManagedStateExisted = managedState.existed

		state, err := parseWindowsCodexMachineOwnership(ownership.data)
		if err != nil {
			return fmt.Errorf("parse Codex requirements ownership: %w", err)
		}
		if err := validateWindowsCodexMachineOwnership(state, opts); err != nil {
			return err
		}
		report.PreimageSHA256 = state.PreimageSHA256
		report.PostimageSHA256 = windowsCodexMachineHash(requirements.data)
		if err := verifyWindowsCodexRequirementsBytes(requirements.data, opts); err != nil {
			return err
		}
		if state.Pending {
			return errors.New("Codex requirements ownership contains an incomplete transaction")
		}
		if state.PostimageSHA256 != report.PostimageSHA256 {
			return fmt.Errorf(
				"Codex requirements hash %s does not match protected postimage %s",
				report.PostimageSHA256,
				state.PostimageSHA256,
			)
		}
		runtime, err := parseWindowsCodexManagedRuntimeState(managedState.data)
		if err != nil {
			return fmt.Errorf("parse Codex managed runtime state: %w", err)
		}
		if err := validateWindowsCodexManagedRuntimeStateIdentity(runtime, opts); err != nil {
			return err
		}
		if runtime.RequirementsSHA256 != report.PostimageSHA256 {
			return errors.New("Codex managed runtime state is not bound to the current requirements bytes")
		}
		return nil
	})
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.OK = true
	report.SecurityComplete = windowsCodexMachineSecurityComplete(opts)
	report.Disposition = "verified"
	return report, nil
}

// RemoveWindowsCodexMachineRequirements restores an exact preimage when the
// requirements still equal the protected postimage. If unrelated administrator
// edits landed later, it removes only DefenseClaw-owned additions and preserves
// those edits.
func RemoveWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	report := windowsCodexMachineReport("remove", opts)
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		report.Error = err.Error()
		return report, err
	}
	// The locked path below requires the Codex machine-policy directory, which
	// exists only once a target has been enrolled. No artifact means nothing to
	// remove, which is the same result that path reports for this state.
	present, err := windowsCodexMachineAnyArtifactPathExists(opts)
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	if !present {
		report.OK = true
		report.Disposition = "ownership_absent"
		report.SafeToRemoveBinary = true
		report.ManagedStateRemovedOrAbsent = true
		return report, nil
	}
	err = withWindowsCodexMachineMutation(opts, func() error {
		requirements, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			true,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		ownership, err := readWindowsCodexMachineFile(
			opts.OwnershipPath,
			windowsCodexMachineOwnershipLimit,
			true,
			"Codex requirements ownership",
		)
		if err != nil {
			return err
		}
		managedState, err := readWindowsCodexMachineFile(
			opts.ManagedStatePath,
			windowsCodexManagedStateLimit,
			true,
			"Codex managed runtime state",
		)
		if err != nil {
			return err
		}
		report.RequirementsExisted = requirements.existed
		report.OwnershipExisted = ownership.existed
		report.ManagedStateExisted = managedState.existed

		if !ownership.existed {
			contains, markerErr := windowsCodexRequirementsContainExactManagedHook(requirements.data, opts)
			if markerErr != nil {
				return fmt.Errorf("inspect unowned Codex requirements: %w", markerErr)
			}
			if contains || managedState.existed {
				return errors.New("DefenseClaw Codex artifacts remain without protected ownership; refusing unsafe binary removal")
			}
			references, referenceErr := windowsCodexOwnedPathReferenceCount(requirements.data, opts)
			if referenceErr != nil {
				return referenceErr
			}
			report.SurvivingOwnedPathReferences = references
			if references != 0 {
				return fmt.Errorf(
					"%d Codex managed hook references to the DefenseClaw install tree remain without ownership metadata",
					references,
				)
			}
			report.Disposition = "ownership_absent"
			report.SafeToRemoveBinary = true
			report.ManagedStateRemovedOrAbsent = true
			return nil
		}

		state, err := parseWindowsCodexMachineOwnership(ownership.data)
		if err != nil {
			return fmt.Errorf("parse Codex requirements ownership: %w", err)
		}
		if err := validateWindowsCodexMachineOwnership(state, opts); err != nil {
			return err
		}
		report.PreimageSHA256 = state.PreimageSHA256
		report.PostimageSHA256 = windowsCodexMachineHash(requirements.data)

		exactPostimage := requirements.existed && report.PostimageSHA256 == state.PostimageSHA256
		candidate := append([]byte(nil), requirements.data...)
		candidateExists := requirements.existed
		switch {
		case exactPostimage && state.PreimageExisted:
			candidate = append([]byte(nil), state.Preimage...)
			candidateExists = true
			report.Changed = !bytes.Equal(requirements.data, state.Preimage)
			report.Disposition = "restored_preimage"
		case exactPostimage && !state.PreimageExisted:
			candidate = nil
			candidateExists = false
			report.Changed = requirements.existed
			report.Disposition = "restored_preimage"
		default:
			cleaned, changed, cleanErr := removeWindowsCodexRequirementsOwnedChanges(
				requirements.data,
				state.Preimage,
				opts,
			)
			if cleanErr != nil {
				return cleanErr
			}
			candidate = cleaned
			candidateExists = true
			if len(bytes.TrimSpace(cleaned)) == 0 && !state.PreimageExisted {
				candidate = nil
				candidateExists = false
			}
			report.Changed = changed
			report.Disposition = "surgical_preservation"
		}

		// Validate the complete candidate before the first mutation. In
		// particular, an unrelated administrator hook that still points into
		// our install tree must leave requirements, ownership, and runtime
		// state byte-for-byte intact on a blocked removal.
		contains, err := windowsCodexRequirementsContainExactManagedHook(candidate, opts)
		if err != nil {
			return err
		}
		if contains {
			return errors.New("exact DefenseClaw Codex managed hooks would remain after removal")
		}
		references, err := windowsCodexOwnedPathReferenceCount(candidate, opts)
		if err != nil {
			return err
		}
		report.SurvivingOwnedPathReferences = references
		if references != 0 {
			return fmt.Errorf(
				"%d surviving Codex managed hook references still point into the DefenseClaw install tree; explicit ownership transfer is required before binary removal",
				references,
			)
		}

		if report.Changed {
			if candidateExists {
				if err := writeWindowsCodexMachineFile(
					opts.RequirementsPath,
					candidate,
					windowsCodexMachineRequirementsLimit,
					"Codex machine requirements",
				); err != nil {
					return err
				}
			} else if err := deleteWindowsCodexMachineFile(
				opts.RequirementsPath,
				"Codex machine requirements",
			); err != nil {
				return err
			}
		}

		// Re-read before dropping rollback metadata. If an administrator raced
		// our candidate publication, ownership remains available and the
		// installer must not remove the binary.
		remaining, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			true,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		if remaining.existed != candidateExists ||
			(candidateExists && !bytes.Equal(remaining.data, candidate)) {
			return errors.New("Codex requirements changed before removal could commit")
		}
		if managedState.existed {
			if err := deleteWindowsCodexMachineFile(opts.ManagedStatePath, "Codex managed runtime state"); err != nil {
				return err
			}
			report.ManagedStateRemoved = true
			report.Changed = true
		}
		if err := deleteWindowsCodexMachineFile(opts.OwnershipPath, "Codex requirements ownership"); err != nil {
			return err
		}
		report.Changed = true
		report.SafeToRemoveBinary = true
		report.ManagedStateRemovedOrAbsent = true
		return nil
	})
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.OK = true
	return report, nil
}

// PublishWindowsCodexManagedRuntimeTargets atomically publishes the exact
// administrator manifest set after per-user runtime reconciliation. Missing,
// duplicate, malformed, or system-account SIDs are rejected.
func PublishWindowsCodexManagedRuntimeTargets(
	opts WindowsCodexMachineRequirementsOptions,
	targets []WindowsCodexManagedRuntimeTarget,
) error {
	return withWindowsCodexMachineMutation(opts, func() error {
		if err := verifyWindowsCodexMachineRequirementsLocked(opts, nil); err != nil {
			return err
		}
		normalized, err := normalizeWindowsCodexManagedRuntimeTargets(targets)
		if err != nil {
			return err
		}
		requirements, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			false,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		state := windowsCodexManagedRuntimeState{
			SchemaVersion:      windowsCodexMachineRequirementsSchema,
			RequirementsPath:   opts.RequirementsPath,
			RequirementsSHA256: windowsCodexMachineHash(requirements.data),
			HookExecutable:     opts.HookBinary,
			GatewayAddr:        opts.GatewayAddr,
			GatewayServiceName: opts.GatewayServiceName,
			Targets:            normalized,
		}
		data, err := marshalWindowsCodexManagedRuntimeState(state)
		if err != nil {
			return err
		}
		return writeWindowsCodexMachineFile(
			opts.ManagedStatePath,
			data,
			windowsCodexManagedStateLimit,
			"Codex managed runtime state",
		)
	})
}

// RemoveWindowsCodexManagedRuntimeTarget de-registers one SID from the
// protected machine registry before binaries or user runtime are removed. The
// now-inert per-user runtime may be retained as recovery evidence.
func RemoveWindowsCodexManagedRuntimeTarget(
	opts WindowsCodexMachineRequirementsOptions,
	rawSID string,
) error {
	targetSID, err := windows.StringToSid(strings.TrimSpace(rawSID))
	if err != nil || targetSID == nil {
		return fmt.Errorf("invalid Codex managed runtime target SID %q", rawSID)
	}
	return withWindowsCodexMachineMutation(opts, func() error {
		if err := verifyWindowsCodexMachineRequirementsLocked(opts, nil); err != nil {
			return err
		}
		requirements, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			false,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		stateFile, err := readWindowsCodexMachineFile(
			opts.ManagedStatePath,
			windowsCodexManagedStateLimit,
			false,
			"Codex managed runtime state",
		)
		if err != nil {
			return err
		}
		state, err := parseWindowsCodexManagedRuntimeState(stateFile.data)
		if err != nil {
			return err
		}
		filtered := make([]WindowsCodexManagedRuntimeTarget, 0, len(state.Targets))
		for _, target := range state.Targets {
			if strings.EqualFold(target.SID, targetSID.String()) {
				continue
			}
			filtered = append(filtered, target)
		}
		if len(filtered) == len(state.Targets) {
			return nil
		}
		state.Targets = filtered
		state.RequirementsSHA256 = windowsCodexMachineHash(requirements.data)
		body, err := marshalWindowsCodexManagedRuntimeState(state)
		if err != nil {
			return err
		}
		return writeWindowsCodexMachineFile(
			opts.ManagedStatePath,
			body,
			windowsCodexManagedStateLimit,
			"Codex managed runtime state",
		)
	})
}

// ResolveWindowsCodexManagedRuntimeRegistry is the standard-user hook-side
// reader. A clean absence of both the exact DefenseClaw requirement marker and
// protected registry returns Active=false; partial, corrupt, or stale state is
// an error so an active managed command cannot downgrade to a no-op.
func ResolveWindowsCodexManagedRuntimeRegistry(
	hookExecutable string,
) (WindowsCodexManagedRuntimeRegistry, error) {
	var result WindowsCodexManagedRuntimeRegistry
	programData, err := windowsCodexMachineProgramData()
	if err != nil {
		return result, fmt.Errorf("resolve ProgramData: %w", err)
	}
	requirementsPath := filepath.Join(programData, "OpenAI", "Codex", "requirements.toml")
	statePath := filepath.Join(filepath.Dir(requirementsPath), windowsCodexManagedStateFile)
	lockPath := filepath.Join(filepath.Dir(requirementsPath), windowsCodexManagedLockFile)
	lockExists, err := windowsCodexMachinePathExists(lockPath)
	if err != nil {
		return result, err
	}
	if !lockExists {
		requirementsExists, requirementsErr := windowsCodexMachinePathExists(requirementsPath)
		if requirementsErr != nil {
			return result, requirementsErr
		}
		stateExists, stateErr := windowsCodexMachinePathExists(statePath)
		if stateErr != nil {
			return result, stateErr
		}
		// Close the first-install race before using either unlocked observation.
		// The writer always creates the protected lock before publishing policy.
		lockExists, err = windowsCodexMachinePathExists(lockPath)
		if err != nil {
			return result, err
		}
		if lockExists {
			// The policy pair will be inspected again after the writer releases
			// this lock, so no unlocked observation above influences the result.
		} else if requirementsExists || stateExists {
			return result, errors.New("Codex managed artifacts exist without the machine policy lock")
		} else {
			return result, nil
		}
	}
	err = withWindowsCodexMachinePolicyLock(requirementsPath, func() error {
		var resolveErr error
		result, resolveErr = resolveWindowsCodexManagedRuntimeRegistryLocked(
			requirementsPath,
			statePath,
			hookExecutable,
		)
		return resolveErr
	})
	return result, err
}

func resolveWindowsCodexManagedRuntimeRegistryLocked(
	requirementsPath string,
	statePath string,
	hookExecutable string,
) (WindowsCodexManagedRuntimeRegistry, error) {
	var result WindowsCodexManagedRuntimeRegistry
	requirementsExists, err := windowsCodexMachinePathExists(requirementsPath)
	if err != nil {
		return result, err
	}
	stateExists, err := windowsCodexMachinePathExists(statePath)
	if err != nil {
		return result, err
	}
	if !requirementsExists && !stateExists {
		return result, nil
	}
	if !requirementsExists {
		return result, errors.New("Codex managed runtime state exists without machine requirements")
	}
	requirements, err := readWindowsCodexMachineFile(
		requirementsPath,
		windowsCodexMachineRequirementsLimit,
		false,
		"Codex machine requirements",
	)
	if err != nil {
		return result, err
	}
	identityOpts := WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   requirementsPath,
		ManagedDir:         filepath.Dir(hookExecutable),
		HookBinary:         hookExecutable,
		ManagedStatePath:   statePath,
		CodexTargetEnabled: true,
	}
	if !stateExists {
		contains, markerErr := windowsCodexRequirementsContainExactManagedHook(
			requirements.data,
			identityOpts,
		)
		if markerErr != nil {
			return result, markerErr
		}
		if contains {
			return result, errors.New("active Codex machine requirements are missing protected managed runtime state")
		}
		return result, nil
	}
	if err := verifyWindowsCodexRequirementsBytes(requirements.data, identityOpts); err != nil {
		return result, fmt.Errorf("verify active Codex machine requirements: %w", err)
	}
	stateFile, err := readWindowsCodexMachineFile(
		statePath,
		windowsCodexManagedStateLimit,
		false,
		"Codex managed runtime state",
	)
	if err != nil {
		return result, err
	}
	state, err := parseWindowsCodexManagedRuntimeState(stateFile.data)
	if err != nil {
		return result, fmt.Errorf("parse Codex managed runtime state: %w", err)
	}
	if state.SchemaVersion != windowsCodexMachineRequirementsSchema ||
		!sameWindowsCodexMachinePath(state.RequirementsPath, requirementsPath) {
		return result, errors.New("Codex managed runtime state has an invalid requirements identity")
	}
	if !sameWindowsCodexMachinePath(state.HookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"invoking hook executable %s does not match protected Codex runtime state %s",
			hookExecutable,
			state.HookExecutable,
		)
	}
	if state.RequirementsSHA256 != windowsCodexMachineHash(requirements.data) {
		return result, errors.New("Codex managed runtime state is stale for the active requirements bytes")
	}
	targets, err := normalizeWindowsCodexManagedRuntimeTargets(state.Targets)
	if err != nil {
		return result, err
	}
	result.Active = true
	result.GatewayAddr = state.GatewayAddr
	result.GatewayServiceName = state.GatewayServiceName
	result.Targets = targets
	return result, nil
}

// ReadWindowsCodexManagedRuntimeTargets returns the exact protected target set.
// A clean post-uninstall absence returns an empty set; callers that need to
// distinguish absence use ResolveWindowsCodexManagedRuntimeRegistry.
func ReadWindowsCodexManagedRuntimeTargets(
	hookExecutable string,
) ([]WindowsCodexManagedRuntimeTarget, error) {
	registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hookExecutable)
	if err != nil {
		return nil, err
	}
	return registry.Targets, nil
}

func windowsCodexMachinePathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Codex managed artifact %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("Codex managed artifact is not a regular non-link file: %s", path)
	}
	return true, nil
}

func verifyWindowsCodexMachineRequirementsLocked(
	opts WindowsCodexMachineRequirementsOptions,
	expectedTargets []WindowsCodexManagedRuntimeTarget,
) error {
	if err := validateWindowsCodexMachinePrerequisites(opts); err != nil {
		return err
	}
	if !opts.CodexTargetEnabled {
		return nil
	}
	requirements, err := readWindowsCodexMachineFile(
		opts.RequirementsPath,
		windowsCodexMachineRequirementsLimit,
		false,
		"Codex machine requirements",
	)
	if err != nil {
		return err
	}
	if err := verifyWindowsCodexRequirementsBytes(requirements.data, opts); err != nil {
		return err
	}
	ownership, err := readWindowsCodexMachineFile(
		opts.OwnershipPath,
		windowsCodexMachineOwnershipLimit,
		false,
		"Codex requirements ownership",
	)
	if err != nil {
		return err
	}
	state, err := parseWindowsCodexMachineOwnership(ownership.data)
	if err != nil {
		return fmt.Errorf("parse Codex requirements ownership: %w", err)
	}
	if err := validateWindowsCodexMachineOwnership(state, opts); err != nil {
		return err
	}
	hash := windowsCodexMachineHash(requirements.data)
	if state.Pending || state.PostimageSHA256 != hash {
		return errors.New("Codex requirements ownership is pending or stale")
	}
	managedState, err := readWindowsCodexMachineFile(
		opts.ManagedStatePath,
		windowsCodexManagedStateLimit,
		false,
		"Codex managed runtime state",
	)
	if err != nil {
		return err
	}
	runtime, err := parseWindowsCodexManagedRuntimeState(managedState.data)
	if err != nil {
		return err
	}
	if err := validateWindowsCodexManagedRuntimeStateIdentity(runtime, opts); err != nil {
		return err
	}
	if runtime.RequirementsSHA256 != hash {
		return errors.New("Codex managed runtime state is stale for current requirements")
	}
	if expectedTargets != nil {
		normalized, err := normalizeWindowsCodexManagedRuntimeTargets(expectedTargets)
		if err != nil {
			return err
		}
		if !windowsCodexManagedRuntimeTargetsEqual(runtime.Targets, normalized) {
			return errors.New("Codex managed runtime target set differs from the administrator manifest")
		}
	}
	return nil
}

func validateWindowsCodexMachineOwnership(
	state windowsCodexMachineOwnership,
	opts WindowsCodexMachineRequirementsOptions,
) error {
	if state.SchemaVersion != windowsCodexMachineRequirementsSchema {
		return fmt.Errorf("unsupported Codex requirements ownership schema %d", state.SchemaVersion)
	}
	if !sameWindowsCodexMachinePath(state.RequirementsPath, opts.RequirementsPath) ||
		!sameWindowsCodexMachinePath(state.ManagedDir, opts.ManagedDir) ||
		!sameWindowsCodexMachinePath(state.HookBinary, opts.HookBinary) {
		return errors.New("Codex requirements ownership belongs to another protected layout")
	}
	if state.PreimageSHA256 != windowsCodexMachineHash(state.Preimage) {
		return errors.New("Codex requirements ownership preimage hash is invalid")
	}
	if !state.PreimageExisted && len(state.Preimage) != 0 {
		return errors.New("Codex requirements ownership has bytes for an absent preimage")
	}
	if len(state.PostimageSHA256) != windowsCodexSHA256HexLength || !isLowerHex(state.PostimageSHA256) {
		return errors.New("Codex requirements ownership postimage hash is invalid")
	}
	return nil
}

const windowsCodexSHA256HexLength = 64

func isLowerHex(value string) bool {
	if value != strings.ToLower(value) {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validateWindowsCodexManagedRuntimeStateIdentity(
	state windowsCodexManagedRuntimeState,
	opts WindowsCodexMachineRequirementsOptions,
) error {
	if state.SchemaVersion != windowsCodexMachineRequirementsSchema {
		return fmt.Errorf("unsupported Codex managed runtime state schema %d", state.SchemaVersion)
	}
	if !sameWindowsCodexMachinePath(state.RequirementsPath, opts.RequirementsPath) ||
		!sameWindowsCodexMachinePath(state.HookExecutable, opts.HookBinary) {
		return errors.New("Codex managed runtime state belongs to another protected layout")
	}
	gatewayAddr, err := NormalizeWindowsManagedGatewayAddr(state.GatewayAddr)
	if err != nil || gatewayAddr != state.GatewayAddr {
		return errors.New("Codex managed runtime state has an invalid gateway address")
	}
	if err := ValidateWindowsManagedGatewayServiceName(state.GatewayServiceName); err != nil {
		return err
	}
	if opts.GatewayAddr != "" && state.GatewayAddr != opts.GatewayAddr {
		return errors.New("Codex managed runtime state gateway address differs from protected deployment configuration")
	}
	if opts.GatewayServiceName != "" && state.GatewayServiceName != opts.GatewayServiceName {
		return errors.New("Codex managed runtime state service identity differs from protected deployment configuration")
	}
	if len(state.RequirementsSHA256) != windowsCodexSHA256HexLength || !isLowerHex(state.RequirementsSHA256) {
		return errors.New("Codex managed runtime state requirements hash is invalid")
	}
	normalized, err := normalizeWindowsCodexManagedRuntimeTargets(state.Targets)
	if err != nil {
		return err
	}
	if !windowsCodexManagedRuntimeTargetsEqual(state.Targets, normalized) {
		return errors.New("Codex managed runtime targets are not canonical")
	}
	return nil
}

func normalizeWindowsCodexManagedRuntimeTargets(
	targets []WindowsCodexManagedRuntimeTarget,
) ([]WindowsCodexManagedRuntimeTarget, error) {
	if len(targets) > 4096 {
		return nil, errors.New("Codex managed runtime state has too many targets")
	}
	result := make([]WindowsCodexManagedRuntimeTarget, 0, len(targets))
	seen := map[string]struct{}{}
	for _, target := range targets {
		rawSID := strings.TrimSpace(target.SID)
		sid, err := windows.StringToSid(rawSID)
		if err != nil || sid == nil {
			return nil, fmt.Errorf("Codex managed runtime target has invalid SID %q", target.SID)
		}
		if sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinLocalServiceSid) ||
			sid.IsWellKnown(windows.WinNetworkServiceSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return nil, fmt.Errorf("Codex managed runtime target SID %s is not an interactive user", sid)
		}
		sidKey := strings.ToUpper(sid.String())
		if _, duplicate := seen[sidKey]; duplicate {
			return nil, fmt.Errorf("duplicate Codex managed runtime target SID %s", sid)
		}
		seen[sidKey] = struct{}{}
		dataDir := strings.TrimSpace(target.DataDir)
		if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir ||
			strings.ContainsAny(dataDir, "\x00\r\n") ||
			!strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
			return nil, fmt.Errorf("Codex managed runtime target %s has invalid data_dir %q", sid, target.DataDir)
		}
		result = append(result, WindowsCodexManagedRuntimeTarget{
			SID:     sid.String(),
			DataDir: dataDir,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToUpper(result[i].SID) < strings.ToUpper(result[j].SID)
	})
	return result, nil
}

func windowsCodexManagedRuntimeTargetsEqual(
	left, right []WindowsCodexManagedRuntimeTarget,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index].SID, right[index].SID) ||
			!sameWindowsCodexMachinePath(left[index].DataDir, right[index].DataDir) {
			return false
		}
	}
	return true
}

func marshalWindowsCodexManagedRuntimeState(state windowsCodexManagedRuntimeState) ([]byte, error) {
	normalized, err := normalizeWindowsCodexManagedRuntimeTargets(state.Targets)
	if err != nil {
		return nil, err
	}
	state.Targets = normalized
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > windowsCodexManagedStateLimit {
		return nil, fmt.Errorf("Codex managed runtime state exceeds %d bytes", windowsCodexManagedStateLimit)
	}
	return data, nil
}

func parseWindowsCodexManagedRuntimeState(data []byte) (windowsCodexManagedRuntimeState, error) {
	var state windowsCodexManagedRuntimeState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return state, errors.New("Codex managed runtime state contains trailing JSON")
		}
		return state, err
	}
	if err := validateWindowsCodexManagedRuntimeStateIdentity(state, WindowsCodexMachineRequirementsOptions{
		RequirementsPath: state.RequirementsPath,
		HookBinary:       state.HookExecutable,
	}); err != nil {
		return state, err
	}
	return state, nil
}

func withWindowsCodexMachineMutation(
	opts WindowsCodexMachineRequirementsOptions,
	fn func() error,
) error {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		return err
	}
	return withWindowsCodexMachineRead(opts, fn)
}

func withWindowsCodexMachineRead(
	opts WindowsCodexMachineRequirementsOptions,
	fn func() error,
) error {
	if err := validateWindowsCodexMachineLayout(opts); err != nil {
		return err
	}
	return withWindowsCodexMachinePolicyLock(opts.RequirementsPath, func() error {
		// The lock wait is bounded but may still outlive an operator mount or
		// policy change. Re-establish the complete path identity immediately
		// before the protected read or mutation.
		if err := validateWindowsCodexMachineLayout(opts); err != nil {
			return fmt.Errorf("revalidate Codex machine layout after lock acquisition: %w", err)
		}
		return fn()
	})
}

func withWindowsCodexMachinePolicyLock(
	requirementsPath string,
	fn func() error,
) error {
	windowsCodexMachineProcessMu.Lock()
	defer windowsCodexMachineProcessMu.Unlock()

	lockPath := filepath.Join(
		filepath.Dir(requirementsPath),
		windowsCodexManagedLockFile,
	)
	lock, overlapped, err := acquireWindowsCodexMachineFileLock(lockPath)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	defer windows.UnlockFileEx(lock, 0, 1, 0, overlapped)
	return fn()
}

func acquireWindowsCodexMachineFileLock(
	path string,
) (windows.Handle, *windows.Overlapped, error) {
	parent := filepath.Dir(path)
	if err := windowsCodexMachineTrustedDirCheck(parent, "Codex machine policy lock parent"); err != nil {
		return 0, nil, err
	}
	existed := false
	if info, err := os.Lstat(path); err == nil {
		existed = true
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, nil, fmt.Errorf(
				"Codex machine policy lock is not a regular non-link file: %s",
				path,
			)
		}
		if err := windowsCodexMachineTrustedFileCheck(path, "Codex machine policy lock"); err != nil {
			return 0, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, nil, fmt.Errorf("inspect Codex machine policy lock: %w", err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, nil, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("open Codex machine policy lock: %w", err)
	}
	closeOnError := func(cause error) (windows.Handle, *windows.Overlapped, error) {
		_ = windows.CloseHandle(handle)
		return 0, nil, cause
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return closeOnError(fmt.Errorf("inspect Codex machine policy lock handle: %w", err))
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 {
		return closeOnError(fmt.Errorf(
			"Codex machine policy lock must be a no-reparse single-link regular file (links=%d)",
			info.NumberOfLinks,
		))
	}
	if !existed {
		if err := setWindowsCodexMachineFileProtection(path, true); err != nil {
			return closeOnError(fmt.Errorf("protect Codex machine policy lock: %w", err))
		}
	}
	overlapped := new(windows.Overlapped)
	deadline := time.Now().Add(windowsCodexMachineLockTimeout)
	for {
		err = windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			overlapped,
		)
		if err == nil {
			return handle, overlapped, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return closeOnError(fmt.Errorf("acquire Codex machine policy lock: %w", err))
		}
		if !time.Now().Before(deadline) {
			return closeOnError(fmt.Errorf(
				"timed out waiting %s for Codex machine policy lock",
				windowsCodexMachineLockTimeout,
			))
		}
		delay := 50 * time.Millisecond
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

func requireWindowsCodexMachineAdministrator() error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil &&
		user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return errors.New("Codex machine requirements require an elevated Administrator or LocalSystem token")
}

func windowsCodexMachineAnyArtifactPathExists(
	opts WindowsCodexMachineRequirementsOptions,
) (bool, error) {
	for _, path := range []string{
		opts.RequirementsPath,
		opts.OwnershipPath,
		opts.ManagedStatePath,
	} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) ||
			filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return false, fmt.Errorf("Codex artifact path is not exact, clean, and absolute: %q", path)
		}
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect Codex artifact path %s: %w", path, err)
		}
	}
	return false, nil
}

func validateWindowsCodexMachineLayout(opts WindowsCodexMachineRequirementsOptions) error {
	gatewayAddr, err := NormalizeWindowsManagedGatewayAddr(opts.GatewayAddr)
	if err != nil || gatewayAddr != opts.GatewayAddr {
		return fmt.Errorf("Codex managed gateway address is not canonical: %q", opts.GatewayAddr)
	}
	if err := ValidateWindowsManagedGatewayServiceName(opts.GatewayServiceName); err != nil {
		return err
	}
	programData, err := windowsCodexMachineProgramData()
	if err != nil {
		return fmt.Errorf("resolve ProgramData: %w", err)
	}
	expectedRequirements := filepath.Join(programData, "OpenAI", "Codex", "requirements.toml")
	expectedState := filepath.Join(filepath.Dir(expectedRequirements), windowsCodexManagedStateFile)
	for label, path := range map[string]string{
		"requirements":          opts.RequirementsPath,
		"managed directory":     opts.ManagedDir,
		"hook binary":           opts.HookBinary,
		"ownership":             opts.OwnershipPath,
		"managed runtime state": opts.ManagedStatePath,
	} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) ||
			filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("Codex %s path is not exact, clean, and absolute: %q", label, path)
		}
	}
	if !sameWindowsCodexMachinePath(opts.RequirementsPath, expectedRequirements) {
		return fmt.Errorf("refusing noncanonical Codex requirements path %s", opts.RequirementsPath)
	}
	if !sameWindowsCodexMachinePath(opts.ManagedStatePath, expectedState) {
		return fmt.Errorf("refusing noncanonical Codex managed runtime state path %s", opts.ManagedStatePath)
	}
	if !sameWindowsCodexMachinePath(filepath.Dir(opts.HookBinary), opts.ManagedDir) ||
		!strings.EqualFold(filepath.Base(opts.ManagedDir), "bin") ||
		!strings.EqualFold(filepath.Base(opts.HookBinary), "defenseclaw-hook.exe") {
		return errors.New("Codex managed hook binary is not the exact DefenseClaw bin sibling")
	}
	if !strings.EqualFold(filepath.Base(opts.OwnershipPath), "codex-requirements-ownership.json") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(opts.OwnershipPath)), "install") {
		return fmt.Errorf("refusing noncanonical Codex requirements ownership path %s", opts.OwnershipPath)
	}
	// Leaf-checked paths only. ProgramData is reached as an ancestor by the walk
	// up from the Codex directory, which is the rule that applies to it.
	for _, path := range []string{
		filepath.Dir(opts.RequirementsPath),
		opts.ManagedDir,
		filepath.Dir(opts.OwnershipPath),
	} {
		if err := windowsCodexMachineVolumeCheck(path); err != nil {
			return err
		}
		if err := rejectWindowsCodexMachineReparseChain(path); err != nil {
			return err
		}
		if err := windowsCodexMachineTrustedDirCheck(path, "Codex machine policy directory"); err != nil {
			return err
		}
	}
	if err := readWindowsCodexMachineBinary(opts.HookBinary); err != nil {
		return err
	}
	return nil
}

func readWindowsCodexMachineBinary(path string) error {
	if err := windowsCodexMachineTrustedFileCheck(path, "Codex managed hook binary"); err != nil {
		return err
	}
	file, err := openWindowsCodexNoFollow(path, windows.GENERIC_READ, false)
	if err != nil {
		return fmt.Errorf("open Codex managed hook binary: %w", err)
	}
	defer windows.CloseHandle(file)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(file, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.NumberOfLinks != 1 {
		return errors.New("Codex managed hook binary is not a single-link regular file")
	}
	return nil
}

func readWindowsCodexMachineFile(
	path string,
	limit int,
	allowMissing bool,
	label string,
) (windowsCodexStableFile, error) {
	result := windowsCodexStableFile{}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		if err := windowsCodexMachineTrustedDirCheck(filepath.Dir(path), label+" parent"); err != nil {
			return result, err
		}
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(limit) {
		return result, fmt.Errorf("%s is not a bounded regular file", label)
	}
	if err := windowsCodexMachineTrustedFileCheck(path, label); err != nil {
		return result, err
	}
	handle, err := openWindowsCodexNoFollow(path, windows.GENERIC_READ, false)
	if err != nil {
		return result, fmt.Errorf("open %s: %w", label, err)
	}
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &before); err != nil {
		_ = windows.CloseHandle(handle)
		return result, fmt.Errorf("inspect opened %s: %w", label, err)
	}
	if before.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		before.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		return result, fmt.Errorf("%s is redirected, not regular, or has %d hardlinks", label, before.NumberOfLinks)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return result, fmt.Errorf("wrap %s handle", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, fmt.Errorf("read %s: %w", label, err)
	}
	if len(data) > limit {
		return result, fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	afterInfo, err := os.Lstat(path)
	if err != nil || afterInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, afterInfo) {
		return result, fmt.Errorf("%s changed identity while it was read", label)
	}
	result.data = data
	result.existed = true
	return result, nil
}

func writeWindowsCodexMachineFile(path string, data []byte, limit int, label string) error {
	if len(data) > limit {
		return fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	if err := windowsCodexMachineTrustedDirCheck(filepath.Dir(path), label+" parent"); err != nil {
		return err
	}
	existing, err := readWindowsCodexMachineFile(path, limit, true, label)
	if err != nil {
		return err
	}
	if existing.existed && bytes.Equal(existing.data, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-codex-*")
	if err != nil {
		return fmt.Errorf("create %s temp file: %w", label, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write %s temp file: %w", label, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync %s temp file: %w", label, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s temp file: %w", label, err)
	}
	userReadable := windowsCodexMachineFileUserReadable(path)
	if err := setWindowsCodexMachineFileProtection(tmpPath, userReadable); err != nil {
		cleanup()
		return fmt.Errorf("protect %s temp file: %w", label, err)
	}
	if err := safefile.ReplaceFile(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("publish %s: %w", label, err)
	}
	if err := setWindowsCodexMachineFileProtection(path, userReadable); err != nil {
		return fmt.Errorf("protect published %s: %w", label, err)
	}
	persisted, err := readWindowsCodexMachineFile(path, limit, false, label)
	if err != nil {
		return err
	}
	if !bytes.Equal(persisted.data, data) {
		return fmt.Errorf("%s changed during atomic publication", label)
	}
	return nil
}

func windowsCodexMachineFileUserReadable(path string) bool {
	return strings.EqualFold(filepath.Base(path), "requirements.toml") ||
		strings.EqualFold(filepath.Base(path), windowsCodexManagedStateFile) ||
		strings.EqualFold(filepath.Base(path), windowsCodexManagedLockFile)
}

func setWindowsCodexMachineFileProtection(path string, userReadable bool) error {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
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
	entries := []windows.EXPLICIT_ACCESS{}
	for _, sid := range []*windows.SID{owner, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	if userReadable {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(users),
			},
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
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		nil,
		nil,
	); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func deleteWindowsCodexMachineFile(path, label string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s before deletion: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular file", label)
	}
	if err := windowsCodexMachineTrustedFileCheck(path, label); err != nil {
		return err
	}
	handle, err := openWindowsCodexNoFollow(
		path,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		false,
	)
	if err != nil {
		return fmt.Errorf("open %s for handle-bound deletion: %w", label, err)
	}
	defer windows.CloseHandle(handle)
	var infoByHandle windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &infoByHandle); err != nil {
		return err
	}
	if infoByHandle.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		infoByHandle.NumberOfLinks != 1 {
		return fmt.Errorf("%s is redirected, not regular, or has %d hardlinks", label, infoByHandle.NumberOfLinks)
	}
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	); err != nil {
		deleteFile := byte(1)
		if fallbackErr := windows.SetFileInformationByHandle(
			handle,
			windows.FileDispositionInfo,
			&deleteFile,
			1,
		); fallbackErr != nil {
			return fmt.Errorf("mark %s for handle-bound deletion: %w", label, fallbackErr)
		}
	}
	return nil
}

func openWindowsCodexNoFollow(path string, access uint32, directory bool) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	return windows.CreateFile(
		ptr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
}

func rejectWindowsCodexMachineReparseChain(path string) error {
	cursor := filepath.Clean(path)
	for {
		ptr, err := winpath.UTF16Ptr(cursor)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(ptr)
		if err != nil {
			return fmt.Errorf("inspect Codex machine path %s: %w", cursor, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse points are not allowed in Codex machine path: %s", cursor)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return nil
		}
		cursor = parent
	}
}

func validateWindowsCodexMachineVolume(path string) error {
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return fmt.Errorf("Codex machine path is not on a trusted mount-manager NTFS drive: %w", err)
	}
	return nil
}
