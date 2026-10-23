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

	windowsCodexMachineProgramData     = winpath.TrustedProgramData
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
	reconcile := func() error {
		report = windowsCodexMachineReport("reconcile", opts)
		requirementsFile, err := readWindowsCodexSharedRequirements(opts.RequirementsPath)
		if err != nil {
			return err
		}
		requirements := windowsCodexStableFile{data: requirementsFile.Data, existed: requirementsFile.Exists}
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
		ownershipAdopted := !ownership.existed
		// discarded is the parseable record of another layout that the
		// identity-drift branch below adopts over; nil when there is none.
		var discarded *windowsCodexMachineOwnership
		if ownership.existed {
			state, err = parseWindowsCodexMachineOwnership(ownership.data)
			if err != nil {
				// Strict mode (DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1)
				// refuses to silently seed fresh ownership on top of an
				// unparseable record. The parse failure is the same
				// forensic tamper signal operators configure strict mode
				// to catch (prior install wrote a corrupted record or an
				// external process tampered with the JSON).
				if managed.TrustStrictAncestors() {
					return fmt.Errorf("enterprise hooks: parse Codex machine ownership: %w", err)
				}
				// Bulldoze: ownership JSON is on disk but unparseable (prior
				// install wrote a partial file, or disk corruption). Treat
				// as adoptable and seed fresh ownership from the current
				// wire shape. Same posture as the ownership-absent branch
				// below.
				fmt.Fprintf(os.Stderr,
					"[enterprise-hooks] reclaiming unparseable Codex ownership at %s: %v\n",
					opts.OwnershipPath, err)
				ownershipAdopted = true
				state = windowsCodexMachineOwnership{}
			} else if err := validateWindowsCodexMachineOwnership(state, opts); err != nil {
				// Strict mode (DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1)
				// preserves refuse-on-drift: a hardened deployment must
				// NOT silently adopt a mismatched ownership record,
				// because that masks exactly the tamper signal operators
				// configure strict mode to catch (a prior install's
				// scoped layout surviving into a new scope).
				if managed.TrustStrictAncestors() {
					return err
				}
				// Bulldoze: ownership metadata is a valid DefenseClaw record
				// but belongs to a prior install with a different ManagedDir
				// / HookBinary / RequirementsPath (common cause: an unsigned
				// certification install at a scoped path that was
				// uninstalled, leaving C:\ProgramData\OpenAI\Codex\* with
				// the old bin path baked in). Refusing here strands the
				// current install's reconcile. Treat the ownership as
				// adoptable: discard the mismatched record and fall through
				// to the fresh-ownership seed path below, which also
				// surgically removes any orphan managed-hook entries from
				// the preimage.
				fmt.Fprintf(os.Stderr,
					"[enterprise-hooks] reclaiming identity-drifted Codex "+
						"ownership at %s (prior install's layout does not "+
						"match current scope): %v\n",
					opts.OwnershipPath, err)
				ownershipAdopted = true
				previous := state
				discarded = &previous
				state = windowsCodexMachineOwnership{}
			}
		}
		requirementsBase := requirements.data
		if ownershipAdopted {
			// Managed-mode trust posture: the ownership JSON being absent while
			// a DefenseClaw hook or managed-state file is present is the signature
			// of a prior failed install/uninstall that got partway through writing
			// the pre-reconcile side (requirements.toml) and never finished writing
			// the post-reconcile side (ownership + managed runtime state). Refusing
			// here strands the user: install can't adopt what it finds, and
			// uninstall can't clean what install won't adopt. The product
			// invariant is "canonical state after install, not refuse-on-drift" —
			// treat the orphan hook / state as adoptable and seed fresh ownership
			// metadata from the current wire shape. The reconcile pass below
			// writes the canonical ACL (via Set-DefenseClawPathAcl's own self-heal
			// chain) so the resulting trio is internally consistent.
			//
			// Strip DefenseClaw's own changes from the preimage we persist.
			// Otherwise an eventual uninstall would restore the preimage, see
			// the canonical hook still present, and refuse to commit ("exact
			// DefenseClaw Codex managed hooks would remain after removal"), or
			// restore a stale prior-install layout. On identity drift the
			// discarded record names the prior layout: its hook groups and
			// windows_managed_dir are stripped from both the live base and the
			// preimage, and the shared isolation controls stay in the preimage
			// only when that record's trustworthy preimage shows they predate
			// DefenseClaw (see windowsCodexAdoptRequirements).
			adoption, adoptErr := windowsCodexAdoptRequirements(requirements.data, requirements.existed, discarded, opts)
			if adoptErr != nil {
				return fmt.Errorf("prepare adopted Codex requirements preimage: %w", adoptErr)
			}
			requirementsBase = adoption.base
			state = windowsCodexMachineOwnership{
				SchemaVersion:    windowsCodexMachineRequirementsSchema,
				RequirementsPath: opts.RequirementsPath,
				ManagedDir:       opts.ManagedDir,
				HookBinary:       opts.HookBinary,
				PreimageExisted:  adoption.preimageExisted,
				Preimage:         adoption.preimage,
				PreimageSHA256:   windowsCodexMachineHash(adoption.preimage),
			}
		}
		report.PreimageSHA256 = state.PreimageSHA256

		rendered, _, err := reconcileWindowsCodexRequirements(requirementsBase, opts)
		if err != nil {
			return err
		}
		// A file ordinary users cannot read leaves their Codex without the
		// managed hooks: it is published again with the read restored.
		requirementsChanged := !bytes.Equal(requirements.data, rendered) ||
			windowsCodexRequirementsUnreadable(requirementsFile)
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
			// An administrator does not take the DefenseClaw lock. Publish the
			// merge only over the file it was made from; a newer save is kept,
			// the ownership record goes back to what this pass read, and the
			// merge runs again on the newer file.
			if err := publishWindowsCodexRequirements(requirementsFile, rendered, false); err != nil {
				if !errors.Is(err, errWindowsCodexMachineFileChanged) {
					return err
				}
				var restoreErr error
				if ownership.existed {
					restoreErr = writeWindowsCodexMachineFile(
						opts.OwnershipPath,
						ownership.data,
						windowsCodexMachineOwnershipLimit,
						"Codex requirements ownership",
					)
				} else {
					restoreErr = deleteWindowsCodexMachineFile(opts.OwnershipPath, "Codex requirements ownership")
				}
				if restoreErr != nil {
					return fmt.Errorf("%v (restore Codex requirements ownership: %w)", err, restoreErr)
				}
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
		// A save that lands after the publication is newer and is kept: the
		// pass runs again and merges the guard into it, instead of leaving an
		// ownership record that no longer describes the file.
		published, err := readWindowsCodexMachineFile(
			opts.RequirementsPath,
			windowsCodexMachineRequirementsLimit,
			false,
			"Codex machine requirements",
		)
		if err != nil {
			return err
		}
		if windowsCodexMachineHash(published.data) != postHash {
			return windowsCodexMachineFileChanged("Codex machine requirements")
		}

		report.Changed = true
		if !requirements.existed {
			report.Disposition = "created"
		} else {
			report.Disposition = "reconciled"
		}
		return verifyWindowsCodexMachineRequirementsLocked(opts, nil)
	}
	err := withWindowsCodexMachineMutation(opts, func() error {
		for attempt := 1; ; attempt++ {
			err := reconcile()
			if !errors.Is(err, errWindowsCodexMachineFileChanged) || attempt == windowsCodexMachineReconcileAttempts {
				return err
			}
		}
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
		absent, err := windowsCodexMachineArtifactsAbsentUnlocked(opts)
		if err != nil {
			report.Error = err.Error()
			return report, err
		}
		if absent {
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
		if err := verifyWindowsCodexRequirementsUsersCanRead(opts.RequirementsPath); err != nil {
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
// those edits. An administrator does not take the DefenseClaw lock, so the
// requirements write or deletion is a compare-and-swap against the file the
// removal was computed from: a save made in between is kept, and the removal
// is computed again from it, up to windowsCodexMachineReconcileAttempts times.
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
	// remove, which is the same result that path reports for this state. The
	// bracketed lock-existence checks in
	// windowsCodexMachineArtifactsAbsentUnlocked close the race a plain scan
	// would leave open against a concurrent Reconcile.
	absent, err := windowsCodexMachineArtifactsAbsentUnlocked(opts)
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	if absent {
		report.OK = true
		report.Disposition = "ownership_absent"
		report.SafeToRemoveBinary = true
		report.ManagedStateRemovedOrAbsent = true
		return report, nil
	}
	remove := func() error {
		report = windowsCodexMachineReport("remove", opts)
		requirementsFile, err := readWindowsCodexSharedRequirements(opts.RequirementsPath)
		if err != nil {
			return err
		}
		requirements := windowsCodexStableFile{data: requirementsFile.Data, existed: requirementsFile.Exists}
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
		var candidate []byte
		var candidateExists bool
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
			// Publish the candidate, or delete the file, only over the file
			// the candidate was computed from. A newer save is kept and the
			// removal is computed again from it.
			if err := publishWindowsCodexRequirements(requirementsFile, candidate, !candidateExists); err != nil {
				return err
			}
		}

		// Re-read before dropping rollback metadata. A save made after the
		// candidate was published keeps the ownership record, so the removal
		// is computed again from the newer file and the installer does not
		// remove the binary meanwhile.
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
			return fmt.Errorf("%s %w before removal could commit", "Codex machine requirements", errWindowsCodexMachineFileChanged)
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
	}
	err = withWindowsCodexMachineMutation(opts, func() error {
		for attempt := 1; ; attempt++ {
			err := remove()
			if !errors.Is(err, errWindowsCodexMachineFileChanged) || attempt == windowsCodexMachineReconcileAttempts {
				return err
			}
		}
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
		HookContractID:     WindowsCodexManagedHookContract(hookExecutable),
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

// windowsCodexMachineArtifactsAbsentUnlocked reports whether every managed
// Codex artifact — and the machine policy lock file — is absent. It uses the
// same lock-observation-lock pattern ResolveWindowsCodexManagedRuntimeRegistry
// applies: two lock-existence probes bracket the artifact check so a
// concurrent writer that publishes between the artifact scan and the caller's
// "nothing to remove" conclusion cannot slip through unseen.
func windowsCodexMachineArtifactsAbsentUnlocked(
	opts WindowsCodexMachineRequirementsOptions,
) (bool, error) {
	lockPath := filepath.Join(filepath.Dir(opts.RequirementsPath), windowsCodexManagedLockFile)
	lockExists, err := windowsCodexMachinePathExists(lockPath)
	if err != nil {
		return false, err
	}
	if lockExists {
		return false, nil
	}
	present, err := windowsCodexMachineAnyArtifactPathExists(opts)
	if err != nil {
		return false, err
	}
	// Close the writer-first-install race before trusting the artifact scan.
	// The Reconcile path always creates the protected lock before publishing
	// policy, so a lock that materialized during the scan means a writer is
	// mid-flight and the caller must defer to the locked path.
	lockExists, err = windowsCodexMachinePathExists(lockPath)
	if err != nil {
		return false, err
	}
	if lockExists {
		return false, nil
	}
	return !present, nil
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
	if err := verifyWindowsCodexRequirementsUsersCanRead(opts.RequirementsPath); err != nil {
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
	if managed.WindowsCurrentProcessIsGatewayService() {
		return errors.New("Codex machine requirements cannot be written by the managed gateway service")
	}
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

// windowsCodexMachineReconcileAttempts bounds how often a reconcile merges, or
// a removal computes its candidate, again after an administrator changed the
// requirements under it.
const windowsCodexMachineReconcileAttempts = 4

// errWindowsCodexMachineFileChanged reports that a file changed after the
// caller read it; the newer file is kept.
var errWindowsCodexMachineFileChanged = errors.New("changed concurrently")

// windowsCodexMachineBeforeConditionalSwap runs just before a conditional
// write swaps its file in; tests replace it to interleave a save.
var windowsCodexMachineBeforeConditionalSwap = func(string) {}

// windowsCodexMachineFileChanged reports a file another writer changed after
// DefenseClaw read it. It wraps safefile.ErrSwapRaced too, as the shared
// writer reports a newer file.
func windowsCodexMachineFileChanged(label string) error {
	return fmt.Errorf("%s %w (%w)", label, errWindowsCodexMachineFileChanged, safefile.ErrSwapRaced)
}

// readWindowsCodexSharedRequirements reads requirements.toml for the shared
// writer: its bytes, as readWindowsCodexMachineFile reads them, and its
// owner, access list and attributes.
func readWindowsCodexSharedRequirements(path string) (safefile.SharedFile, error) {
	file, err := readWindowsCodexMachineFile(path, windowsCodexMachineRequirementsLimit, true, "Codex machine requirements")
	if err != nil {
		return safefile.SharedFile{}, err
	}
	shared := safefile.SharedFile{Path: path, Exists: file.existed, Data: file.data}
	if file.existed {
		if shared.Metadata, err = safefile.ReadPathMetadata(path); err != nil {
			return safefile.SharedFile{}, fmt.Errorf("read Codex machine requirements metadata: %w", err)
		}
	}
	return shared, nil
}

// windowsCodexRequirementsWriter is the shared writer
// (safefile.SharedFileWriter) for the machine requirements.toml, the file the
// Cursor hooks.json writer also uses. Each write is published only over the
// file it was computed from, its bytes, owner, access list and attributes,
// and the file keeps its own metadata; a new file gets DefenseClaw's
// protection. One attempt: reconcile and removal compute the ownership record
// from the file they read, so a newer file runs the whole pass again.
func windowsCodexRequirementsWriter() safefile.SharedFileWriter {
	return safefile.SharedFileWriter{
		Attempts: 1,
		Read:     readWindowsCodexSharedRequirements,
		Write:    writeWindowsCodexSharedRequirements,
	}
}

// publishWindowsCodexRequirements publishes candidate, or removes the file,
// only over base, the file the candidate was computed from. A newer file is
// kept, and the error wraps errWindowsCodexMachineFileChanged. A file that
// ordinary users cannot read is published even when candidate is its
// content, so that it gets the read back.
func publishWindowsCodexRequirements(base safefile.SharedFile, candidate []byte, remove bool) error {
	_, err := windowsCodexRequirementsWriter().Update(base, func(current safefile.SharedFile) (safefile.SharedEdit, error) {
		return safefile.SharedEdit{
			Data: candidate, Remove: remove,
			Rewrite: !remove && windowsCodexRequirementsUnreadable(current),
		}, nil
	})
	return err
}

// windowsCodexRequirementsUnreadable reports a requirements.toml that is
// present and that ordinary users cannot read (safefile.UsersCanRead).
func windowsCodexRequirementsUnreadable(file safefile.SharedFile) bool {
	return file.Exists && safefile.UsersCanRead(file.Metadata) != nil
}

// verifyWindowsCodexRequirementsUsersCanRead is the verification's check
// that ordinary users can read the requirements. Verification reads the file
// elevated, which proves nothing for the users: Codex reads it with each
// user's own token.
func verifyWindowsCodexRequirementsUsersCanRead(path string) error {
	if err := safefile.PathUsersCanRead(path); err != nil {
		return fmt.Errorf("ordinary users cannot read the Codex machine requirements: %w", err)
	}
	return nil
}

// protectWindowsCodexSharedRequirements gives a requirements.toml about to
// be published its access, before it is published: keep, the metadata of the
// file it replaces, or DefenseClaw's protection for a new file, readable by
// every ordinary user (safefile.ProtectReadableByUsers).
func protectWindowsCodexSharedRequirements(path string, keep *safefile.FileMetadata) error {
	return safefile.ProtectReadableByUsers(path, keep, func(path string) error {
		return setWindowsCodexMachineFileProtection(path, true)
	})
}

func writeWindowsCodexSharedRequirements(base safefile.SharedFile, edit safefile.SharedEdit) (safefile.SharedWriteResult, error) {
	const label = "Codex machine requirements"
	const limit = windowsCodexMachineRequirementsLimit
	path := base.Path
	if len(edit.Data) > limit {
		return safefile.SharedWriteResult{}, fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	if err := windowsCodexMachineTrustedDirCheck(filepath.Dir(path), label+" parent"); err != nil {
		return safefile.SharedWriteResult{}, err
	}
	existing, err := readWindowsCodexSharedRequirements(path)
	if err != nil {
		return safefile.SharedWriteResult{}, err
	}
	if !existing.Same(base) {
		return safefile.SharedWriteResult{}, windowsCodexMachineFileChanged(label)
	}
	windowsCodexMachineBeforeConditionalSwap(path)
	if edit.Remove {
		if err := safefile.RemoveSharedFile(base, true, limit, windowsCodexMachineSingleLinkCheck); err != nil {
			if errors.Is(err, safefile.ErrSwapRaced) {
				return safefile.SharedWriteResult{}, windowsCodexMachineFileChanged(label)
			}
			return safefile.SharedWriteResult{}, fmt.Errorf("delete %s: %w", label, err)
		}
		return safefile.SharedWriteResult{Published: true, Left: safefile.SharedFile{Path: path}}, nil
	}
	keep := edit.Metadata
	if keep == nil && base.Exists {
		keep = &base.Metadata
	}
	published, swapped, err := safefile.PublishSharedFile(safefile.SharedPublish{
		Base: base, CompareMetadata: true, Data: edit.Data, Limit: limit,
		Inspect: windowsCodexMachineSingleLinkCheck, TempPattern: ".defenseclaw-codex-*",
		Protect: func(temp string) error { return protectWindowsCodexSharedRequirements(temp, keep) },
	})
	if !swapped {
		if errors.Is(err, safefile.ErrSwapRaced) {
			return safefile.SharedWriteResult{}, windowsCodexMachineFileChanged(label)
		}
		return safefile.SharedWriteResult{}, fmt.Errorf("publish %s: %w", label, err)
	}
	result := safefile.SharedWriteResult{
		Published: true,
		Left:      safefile.SharedFile{Path: path, Exists: true, Data: edit.Data, Metadata: published},
	}
	if err != nil {
		return result, fmt.Errorf("publish %s: %w", label, err)
	}
	persisted, err := readWindowsCodexMachineFile(path, limit, false, label)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(persisted.data, edit.Data) {
		// Another writer saved right after the swap. Its file is newer and is
		// kept; the caller computes its edit again from it.
		return result, fmt.Errorf("%s %w after publication", label, errWindowsCodexMachineFileChanged)
	}
	if err := safefile.PathUsersCanRead(path); err != nil {
		// An access list change landed with the swap and took the read from
		// ordinary users. The caller publishes again over it, with the read.
		return result, fmt.Errorf("%s %w after publication: %v", label, errWindowsCodexMachineFileChanged, err)
	}
	return result, nil
}

// writeWindowsCodexMachineFile atomically replaces one of DefenseClaw's own
// Codex files (ownership, runtime state) with data and DefenseClaw's
// protection, under the Codex machine lock.
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

// windowsCodexMachineSingleLinkCheck refuses a file with other hard links,
// as readWindowsCodexMachineFile does.
func windowsCodexMachineSingleLinkCheck(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s has %d hardlinks", file.Name(), info.NumberOfLinks)
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

// WindowsCodexStandaloneHookContract is the hook contract the standalone
// profile binds into every Codex machine-requirements command when
// hookBinary is the standalone install's hook launcher, and "" for any
// other launcher. The standalone launcher path derives from the protected
// HKLM Program Files registration, never the caller's environment, so the
// hook process (which runs with the agent's environment) and the SYSTEM
// lifecycle render and verify the same commands.
func WindowsCodexStandaloneHookContract(hookBinary string) string {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return ""
	}
	return windowsCodexStandaloneHookContractFor(layout, hookBinary)
}

// WindowsCodexManagedHookContract is the hook contract every Windows Codex
// machine-requirements command binds, for both profiles: the standalone
// launcher's contract, else the default Codex contract, which registers
// every event of the published group matrix. A bound command names its
// event and contract and waits for the GUI-subsystem launcher. The Secure
// Client profile used to keep the pre-1.0 call-operator command instead; the
// hook refuses it (it names no event or contract) and the call operator does
// not wait for the launcher, so its exit code (2 blocks) never reached Codex.
func WindowsCodexManagedHookContract(hookBinary string) string {
	if contract := WindowsCodexStandaloneHookContract(hookBinary); contract != "" {
		return contract
	}
	return ResolveHookContract("codex", "").Contract.ContractID
}
