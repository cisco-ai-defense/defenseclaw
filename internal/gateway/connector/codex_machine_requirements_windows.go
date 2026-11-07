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
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const windowsCodexMachineLockTimeout = 10 * time.Second

var (
	windowsCodexMachineProcessMu sync.Mutex

	windowsCodexMachineProgramData     = winpath.TrustedProgramData
	windowsCodexMachineTrustedDirCheck = func(path, label string) error {
		return ensureWindowsCodexMachineDirTrust(path, label)
	}
	windowsCodexMachineTrustedFileCheck = func(path, label string) error {
		return managed.ValidateTrustedFilePath(path, label)
	}
	// windowsCodexMachineStructureFileCheck keeps only the structural half of
	// the trust walk (reparse points, links, object type, volume). It decides
	// whether a failed strict check was permission drift or a real boundary.
	windowsCodexMachineStructureFileCheck = func(path, label string) error {
		return managed.ValidateTrustedFileStructureTolerant(path, label)
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
		managedState, err := readWindowsCodexManagedState(opts.ManagedStatePath, true)
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
				managed.EmitResilienceEvent(managed.MarkerRecover, map[string]string{
					"path":   opts.OwnershipPath,
					"reason": "reclaiming unparseable Codex ownership: " + err.Error(),
				})
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
				managed.EmitResilienceEvent(managed.MarkerRecover, map[string]string{
					"path": opts.OwnershipPath,
					"reason": "reclaiming identity-drifted Codex ownership " +
						"(prior install's layout does not match current scope): " + err.Error(),
				})
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

		// The file is DefenseClaw's own publication when it still holds, byte
		// for byte, the postimage the trusted record names.
		ownPublication := !ownershipAdopted && requirements.existed &&
			windowsCodexMachineHash(requirements.data) == state.PostimageSHA256
		rendered, _, err := reconcileWindowsCodexRequirements(requirementsBase, opts, ownPublication)
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
			if err := writeWindowsCodexManagedState(opts.ManagedStatePath, runtimeBytes); err != nil {
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
		report.RequirementsHeldBy = windowsCodexRequirementsHeldBy(err)
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
			managedState, readErr := readWindowsCodexManagedState(opts.ManagedStatePath, true)
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
		managedState, err := readWindowsCodexManagedState(opts.ManagedStatePath, false)
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
		// Content-hash pins are advisory: an outside edit that keeps the exact
		// DefenseClaw hooks (checked above) is reported here and re-pinned by
		// the next privileged reconcile, never failed.
		if state.PostimageSHA256 != report.PostimageSHA256 {
			report.PinMismatch = true
			managedPinMismatch(opts.RequirementsPath, "ownership postimage",
				state.PostimageSHA256, report.PostimageSHA256)
		}
		runtime, err := parseWindowsCodexManagedRuntimeState(managedState.data)
		if err != nil {
			return fmt.Errorf("parse Codex managed runtime state: %w", err)
		}
		if err := validateWindowsCodexManagedRuntimeStateIdentity(runtime, opts); err != nil {
			return err
		}
		if runtime.RequirementsSHA256 != report.PostimageSHA256 {
			report.PinMismatch = true
			managedPinMismatch(opts.RequirementsPath, "managed runtime state",
				runtime.RequirementsSHA256, report.PostimageSHA256)
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
//
// This is the strict removal every caller but an uninstall uses (the disabled
// Codex reconcile, the hidden remove action and the guardian): a link at the
// Codex machine-policy folder is refused, never reported as removed, so
// SafeToRemoveBinary is never claimed for a folder that was not read. The
// uninstall alone calls RemoveWindowsCodexMachineRequirementsForTeardown.
func RemoveWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	return removeWindowsCodexMachineRequirements(opts, false)
}

// RemoveWindowsCodexMachineRequirementsForTeardown is the removal an uninstall
// makes (GAP-0773). It is RemoveWindowsCodexMachineRequirements, except that a
// link at the Codex machine-policy folder (standalone profile only) is kept,
// not followed and not read: the result is ok with disposition "link_kept" and
// LinkKept set to the link, and it attests neither SafeToRemoveBinary nor
// ManagedStateRemovedOrAbsent, because nothing behind the link was checked. A
// Codex requirement behind it may still name the hook binary the uninstall
// removes; the caller says so where it names the kept link.
func RemoveWindowsCodexMachineRequirementsForTeardown(
	opts WindowsCodexMachineRequirementsOptions,
) (WindowsCodexMachineRequirementsReport, error) {
	return removeWindowsCodexMachineRequirements(opts, true)
}

func removeWindowsCodexMachineRequirements(
	opts WindowsCodexMachineRequirementsOptions,
	keepLink bool,
) (WindowsCodexMachineRequirementsReport, error) {
	report := windowsCodexMachineReport("remove", opts)
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		report.Error = err.Error()
		return report, err
	}
	if keepLink {
		// A link at the Codex machine-policy folder is kept and named
		// (GAP-0773): nothing behind it is read, opened, locked, written or
		// deleted, and the removal does not fail on it. Standalone only.
		kept, err := WindowsCodexMachineFolderKept()
		if err != nil {
			report.Error = err.Error()
			return report, err
		}
		if kept != "" {
			report.OK = true
			report.Disposition = "link_kept"
			report.LinkKept = kept
			report.Details = append(report.Details, windowsCodexMachineLinkKeptDetail(kept))
			return report, nil
		}
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
		managedState, err := readWindowsCodexManagedState(opts.ManagedStatePath, true)
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

		candidate, candidateExists, changed, disposition, err := windowsCodexRemovalCandidate(
			requirements.data, requirements.existed, state, opts,
		)
		if err != nil {
			return err
		}
		report.Changed = changed
		report.Disposition = disposition

		// Validate the complete candidate before the first mutation. In
		// particular, an unrelated administrator hook that still points into
		// our install tree must leave requirements, ownership, and runtime
		// state byte-for-byte intact on a blocked removal.
		contains, err := windowsCodexRequirementsContainExactManagedHook(candidate, opts)
		if err != nil {
			return err
		}
		if !contains {
			if contains, err = windowsCodexRequirementsHoldOwnedLeftovers(candidate, opts); err != nil {
				return err
			}
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
			if err := deleteWindowsCodexManagedState(opts.ManagedStatePath); err != nil {
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
		report.RequirementsHeldBy = windowsCodexRequirementsHeldBy(err)
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
		return writeWindowsCodexManagedState(opts.ManagedStatePath, data)
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
		stateFile, err := readWindowsCodexManagedState(opts.ManagedStatePath, false)
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
		return writeWindowsCodexManagedState(opts.ManagedStatePath, body)
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
	writerLockPath := filepath.Join(filepath.Dir(requirementsPath), WindowsCodexManagedWriterLockFile)
	legacyLockPath := filepath.Join(filepath.Dir(requirementsPath), windowsCodexManagedLegacyLockFile)
	// resolve reads the state from stateFile: the hook copy the even counter
	// names once a writer of this release has run, the fixed name before.
	resolve := func(stateFile string) (WindowsCodexManagedRuntimeRegistry, error) {
		return resolveWindowsCodexManagedRuntimeRegistryLocked(requirementsPath, statePath, stateFile, hookExecutable)
	}
	writerLock, err := windowsCodexMachinePathExists(writerLockPath)
	if err != nil {
		return result, err
	}
	if writerLock {
		return resolveWindowsCodexManagedRuntimeRegistryStable(writerLockPath, resolve)
	}
	legacyLock, err := windowsCodexMachinePathExists(legacyLockPath)
	if err != nil {
		return result, err
	}
	if legacyLock {
		// Upgrade from 1.0.8 or earlier: no writer of this release has run
		// yet. Every writer creates its lock before it changes a file, so a
		// writer lock that exists after this read means one may have run
		// during it, and the read is taken again against the counter.
		result, err = resolveWindowsCodexManagedRuntimeRegistryLegacy(legacyLockPath, func() (WindowsCodexManagedRuntimeRegistry, error) {
			return resolve(statePath)
		})
		started, existsErr := windowsCodexMachinePathExists(writerLockPath)
		if existsErr != nil {
			return WindowsCodexManagedRuntimeRegistry{}, existsErr
		}
		if started {
			return resolveWindowsCodexManagedRuntimeRegistryStable(writerLockPath, resolve)
		}
		return result, err
	}
	requirementsExists, err := windowsCodexMachinePathExists(requirementsPath)
	if err != nil {
		return result, err
	}
	stateExists, err := windowsCodexMachinePathExists(statePath)
	if err != nil {
		return result, err
	}
	// Close the first-install race before using either unlocked observation.
	// The writer always creates its lock before publishing policy.
	writerLock, err = windowsCodexMachinePathExists(writerLockPath)
	if err != nil {
		return result, err
	}
	if writerLock {
		return resolveWindowsCodexManagedRuntimeRegistryStable(writerLockPath, resolve)
	}
	if requirementsExists || stateExists {
		return result, errors.New("the Codex managed artifacts exist without the machine policy lock")
	}
	return result, nil
}

// windowsCodexTransactionCounterRead reads the writer lock's transaction
// counter; tests replace it.
var windowsCodexTransactionCounterRead = readWindowsCodexTransactionCounter

// windowsCodexReaderWait bounds how long the hook-side reader waits for a
// writer's transaction to finish, as long as the old shared lock waited;
// tests shorten it.
var windowsCodexReaderWait = windowsCodexMachineLockTimeout

// resolveWindowsCodexManagedRuntimeRegistryStable runs resolve without any
// lock, so no reader can make a writer wait (GAP-0650), and keeps its result
// only when the writer lock's transaction counter was even (no transaction
// running) and unchanged across the whole read: requirements.toml and the
// hook copy of the state that counter names were then read as one committed
// pair. Otherwise it reads again.
// When no stable read is possible within windowsCodexReaderWait it fails
// closed, as a timed-out wait for the old lock did.
func resolveWindowsCodexManagedRuntimeRegistryStable(
	lockPath string,
	resolve func(stateFile string) (WindowsCodexManagedRuntimeRegistry, error),
) (WindowsCodexManagedRuntimeRegistry, error) {
	if err := windowsCodexMachineTrustedDirCheck(filepath.Dir(lockPath), "Codex machine policy lock parent"); err != nil {
		return WindowsCodexManagedRuntimeRegistry{}, err
	}
	if err := ensureWindowsCodexMachineFileTrust(lockPath, "Codex machine policy writer lock", false); err != nil {
		return WindowsCodexManagedRuntimeRegistry{}, err
	}
	deadline := time.Now().Add(windowsCodexReaderWait)
	for {
		before, err := windowsCodexTransactionCounterRead(lockPath)
		if err != nil {
			return WindowsCodexManagedRuntimeRegistry{}, err
		}
		if before%2 == 0 {
			result, resolveErr := resolve(windowsCodexStableStateFile(filepath.Dir(lockPath), before))
			after, err := windowsCodexTransactionCounterRead(lockPath)
			if err != nil {
				return WindowsCodexManagedRuntimeRegistry{}, err
			}
			if after == before {
				return result, resolveErr
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return WindowsCodexManagedRuntimeRegistry{}, fmt.Errorf(
				"timed out waiting %s for a Codex machine policy transaction to finish",
				windowsCodexReaderWait,
			)
		}
		delay := 25 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}

// windowsCodexStableStateFile is the state file a stable read at counter
// uses: the hook copy the counter names. A counter of 0 is a writer lock no
// transaction has used yet (a writer of this release creating it on a host
// that 1.0.8 set up), whose state is still the fixed name.
func windowsCodexStableStateFile(dir string, counter uint64) string {
	if counter == 0 {
		return filepath.Join(dir, windowsCodexManagedStateFile)
	}
	return windowsCodexManagedStateGenerationPath(dir, counter)
}

// resolveWindowsCodexManagedRuntimeRegistryLegacy reads under the shared lock
// of 1.0.8 and earlier, for a host no writer of this release has reached yet.
func resolveWindowsCodexManagedRuntimeRegistryLegacy(
	lockPath string,
	resolve func() (WindowsCodexManagedRuntimeRegistry, error),
) (WindowsCodexManagedRuntimeRegistry, error) {
	windowsCodexMachineProcessMu.Lock()
	defer windowsCodexMachineProcessMu.Unlock()
	lock, overlapped, err := acquireWindowsCodexMachineFileLockMode(lockPath, true)
	if err != nil {
		return WindowsCodexManagedRuntimeRegistry{}, err
	}
	defer windows.CloseHandle(lock)
	defer windows.UnlockFileEx(lock, 0, 1, 0, overlapped)
	return resolve()
}

// readWindowsCodexTransactionCounter returns the size of the writer lock,
// through a handle that asks for the attributes only: such a handle takes no
// part in sharing, so the hook's read never stops a writer from opening it.
func readWindowsCodexTransactionCounter(path string) (uint64, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("read the Codex machine policy transaction counter: %w", err)
	}
	defer windows.CloseHandle(handle)
	return windowsCodexWriterLockCounter(handle)
}

func windowsCodexWriterLockCounter(handle windows.Handle) (uint64, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, fmt.Errorf("inspect Codex machine policy lock handle: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 {
		return 0, fmt.Errorf(
			"the Codex machine policy lock must be a no-reparse single-link regular file (links=%d)",
			info.NumberOfLinks,
		)
	}
	return uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow), nil
}

// resolveWindowsCodexManagedRuntimeRegistryLocked reads requirementsPath and
// the state in stateFile; statePath is the logical state path the identity
// checks name.
func resolveWindowsCodexManagedRuntimeRegistryLocked(
	requirementsPath string,
	statePath string,
	stateFile string,
	hookExecutable string,
) (WindowsCodexManagedRuntimeRegistry, error) {
	var result WindowsCodexManagedRuntimeRegistry
	requirementsExists, err := windowsCodexMachinePathExists(requirementsPath)
	if err != nil {
		return result, err
	}
	stateExists, err := windowsCodexMachinePathExists(stateFile)
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
	stateCopy, err := readWindowsCodexMachineFile(
		stateFile,
		windowsCodexManagedStateLimit,
		false,
		"Codex managed runtime state",
	)
	if err != nil {
		return result, err
	}
	state, err := parseWindowsCodexManagedRuntimeState(stateCopy.data)
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
	if live := windowsCodexMachineHash(requirements.data); state.RequirementsSHA256 != live {
		// The exact DefenseClaw hooks were verified above; a stale hash pin
		// alone only means an outside edit landed before the next reconcile.
		managedPinMismatch(requirementsPath, "managed runtime state", state.RequirementsSHA256, live)
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
// Codex artifact — and both machine policy lock files — is absent. It uses the
// same lock-observation-lock pattern ResolveWindowsCodexManagedRuntimeRegistry
// applies: two lock-existence probes bracket the artifact check so a
// concurrent writer that publishes between the artifact scan and the caller's
// "nothing to remove" conclusion cannot slip through unseen.
func windowsCodexMachineArtifactsAbsentUnlocked(
	opts WindowsCodexMachineRequirementsOptions,
) (bool, error) {
	lockExists := func() (bool, error) {
		for _, name := range []string{WindowsCodexManagedWriterLockFile, windowsCodexManagedLegacyLockFile} {
			exists, err := windowsCodexMachinePathExists(filepath.Join(filepath.Dir(opts.RequirementsPath), name))
			if err != nil || exists {
				return exists, err
			}
		}
		return false, nil
	}
	locked, err := lockExists()
	if err != nil || locked {
		return false, err
	}
	present, err := windowsCodexMachineAnyArtifactPathExists(opts)
	if err != nil {
		return false, err
	}
	// Close the writer-first-install race before trusting the artifact scan.
	// The Reconcile path always creates the protected lock before publishing
	// policy, so a lock that materialized during the scan means a writer is
	// mid-flight and the caller must defer to the locked path.
	locked, err = lockExists()
	if err != nil || locked {
		return false, err
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
	if state.Pending {
		return errors.New("Codex requirements ownership contains an incomplete transaction")
	}
	if state.PostimageSHA256 != hash {
		managedPinMismatch(opts.RequirementsPath, "ownership postimage", state.PostimageSHA256, hash)
	}
	managedState, err := readWindowsCodexManagedState(opts.ManagedStatePath, false)
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
		// Publish and target removal re-pin the state to the live bytes, so
		// a stale pin here must not stop them.
		managedPinMismatch(opts.RequirementsPath, "managed runtime state", runtime.RequirementsSHA256, hash)
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
	locked := func() error {
		// The lock wait is bounded but may still outlive an operator mount or
		// policy change. Re-establish the complete path identity immediately
		// before the protected read or mutation.
		if err := validateWindowsCodexMachineLayout(opts); err != nil {
			return fmt.Errorf("revalidate Codex machine layout after lock acquisition: %w", err)
		}
		return fn()
	}
	if windowsCodexSecureClientTransactions(opts) {
		return withWindowsCodexSecureClientPolicyLock(opts.RequirementsPath, locked)
	}
	// A requirements.toml, or a state file of 1.0.8, that a user holds open
	// fails the transaction with the holder named; the whole transaction is
	// run again, without the writer lock, for a bounded time while the file
	// stays held.
	return withWindowsCodexRequirementsReleaseRetry(func() error {
		return withWindowsCodexMachinePolicyLock(opts.RequirementsPath, locked)
	})
}

// windowsCodexSecureClientTransactions reports that opts is the Secure Client
// profile. The writer lock, the transaction counter, the per-transaction state
// copies and the wait for a held requirements.toml (GAP-0650) exist on the
// standalone profile only: Secure Client hooks and writers keep the shared lock
// and the fixed-name state of 1.0.8 and earlier, so nothing about Secure
// Client changes with them. Windows has two enterprise profiles, standalone
// and Secure Client (managed.ProfileStandalone, managed.ProfileSecureClient).
func windowsCodexSecureClientTransactions(opts WindowsCodexMachineRequirementsOptions) bool {
	return opts.SecureClient
}

// withWindowsCodexSecureClientPolicyLock runs fn under the lock of 1.0.8 and
// earlier, exclusively, with the state read and written at its fixed name.
func withWindowsCodexSecureClientPolicyLock(requirementsPath string, fn func() error) error {
	return withWindowsCodexMachinePolicyLockMode(requirementsPath, false, func() error {
		windowsCodexActiveManagedState = &windowsCodexManagedStateTx{dir: filepath.Dir(requirementsPath), direct: true}
		defer func() { windowsCodexActiveManagedState = nil }()
		return fn()
	})
}

// withWindowsCodexMachinePolicyLockMode is the lock of 1.0.8 and earlier:
// exclusive for Secure Client writers, shared for the hook that reads while no
// writer lock of this release exists.
func withWindowsCodexMachinePolicyLockMode(
	requirementsPath string,
	shared bool,
	fn func() error,
) error {
	windowsCodexMachineProcessMu.Lock()
	defer windowsCodexMachineProcessMu.Unlock()

	lockPath := filepath.Join(
		filepath.Dir(requirementsPath),
		windowsCodexManagedLegacyLockFile,
	)
	lock, overlapped, err := acquireWindowsCodexMachineFileLockMode(lockPath, shared)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	defer windows.UnlockFileEx(lock, 0, 1, 0, overlapped)
	return fn()
}

// windowsCodexWriterLockSDDL is the writer lock's descriptor: Administrators
// and SYSTEM have full control, and BUILTIN\Users may only read the
// attributes (the transaction counter) and the descriptor. No standard user
// can open it for data, so none can share-lock it, byte-range-lock it or
// hold it against a writer (GAP-0650).
const windowsCodexWriterLockSDDL = "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x120080;;;BU)"

// windowsCodexWriterLockUsersAccess is all BUILTIN\Users holds on the writer
// lock: read attributes, read control and synchronize.
const windowsCodexWriterLockUsersAccess = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE

// windowsCodexWriterLockRangeHigh places the writers' one-byte range lock at
// 4 GiB, far past the counter, so moving the end of file never touches it.
const windowsCodexWriterLockRangeHigh = 1

// windowsCodexTransactionCounterWrap keeps the counter (the lock's size)
// small; a reader only compares two values a moment apart.
const windowsCodexTransactionCounterWrap = 1 << 20

// withWindowsCodexMachinePolicyLock runs fn as one Codex machine-policy
// transaction: it holds the writer lock exclusively and keeps the
// transaction counter odd while fn runs, so the hook-side reader never keeps
// what it read during a transaction and never needs a lock of its own.
func withWindowsCodexMachinePolicyLock(
	requirementsPath string,
	fn func() error,
) (err error) {
	windowsCodexMachineProcessMu.Lock()
	defer windowsCodexMachineProcessMu.Unlock()

	dir := filepath.Dir(requirementsPath)
	lock, overlapped, err := acquireWindowsCodexWriterLock(filepath.Join(dir, WindowsCodexManagedWriterLockFile))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	defer windows.UnlockFileEx(lock, 0, 1, 0, overlapped)
	previous, err := windowsCodexWriterLockCounter(lock)
	if err != nil {
		return err
	}
	end, err := beginWindowsCodexTransaction(lock, func(counter uint64) bool {
		return windowsCodexStateGenerationTaken(dir, counter)
	})
	if err != nil {
		return err
	}
	// The state is committed while the counter is still odd, and the hook
	// copy is closed before the counter becomes even. The counter ends on the
	// value the transaction began at when nothing was written (a state that
	// could not be read, a pass that changed nothing): the hook copy that
	// value names is still the pair the hook should read (g582 round 9 S1, L1).
	state, stateErr := beginWindowsCodexManagedState(dir, end)
	defer func() {
		final := end
		if state != nil {
			windowsCodexActiveManagedState = nil
			counter, commitErr := state.settle(previous)
			final = counter
			if commitErr != nil {
				err = errors.Join(err, fmt.Errorf("commit the Codex managed runtime state: %w", commitErr))
			}
		} else if stateErr != nil {
			final = previous
		}
		if endErr := setWindowsCodexTransactionCounter(lock, final); endErr != nil {
			err = errors.Join(err, fmt.Errorf("end the Codex machine policy transaction: %w", endErr))
		}
	}()
	if stateErr != nil {
		return stateErr
	}
	windowsCodexActiveManagedState = state
	removeWindowsCodexLegacyLock(filepath.Join(dir, windowsCodexManagedLegacyLockFile))
	return fn()
}

// beginWindowsCodexTransaction makes the counter odd and returns the even
// value that ends the transaction. An odd counter on entry is a writer that
// stopped mid-transaction; the new odd value still differs from it. An end
// value taken reports is skipped: a hook copy of the state named for it is
// still held open from before the counter wrapped.
func beginWindowsCodexTransaction(lock windows.Handle, taken func(uint64) bool) (uint64, error) {
	counter, err := windowsCodexWriterLockCounter(lock)
	if err != nil {
		return 0, err
	}
	start := counter + 1
	if counter%2 == 1 {
		start = counter + 2
	}
	for skipped := 0; ; skipped++ {
		if start >= windowsCodexTransactionCounterWrap {
			start = 1
		}
		if !taken(start+1) || skipped == windowsCodexTransactionCounterWrap/2 {
			break
		}
		start += 2
	}
	if err := setWindowsCodexTransactionCounter(lock, start); err != nil {
		return 0, fmt.Errorf("begin the Codex machine policy transaction: %w", err)
	}
	return start + 1, nil
}

func setWindowsCodexTransactionCounter(lock windows.Handle, value uint64) error {
	if value >= windowsCodexTransactionCounterWrap+2 {
		return fmt.Errorf("the Codex machine policy transaction counter %d is out of range", value)
	}
	if _, err := windows.SetFilePointer(lock, int32(value), nil, windows.FILE_BEGIN); err != nil {
		return err
	}
	return windows.SetEndOfFile(lock)
}

// removeWindowsCodexLegacyLock deletes the lock of 1.0.8 and earlier once a
// writer of this release holds its own, so hooks stop falling back to it. A
// copy another process still holds open stays until a later transaction.
func removeWindowsCodexLegacyLock(path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	_ = deleteWindowsCodexMachineFile(path, "Codex machine policy lock of an earlier release")
}

// acquireWindowsCodexWriterLock opens, creates with its descriptor, or puts
// back to its descriptor the writer lock, and takes it exclusively, waiting
// at most windowsCodexMachineLockTimeout for another writer.
func acquireWindowsCodexWriterLock(path string) (windows.Handle, *windows.Overlapped, error) {
	if err := windowsCodexMachineTrustedDirCheck(filepath.Dir(path), "Codex machine policy lock parent"); err != nil {
		return 0, nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, nil, fmt.Errorf("the Codex machine policy lock is not a regular non-link file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, nil, fmt.Errorf("inspect Codex machine policy lock: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsCodexWriterLockSDDL)
	if err != nil {
		return 0, nil, fmt.Errorf("build Codex machine policy lock descriptor: %w", err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
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
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&attributes,
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
	if _, err := windowsCodexWriterLockCounter(handle); err != nil {
		return closeOnError(err)
	}
	if err := ensureWindowsCodexWriterLockDescriptor(handle, path); err != nil {
		return closeOnError(err)
	}
	overlapped := &windows.Overlapped{OffsetHigh: windowsCodexWriterLockRangeHigh}
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

// ensureWindowsCodexWriterLockDescriptor keeps the writer lock at exactly
// windowsCodexWriterLockSDDL, through the open handle. The lock carries no
// content, so drift is put back in place in every profile, as for the other
// transaction locks; an owner outside the administrator set is refused.
func ensureWindowsCodexWriterLockDescriptor(handle windows.Handle, path string) error {
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect Codex machine policy lock descriptor: %w", err)
	}
	drift := windowsCodexWriterLockDescriptorDrift(current)
	if drift == "" {
		return nil
	}
	owner, _, err := current.Owner()
	trustedOwner := err == nil && owner != nil &&
		(managed.IsWindowsTrustedAdminOwner(owner) || managed.WindowsAdminEquivalentPrincipal(owner))
	if !trustedOwner {
		ownerText := "an unreadable owner"
		if owner != nil {
			ownerText = owner.String()
		}
		return fmt.Errorf(
			"the Codex machine policy lock %s is owned by %s, not an administrator: from an elevated prompt delete it (del /a:h %q), then run Setup /ensure",
			path, ownerText, path,
		)
	}
	canonical, err := windows.SecurityDescriptorFromString(windowsCodexWriterLockSDDL)
	if err != nil {
		return err
	}
	canonicalOwner, _, err := canonical.Owner()
	if err != nil {
		return err
	}
	canonicalDACL, _, err := canonical.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		canonicalOwner, nil, canonicalDACL, nil); err != nil {
		return fmt.Errorf("protect Codex machine policy lock: %w", err)
	}
	repaired, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect Codex machine policy lock descriptor: %w", err)
	}
	if after := windowsCodexWriterLockDescriptorDrift(repaired); after != "" {
		return fmt.Errorf("the Codex machine policy lock %s is still not protected: %s", path, after)
	}
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"path":   path,
		"reason": "re-stamped the Codex machine policy writer lock descriptor after: " + drift,
	})
	return nil
}

// windowsCodexWriterLockDescriptorDrift says how descriptor differs from
// windowsCodexWriterLockSDDL, or "" when it matches.
func windowsCodexWriterLockDescriptorDrift(descriptor *windows.SECURITY_DESCRIPTOR) string {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return "the owner is not Administrators"
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return "the access list is not protected"
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return "the access list is missing"
	}
	const fileAllAccess = 0x1f01ff
	want := map[string]uint32{
		"S-1-5-32-544": fileAllAccess,
		"S-1-5-18":     fileAllAccess,
		"S-1-5-32-545": windowsCodexWriterLockUsersAccess,
	}
	if int(dacl.AceCount) != len(want) {
		return fmt.Sprintf("the access list has %d entries, want %d", dacl.AceCount, len(want))
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Sprintf("entry %d cannot be read", index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return fmt.Sprintf("entry %d is not a plain allow entry", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		mask, ok := want[sid]
		if !ok || uint32(ace.Mask) != mask {
			return fmt.Sprintf("entry %d gives %s access 0x%x", index, sid, uint32(ace.Mask))
		}
		delete(want, sid)
	}
	return ""
}

// acquireWindowsCodexMachineFileLockMode is the lock of 1.0.8 and earlier,
// byte for byte. Secure Client writers still take it exclusively, and every
// hook takes it shared while no writer lock of this release exists, so Secure
// Client keeps the behavior it had before GAP-0650 (g582 round 9, Secure
// Client rule). The standalone writers take acquireWindowsCodexWriterLock.
func acquireWindowsCodexMachineFileLockMode(
	path string,
	shared bool,
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
		if err := ensureWindowsCodexMachineFileTrust(path, "Codex machine policy lock", true); err != nil {
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
	lockFlags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if shared {
		lockFlags = windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	for {
		err = windows.LockFileEx(
			handle,
			lockFlags,
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
	// The writer copy and the hook copies of the state.
	entries, err := os.ReadDir(filepath.Dir(opts.ManagedStatePath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect Codex artifact folder %s: %w", filepath.Dir(opts.ManagedStatePath), err)
	}
	for _, entry := range entries {
		if windowsCodexManagedStateCopyName(entry.Name()) {
			return true, nil
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
	if err := ensureWindowsCodexMachineFileTrust(path, "Codex managed hook binary", false); err != nil {
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
	info, err := pathidentity.LstatPinned(path)
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
	if err := ensureWindowsCodexMachineFileTrust(path, label, true); err != nil {
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
	// The handle must hold the file the trust check passed: the check after
	// the read proves only that the path names that file again.
	if opened, err := file.Stat(); err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return result, fmt.Errorf("%s changed identity before it was opened", label)
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
	if tx := windowsCodexActiveManagedState; tx != nil && !tx.direct &&
		windowsCodexRequirementsPublishChanges(base, candidate, remove, windowsCodexRequirementsUnreadable(base)) {
		tx.requirementsTouched = true
	}
	_, err := windowsCodexRequirementsWriter().Update(base, func(current safefile.SharedFile) (safefile.SharedEdit, error) {
		return safefile.SharedEdit{
			Data: candidate, Remove: remove,
			Rewrite: !remove && windowsCodexRequirementsUnreadable(current),
		}, nil
	})
	return windowsCodexRequirementsHeldFailure(base.Path, err)
}

// windowsCodexRequirementsPublishChanges reports whether publishing candidate
// over base writes requirements.toml: a removal of a file that exists, a new
// file, other bytes, or the read an unreadable file lacks. A publish that
// would leave the file as it is (unreadable: ordinary users cannot read it,
// so it is published again with the read) does not count as a change of the pair the
// hook reads, so the transaction keeps its hook copy and counter (g582
// round 11, GAP-0764).
func windowsCodexRequirementsPublishChanges(base safefile.SharedFile, candidate []byte, remove, unreadable bool) bool {
	if remove {
		return base.Exists
	}
	return !base.Exists || !bytes.Equal(base.Data, candidate) || unreadable
}

// windowsCodexRequirementsUnreadable reports a requirements.toml that is
// present and that ordinary users cannot read (safefile.UsersCanRead).
func windowsCodexRequirementsUnreadable(file safefile.SharedFile) bool {
	return file.Exists && safefile.UsersCanRead(file.Metadata) != nil
}

// WindowsCodexRequirementsUnreadable reports a requirements.toml at path that
// is present and that ordinary users cannot read. The reconcile publishes
// such a file again with the read restored; it reads the access list only,
// so a program that holds the file open does not change the answer.
func WindowsCodexRequirementsUnreadable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	metadata, err := safefile.ReadPathMetadata(path)
	if err != nil {
		return false
	}
	return safefile.UsersCanRead(metadata) != nil
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
		Class: safefile.PublishDefenseClawOwned,
		Base:  base, CompareMetadata: true, Data: edit.Data, Limit: limit,
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
	// ReplaceFileW refuses a ReadOnly destination with access denied, which
	// would leave the ownership record pending. Clear the attribute for the
	// publication and put it back on the published file afterwards.
	restoreReadOnly, err := clearWindowsManagedReadOnly(path)
	if err != nil {
		cleanup()
		return fmt.Errorf("prepare %s for publication: %w", label, err)
	}
	defer func() {
		if restoreErr := restoreReadOnly(); restoreErr != nil {
			emitManagedResilience(managed.MarkerAccept, path,
				"could not restore ReadOnly attribute after publication: "+restoreErr.Error(), nil)
		}
	}()
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
	base := filepath.Base(path)
	if _, generation := windowsCodexManagedStateGenerationOf(base); generation {
		return true
	}
	return strings.EqualFold(base, "requirements.toml") ||
		strings.EqualFold(base, windowsCodexManagedStateFile) ||
		strings.EqualFold(base, windowsCodexManagedLegacyLockFile)
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
	return deleteWindowsCodexMachineFileChecked(path, label, true)
}

// deleteWindowsCodexManagedStateCopy removes a copy of the Codex managed
// runtime state (a hook copy or the fixed name of 1.0.8) without judging its
// access list first. DefenseClaw wrote the file and only removes it, and a
// copy that was given another access list is exactly the one that has to go:
// judging it first refused the delete on a standalone deployment, so a
// replaced copy with a drifted list stayed in the folder for good, through
// every later pass and the purge (g582 round 11c). The handle-bound checks
// stay: a regular file, no reparse point, one link.
func deleteWindowsCodexManagedStateCopy(path string) error {
	return deleteWindowsCodexMachineFileChecked(path, windowsCodexManagedStateLabel, false)
}

func deleteWindowsCodexMachineFileChecked(path, label string, judgeAccessList bool) error {
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
	if judgeAccessList {
		if err := ensureWindowsCodexMachineFileTrust(path, label, true); err != nil {
			return err
		}
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

// ensureWindowsCodexMachineFileTrust is the trust gate for every existing
// Codex machine file. Structure (reparse points, links, object type, volume)
// stays fatal. Permission drift is repaired first when repairable is set and
// the process is the installer or the LocalSystem guardian; whatever cannot
// be repaired, including drift seen by a standard-user hook, is accepted and
// logged on Secure Client so it never stops reconcile, verify or the hook,
// and refused on standalone (GAP-0561).
//
// On standalone a drifted file is refused with the strict verdict and never
// repaired in place (managed.StandaloneRefusesContentDrift): a repair restores
// the descriptor, not hooks an untrusted writer removed. Setup refuses it as
// well, before it stops anything, and the refusal names the recovery
// (GAP-0561, GAP-0590).
func ensureWindowsCodexMachineFileTrust(path, label string, repairable bool) error {
	strictErr := windowsCodexMachineTrustedFileCheck(path, label)
	if strictErr == nil {
		return nil
	}
	if managed.StandaloneRefusesContentDrift() {
		return managed.RefuseStandaloneContentDrift(strictErr)
	}
	if err := windowsCodexMachineStructureFileCheck(path, label); err != nil {
		return err
	}
	drift, driftErr := windowsCodexMachineFileDrift(path)
	if driftErr != nil && isManagedDescriptorStructural(driftErr) {
		// A descriptor this code cannot classify is structural, not drift.
		return errors.Join(strictErr, driftErr)
	}
	reason := strictErr.Error()
	if driftErr != nil {
		reason += "; descriptor model unavailable: " + driftErr.Error()
	} else if !drift.Canonical {
		reason = drift.Reason() + ": " + reason
	}
	if repairable && driftErr == nil && !drift.Canonical && windowsManagedCanRepair() {
		if repairErr := repairWindowsCodexMachineFileProtection(path); repairErr != nil {
			reason += "; repair failed: " + repairErr.Error()
		} else if recheckErr := windowsCodexMachineTrustedFileCheck(path, label); recheckErr == nil {
			emitManagedRepairResilience(drift, true, path,
				"re-stamped canonical protection: "+reason, map[string]string{"label": label})
			return nil
		} else {
			// The leaf is canonical now; what remains is outside it, such as
			// a drifted ancestor, and is accepted below.
			strictErr = recheckErr
			reason = "re-stamped leaf; remaining: " + recheckErr.Error()
		}
	}
	if managed.TrustStrictAncestors() {
		return strictErr
	}
	emitManagedResilience(managedDriftMarker(drift, false, true), path,
		"accepted permission drift: "+reason, map[string]string{"label": label})
	return nil
}

// windowsCodexMachineCanonicalDescriptorSDDL is the descriptor
// setWindowsCodexMachineFileProtection stamps, in SDDL form.
func windowsCodexMachineCanonicalDescriptorSDDL(userReadable bool) string {
	sddl := "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)"
	if userReadable {
		sddl += "(A;;FR;;;BU)"
	}
	return sddl
}

func windowsCodexMachineCanonicalModel(userReadable bool) managedDescriptor {
	model := managedDescriptor{
		Owner:     managedSIDAdministrators,
		Protected: true,
		ACEs: []managedACE{
			{SID: managedSIDAdministrators, Mask: managedFileAllAccess},
			{SID: managedSIDLocalSystem, Mask: managedFileAllAccess},
		},
	}
	if userReadable {
		model.ACEs = append(model.ACEs, managedACE{SID: managedSIDUsers, Mask: managedFileGenericRead})
	}
	return model
}

func windowsCodexMachineFileDrift(path string) (managedDrift, error) {
	actual, err := windowsManagedPathDescriptorModel(path, false)
	if err != nil {
		return managedDrift{}, err
	}
	return classifyManagedDrift(actual, managedDriftPolicy{
		Canonical: windowsCodexMachineCanonicalModel(windowsCodexMachineFileUserReadable(path)),
	}), nil
}

// repairWindowsCodexMachineFileProtection re-stamps the canonical owner and
// protected DACL on an existing no-follow single-link Codex machine file. The
// owner is normalized to Administrators: an administrator's rename-save under
// the default "object creator" owner policy leaves that user's SID instead.
func repairWindowsCodexMachineFileProtection(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(
		windowsCodexMachineCanonicalDescriptorSDDL(windowsCodexMachineFileUserReadable(path)),
	)
	if err != nil {
		return err
	}
	return repairWindowsManagedDescriptor(path, false, descriptor)
}

// ensureWindowsCodexMachineDirTrust validates a Codex machine directory.
// Structure stays fatal; permission drift such as the inherited ProgramData
// "Users create" grant or an MDM-applied ACL is accepted and logged, because
// the protected files inside are judged and repaired on their own. The
// installer re-stamps the directory descriptor on every action.
func ensureWindowsCodexMachineDirTrust(path, label string) error {
	strictErr := managed.ValidateTrustedRuntimeDir(path, label)
	if strictErr == nil {
		return nil
	}
	if managed.TrustStrictAncestors() {
		return strictErr
	}
	if err := managed.ValidateTrustedRuntimeDirTolerant(path, label); err != nil {
		return err
	}
	emitManagedResilience(managed.MarkerAccept, path,
		"accepted directory permission drift: "+strictErr.Error(), map[string]string{"label": label})
	return nil
}
