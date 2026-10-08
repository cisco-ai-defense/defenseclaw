//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	WindowsManagedRuntimePlanSchemaVersion    = 1
	WindowsManagedRuntimeRequestSchemaVersion = 1
	WindowsManagedRuntimeReportSchemaVersion  = 1

	windowsManagedRuntimeBaselineAbsent    = "absent"
	windowsManagedRuntimeBaselineCanonical = "canonical"
	windowsManagedRuntimeStateStaged       = "staged"
	windowsManagedRuntimeStateCanonical    = "canonical"
	windowsManagedRuntimeStateAbsent       = "absent"

	// windowsManagedRuntimeBaselinePending is a standalone Upgrade/Repair
	// root whose rows are all deferred and whose data directory is absent or
	// one the account created itself before enrollment. Setup neither stages
	// nor validates it: the guardian proves it pending and creates or adopts
	// it in the account's session, so one account's folder never fails the
	// whole lifecycle. Only validation plans carry it.
	windowsManagedRuntimeBaselinePending = "pending"

	windowsManagedRuntimeStagePrefix = ".defenseclaw.setup-"
	// windowsManagedRuntimeRollbackPrefix names a transaction-created root
	// the rollback kept aside because it holds content cleanup did not write.
	windowsManagedRuntimeRollbackPrefix    = ".defenseclaw.rollback-"
	windowsManagedRuntimeStageRandomBytes  = 16
	windowsManagedRuntimeMarkerSubAuths    = 8
	windowsManagedRuntimeMaxRoots          = 128
	windowsManagedRuntimeOwnerMetadataMask = windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

	// NtCreateFile persists a fresh protected marker descriptor as 0x9004.
	// SetSecurityInfo preserves NTFS' auto-inherited provenance on an existing
	// directory, so cleanup quarantine has the distinct exact form 0x9404.
	windowsManagedRuntimeStagingControl = windows.SECURITY_DESCRIPTOR_CONTROL(
		windows.SE_DACL_PRESENT | windows.SE_DACL_PROTECTED | windows.SE_SELF_RELATIVE,
	)
	windowsManagedRuntimeQuarantineControl = windows.SECURITY_DESCRIPTOR_CONTROL(
		windows.SE_DACL_PRESENT | windows.SE_DACL_AUTO_INHERITED |
			windows.SE_DACL_PROTECTED | windows.SE_SELF_RELATIVE,
	)
)

// WindowsManagedRuntimePlan is non-mutating authority for a later Setup
// operation. Setup must persist this value in an already-protected transaction
// record before invoking StageWindowsManagedRuntimeRoots. The random staging
// leaf and marker SID make a crash-created staging inode authenticatable even
// when the staging process dies before its JSON report reaches PowerShell.
type WindowsManagedRuntimePlan struct {
	SchemaVersion  int                             `json:"schema_version"`
	ManifestPath   string                          `json:"manifest_path"`
	ManifestSHA256 string                          `json:"manifest_sha256"`
	TargetCount    int                             `json:"target_count"`
	Roots          []WindowsManagedRuntimeRootPlan `json:"roots"`
}

type WindowsManagedRuntimeRootPlan struct {
	UserHome         string `json:"user_home"`
	DataDir          string `json:"data_dir"`
	SID              string `json:"sid"`
	Baseline         string `json:"baseline"`
	BaselineIdentity string `json:"baseline_identity,omitempty"`
	StagingLeaf      string `json:"staging_leaf"`
	MarkerSID        string `json:"marker_sid"`
}

// WindowsManagedRuntimeRequest combines an immutable protected plan with the
// identities durably journaled from a prior stage report. Finalization always
// requires those identities. Cleanup may omit an identity only for a still
// staging-trusted inode whose secret marker is authenticated by the protected
// plan; a canonical inode is never trusted from a marker alone.
type WindowsManagedRuntimeRequest struct {
	SchemaVersion int                          `json:"schema_version"`
	Plan          WindowsManagedRuntimePlan    `json:"plan"`
	Claims        []WindowsManagedRuntimeClaim `json:"claims,omitempty"`
}

type WindowsManagedRuntimeClaim struct {
	UserHome string `json:"user_home"`
	DataDir  string `json:"data_dir"`
	SID      string `json:"sid"`
	Identity string `json:"identity,omitempty"`
	Created  bool   `json:"created"`
	State    string `json:"state"`
}

type WindowsManagedRuntimeReport struct {
	SchemaVersion int                          `json:"schema_version"`
	Action        string                       `json:"action"`
	OK            bool                         `json:"ok"`
	Claims        []WindowsManagedRuntimeClaim `json:"claims"`
	Error         string                       `json:"error,omitempty"`
}

type windowsManagedRuntimeTarget struct {
	home string
	data string
	sid  *windows.SID
}

type windowsManagedRuntimeFileRenameInfo struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

type windowsManagedRuntimeACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	ACECount uint16
	Sbz2     uint16
}

type windowsManagedRuntimeCleanupFileContract uint8

const (
	windowsManagedRuntimeCleanupCanonicalFile windowsManagedRuntimeCleanupFileContract = iota + 1
	windowsManagedRuntimeCleanupGatewayFile
	// windowsManagedRuntimeCleanupOwnedLockFile is a lock the connector code
	// creates as the account (connector.withOwnedFileLock): owned by the
	// account, with a protected DACL of full control for the account,
	// LocalSystem and Administrators only. The canonical file DACL is also
	// accepted, for a lock a later pass canonicalized.
	windowsManagedRuntimeCleanupOwnedLockFile
	// windowsManagedRuntimeCleanupConnectorBackupFile is a connector backup
	// record (connector.writeManagedFileBackup, as the account): owned by the
	// account, with a protected DACL of full control for the account and
	// LocalSystem only. The canonical file DACL is also accepted, for a
	// record the guardian hardened after a successful setup.
	windowsManagedRuntimeCleanupConnectorBackupFile
	// windowsManagedRuntimeCleanupHookFile is a file in the account's
	// DefenseClaw hooks folder, owned by the account, LocalSystem or
	// Administrators, with any DACL: a guardian retry, an older release's
	// disabled-hook tombstone or the account may have rewritten it, and
	// refusing such a file left the rollback pending with no recovery.
	windowsManagedRuntimeCleanupHookFile
)

// windowsManagedRuntimeCleanupOwnedLocks are the root leaves the connector
// code creates with withOwnedFileLock's owner-only descriptor.
var windowsManagedRuntimeCleanupOwnedLocks = map[string]struct{}{
	".hermes-lifecycle.lock":       {},
	".hook-api-token-publish.lock": {},
}

// windowsManagedRuntimeCleanupPrivateRootFiles are the root leaves the
// connector code writes as the account with the owner-private descriptor of
// a connector backup record (full control for the account and LocalSystem).
var windowsManagedRuntimeCleanupPrivateRootFiles = map[string]struct{}{
	"kiro-created-dirs.json": {},
}

type windowsManagedRuntimeCleanupSpec struct {
	rootFiles            map[string]windowsManagedRuntimeCleanupFileContract
	hookFiles            map[string]windowsManagedRuntimeCleanupFileContract
	generationConnectors map[string]struct{}
	// backupFiles holds, per connector, the leaves of its
	// connector_backups\<connector> directory.
	backupFiles map[string]map[string]windowsManagedRuntimeCleanupFileContract
}

var (
	windowsManagedRuntimeSetupAuthorize                 = requireWindowsEnterpriseAdministrator
	windowsManagedRuntimeSetupPrivilege                 = runWindowsManagedRuntimeSetupPrivilege
	windowsManagedRuntimeEntropy              io.Reader = rand.Reader
	windowsManagedRuntimeCleanupPostPreflight func(rootPath, hookPath string) error
)

// ValidateWindowsManagedRuntimeAdminFile requires the exact protected
// Administrators-owned AdminFile contract used by the installer for every
// plan/report placeholder. The target-runtime CLI layers this exact check on
// top of its trusted-ancestry validation before reading or overwriting bytes.
func ValidateWindowsManagedRuntimeAdminFile(path string) error {
	return validateWindowsTargetsManifestObject(path, false)
}

// PlanWindowsManagedRuntimeRoots resolves and de-duplicates every enabled
// manifest row without mutating a profile. Existing roots are accepted only
// if they already have the exact target-owner/seven-ACE contract, and their
// identity is pinned into the plan. Absent roots receive independent random
// staging names and marker SIDs.
func PlanWindowsManagedRuntimeRoots(
	manifest Manifest,
	manifestPath string,
	manifestSHA256 string,
) (WindowsManagedRuntimePlan, error) {
	return planWindowsManagedRuntimeRoots(manifest, manifestPath, manifestSHA256, false)
}

// PlanWindowsManagedRuntimeRootsForValidation is the Upgrade/Repair plan. It
// is PlanWindowsManagedRuntimeRoots, except that in the standalone profile a
// root whose rows are all deferred and whose data directory is absent or was
// created by the account itself before enrollment is planned pending, as the
// guardian's pending proof treats it, instead of failing the lifecycle.
// Stage, finalize and cleanup refuse a plan with a pending root.
func PlanWindowsManagedRuntimeRootsForValidation(
	manifest Manifest,
	manifestPath string,
	manifestSHA256 string,
) (WindowsManagedRuntimePlan, error) {
	return planWindowsManagedRuntimeRoots(manifest, manifestPath, manifestSHA256, true)
}

func planWindowsManagedRuntimeRoots(
	manifest Manifest,
	manifestPath string,
	manifestSHA256 string,
	validation bool,
) (WindowsManagedRuntimePlan, error) {
	var plan WindowsManagedRuntimePlan
	if err := windowsManagedRuntimeSetupAuthorize(); err != nil {
		return plan, err
	}
	manifestPath = filepath.Clean(strings.TrimSpace(manifestPath))
	if !filepath.IsAbs(manifestPath) {
		return plan, fmt.Errorf("enterprise hooks: managed runtime manifest path must be absolute")
	}
	manifestSHA256 = strings.ToLower(strings.TrimSpace(manifestSHA256))
	if !validWindowsManagedRuntimeDigest(manifestSHA256) {
		return plan, fmt.Errorf("enterprise hooks: invalid managed runtime manifest SHA-256")
	}
	targets, err := resolveWindowsManagedRuntimeTargets(manifest)
	if err != nil {
		return plan, err
	}
	if len(targets) > windowsManagedRuntimeMaxRoots {
		return plan, fmt.Errorf("enterprise hooks: managed runtime plan has %d roots, maximum is %d", len(targets), windowsManagedRuntimeMaxRoots)
	}
	targetCount := 0
	for _, row := range manifest.Targets {
		if row.IsEnabled() {
			targetCount++
		}
	}
	if targetCount > windowsManagedRuntimeMaxRoots*3 {
		return plan, fmt.Errorf(
			"enterprise hooks: managed runtime plan has %d targets, maximum is %d",
			targetCount,
			windowsManagedRuntimeMaxRoots*3,
		)
	}
	plan = WindowsManagedRuntimePlan{
		SchemaVersion:  WindowsManagedRuntimePlanSchemaVersion,
		ManifestPath:   manifestPath,
		ManifestSHA256: manifestSHA256,
		TargetCount:    targetCount,
		Roots:          make([]WindowsManagedRuntimeRootPlan, 0, len(targets)),
	}
	pendingAllowed := validation && windowsEnterpriseStandaloneProcess()
	// Only a standalone install plan re-protects a folder a standalone purge
	// kept; a validation plan never changes a folder.
	adoptPurgeKept := !validation && windowsEnterpriseStandaloneProcess()
	deferredOnly := windowsManagedRuntimeDeferredOnlyRoots(manifest)
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		for _, target := range targets {
			key := windowsManagedRuntimeRootKey(target.sid.String(), target.home)
			root, inspectErr := planWindowsManagedRuntimeRoot(target, pendingAllowed && deferredOnly[key], adoptPurgeKept)
			if inspectErr != nil {
				return inspectErr
			}
			plan.Roots = append(plan.Roots, root)
		}
		return nil
	})
	if err != nil {
		return WindowsManagedRuntimePlan{}, err
	}
	return plan, validateWindowsManagedRuntimePlanRows(plan, manifest, false, pendingAllowed)
}

// windowsManagedRuntimeDeferredOnlyRoots returns the root keys of the
// profiles whose enabled manifest rows are all deferred.
func windowsManagedRuntimeDeferredOnlyRoots(manifest Manifest) map[string]bool {
	roots := make(map[string]bool)
	for _, row := range manifest.Targets {
		if !row.IsEnabled() {
			continue
		}
		target, err := resolveWindowsManagedRuntimeTarget(row.UserHome, row.SID, row.DataDir)
		if err != nil {
			continue
		}
		key := windowsManagedRuntimeRootKey(target.sid.String(), target.home)
		deferred, seen := roots[key]
		roots[key] = row.IsDeferred() && (deferred || !seen)
	}
	return roots
}

// StageWindowsManagedRuntimeRoots creates only random staging leaves. It never
// publishes the final .defenseclaw name. The staging FILE_CREATE atomically
// applies exact random-marker ownership and a trusted-only protected DACL. The
// enrolled target has no access to that inode before publication, and the
// protected plan can authenticate a crash-created inode even if its identity
// report was not persisted.
func StageWindowsManagedRuntimeRoots(
	plan WindowsManagedRuntimePlan,
	manifest Manifest,
	manifestSHA256 string,
	journal func([]WindowsManagedRuntimeClaim) error,
) ([]WindowsManagedRuntimeClaim, error) {
	if err := windowsManagedRuntimeSetupAuthorize(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(manifestSHA256), plan.ManifestSHA256) {
		return nil, fmt.Errorf("enterprise hooks: managed runtime manifest digest changed after planning")
	}
	if err := validateWindowsManagedRuntimePlan(plan, manifest); err != nil {
		return nil, err
	}
	if journal == nil {
		return nil, fmt.Errorf("enterprise hooks: managed runtime stage journal callback is required")
	}
	claims := make([]WindowsManagedRuntimeClaim, 0, len(plan.Roots))
	err := windowsManagedRuntimeSetupPrivilege(func() error {
		for _, rootPlan := range plan.Roots {
			_, stageErr := stageWindowsManagedRuntimeRoot(rootPlan, func(claim WindowsManagedRuntimeClaim) error {
				claims = append(claims, claim)
				return journal(append([]WindowsManagedRuntimeClaim(nil), claims...))
			})
			if stageErr != nil {
				return stageErr
			}
		}
		return nil
	})
	return claims, err
}

// FinalizeWindowsManagedRuntimeRoots authenticates every staging inode against
// both the protected marker plan and the identity journal, no-replace renames
// that still marker-protected handle to .defenseclaw, rebinds the published
// identity, and only then installs the exact target-owned seven-ACE DACL.
// Existing-baseline roots are validation-only.
func FinalizeWindowsManagedRuntimeRoots(
	request WindowsManagedRuntimeRequest,
	manifest Manifest,
	manifestSHA256 string,
) ([]WindowsManagedRuntimeClaim, error) {
	if err := windowsManagedRuntimeSetupAuthorize(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(manifestSHA256), request.Plan.ManifestSHA256) {
		return nil, fmt.Errorf("enterprise hooks: managed runtime manifest digest changed after planning")
	}
	claimsByRoot, err := validateWindowsManagedRuntimeRequest(request, manifest, true)
	if err != nil {
		return nil, err
	}
	claims := make([]WindowsManagedRuntimeClaim, 0, len(request.Plan.Roots))
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		for _, rootPlan := range request.Plan.Roots {
			key := windowsManagedRuntimeRootKey(rootPlan.SID, rootPlan.UserHome)
			claim, finalizeErr := finalizeWindowsManagedRuntimeRoot(rootPlan, claimsByRoot[key])
			if claim.Identity != "" {
				claims = append(claims, claim)
			}
			if finalizeErr != nil {
				return finalizeErr
			}
		}
		return nil
	})
	return claims, err
}

// CleanupWindowsManagedRuntimeRoots removes only roots created by this plan.
// A marker-staged root may be removed without a journaled identity because the
// target cannot read or forge its protected random marker. Any root carrying
// the canonical target DACL requires an exact journaled identity.
// Substitutions fail closed and leave recovery authority intact. Content the
// preflight cannot prove DefenseClaw wrote (an unexpected entry, a changed
// owner or DACL, a hard link) is never deleted: the journaled root holding it
// is renamed aside (windowsManagedRuntimeRollbackPrefix) so the rollback
// still completes instead of staying pending.
func CleanupWindowsManagedRuntimeRoots(
	request WindowsManagedRuntimeRequest,
	manifest Manifest,
	manifestSHA256 string,
) ([]WindowsManagedRuntimeClaim, error) {
	if err := windowsManagedRuntimeSetupAuthorize(); err != nil {
		return nil, err
	}
	// The hook enumerator republishes targets.yaml whenever a row changes (an
	// agent update, a newly discovered agent, a deferred row), including while
	// a failed install waits for readiness. Rollback cleanup acts only on the
	// plan's own roots, authenticated by their marker SIDs and journaled
	// identities, so it accepts a republished manifest that keeps exactly the
	// planned profile roots; stage and finalize still require the planned
	// digest.
	rowDrift := !strings.EqualFold(strings.TrimSpace(manifestSHA256), request.Plan.ManifestSHA256)
	request, manifest, vanished := dropVanishedWindowsManagedRuntimeProfiles(request, manifest)
	rowDrift = rowDrift || len(vanished) > 0
	claimsByRoot, err := validateWindowsManagedRuntimeRequestRows(request, manifest, false, rowDrift)
	if err != nil {
		if rowDrift {
			return nil, fmt.Errorf("enterprise hooks: managed runtime manifest digest changed after planning and the republished manifest does not keep the planned profile roots: %w", err)
		}
		return nil, err
	}
	cleanupSpecs, err := windowsManagedRuntimeCleanupSpecs(request.Plan, manifest)
	if err != nil {
		return nil, err
	}
	claims := make([]WindowsManagedRuntimeClaim, 0, len(request.Plan.Roots)+len(vanished))
	claims = append(claims, vanished...)
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		for _, rootPlan := range request.Plan.Roots {
			key := windowsManagedRuntimeRootKey(rootPlan.SID, rootPlan.UserHome)
			claim, cleanupErr := cleanupWindowsManagedRuntimeRoot(rootPlan, claimsByRoot[key], cleanupSpecs[key])
			if windowsManagedRuntimeCleanupClaimReportable(claim) {
				claims = append(claims, claim)
			}
			if cleanupErr != nil {
				return cleanupErr
			}
		}
		return nil
	})
	return claims, err
}

// dropVanishedWindowsManagedRuntimeProfiles takes out of a rollback cleanup
// each planned root whose profile folder no longer exists: the account was
// deleted with its profile while the install ran, so nothing of it is left
// to clean. Validating it failed on the missing folder and kept the
// transaction pending with the services stopped, and no Setup could recover
// it (GAP-1293). Each such root is reported as its baseline.
func dropVanishedWindowsManagedRuntimeProfiles(
	request WindowsManagedRuntimeRequest,
	manifest Manifest,
) (WindowsManagedRuntimeRequest, Manifest, []WindowsManagedRuntimeClaim) {
	gone := map[string]bool{}
	var vanished []WindowsManagedRuntimeClaim
	roots := make([]WindowsManagedRuntimeRootPlan, 0, len(request.Plan.Roots))
	for _, root := range request.Plan.Roots {
		home := filepath.Clean(strings.TrimSpace(root.UserHome))
		if _, err := os.Lstat(home); filepath.IsAbs(home) && errors.Is(err, os.ErrNotExist) {
			gone[strings.ToUpper(home)] = true
			claim := windowsManagedRuntimeClaimFromPlan(root)
			claim.State = windowsManagedRuntimeStateAbsent
			if root.Baseline == windowsManagedRuntimeBaselineCanonical {
				// An existing baseline is never changed by cleanup.
				claim.State = windowsManagedRuntimeStateCanonical
				claim.Identity = root.BaselineIdentity
			}
			vanished = append(vanished, claim)
			continue
		}
		roots = append(roots, root)
	}
	if len(vanished) == 0 {
		return request, manifest, nil
	}
	isGone := func(home string) bool { return gone[strings.ToUpper(filepath.Clean(strings.TrimSpace(home)))] }
	request.Plan.Roots = roots
	claims := make([]WindowsManagedRuntimeClaim, 0, len(request.Claims))
	for _, claim := range request.Claims {
		if !isGone(claim.UserHome) {
			claims = append(claims, claim)
		}
	}
	request.Claims = claims
	targets := make([]ManifestTarget, 0, len(manifest.Targets))
	for _, row := range manifest.Targets {
		if !isGone(row.UserHome) {
			targets = append(targets, row)
		}
	}
	manifest.Targets = targets
	return request, manifest, vanished
}

func windowsManagedRuntimeCleanupClaimReportable(claim WindowsManagedRuntimeClaim) bool {
	switch claim.State {
	case windowsManagedRuntimeStateStaged, windowsManagedRuntimeStateCanonical, windowsManagedRuntimeStateAbsent:
		return true
	default:
		return false
	}
}

func resolveWindowsManagedRuntimeTargets(manifest Manifest) ([]windowsManagedRuntimeTarget, error) {
	bySID := make(map[string]string)
	byHome := make(map[string]string)
	unique := make(map[string]windowsManagedRuntimeTarget)
	for index, row := range manifest.Targets {
		if !row.IsEnabled() {
			continue
		}
		target, err := resolveWindowsManagedRuntimeTarget(row.UserHome, row.SID, row.DataDir)
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: prepare managed runtime target %d: %w", index, err)
		}
		sidKey := strings.ToUpper(target.sid.String())
		homeKey := strings.ToUpper(filepath.Clean(target.home))
		if prior, ok := bySID[sidKey]; ok && prior != homeKey {
			return nil, fmt.Errorf("enterprise hooks: target SID %s maps to multiple profile roots", target.sid)
		}
		if prior, ok := byHome[homeKey]; ok && prior != sidKey {
			return nil, fmt.Errorf("enterprise hooks: profile root %s maps to multiple target SIDs", target.home)
		}
		bySID[sidKey] = homeKey
		byHome[homeKey] = sidKey
		unique[windowsManagedRuntimeRootKey(sidKey, homeKey)] = target
	}
	targets := make([]windowsManagedRuntimeTarget, 0, len(unique))
	for _, target := range unique {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return windowsManagedRuntimeRootKey(targets[i].sid.String(), targets[i].home) <
			windowsManagedRuntimeRootKey(targets[j].sid.String(), targets[j].home)
	})
	return targets, nil
}

func windowsManagedRuntimeCleanupSpecs(plan WindowsManagedRuntimePlan, manifest Manifest) (map[string]windowsManagedRuntimeCleanupSpec, error) {
	specs := make(map[string]windowsManagedRuntimeCleanupSpec)
	for _, root := range plan.Roots {
		if root.Baseline != windowsManagedRuntimeBaselineAbsent {
			continue
		}
		key := windowsManagedRuntimeRootKey(root.SID, root.UserHome)
		specs[key] = windowsManagedRuntimeCleanupSpec{
			rootFiles: map[string]windowsManagedRuntimeCleanupFileContract{
				"inventory.db":                 windowsManagedRuntimeCleanupGatewayFile,
				"inventory.db-journal":         windowsManagedRuntimeCleanupGatewayFile,
				"inventory.db-shm":             windowsManagedRuntimeCleanupGatewayFile,
				"inventory.db-wal":             windowsManagedRuntimeCleanupGatewayFile,
				"hook_contract_lock.json":      windowsManagedRuntimeCleanupCanonicalFile,
				"hook_contract_lock.json.lock": windowsManagedRuntimeCleanupCanonicalFile,
			},
			hookFiles: map[string]windowsManagedRuntimeCleanupFileContract{
				".hookcfg":      windowsManagedRuntimeCleanupCanonicalFile,
				".hookcfg.lock": windowsManagedRuntimeCleanupCanonicalFile,
				// Scoped-token reconciliation removes this legacy name, but an
				// exact canonical inode is still a bounded crash residue. An
				// inherited or otherwise noncanonical legacy file is refused.
				".token": windowsManagedRuntimeCleanupCanonicalFile,
			},
			generationConnectors: make(map[string]struct{}),
		}
	}
	for index, row := range manifest.Targets {
		if !row.IsEnabled() {
			continue
		}
		target, err := resolveWindowsManagedRuntimeTarget(row.UserHome, row.SID, row.DataDir)
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: derive managed runtime cleanup target %d: %w", index, err)
		}
		key := windowsManagedRuntimeRootKey(target.sid.String(), target.home)
		spec, absentBaseline := specs[key]
		if !absentBaseline {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(row.Connector))
		if name == "" {
			return nil, fmt.Errorf("enterprise hooks: absent-baseline cleanup target %d has no connector", index)
		}
		files, ok := windowsManagedRuntimeCleanupConnectors[name]
		if !ok {
			return nil, fmt.Errorf("enterprise hooks: no bounded absent-baseline cleanup contract for connector %q", row.Connector)
		}
		for _, leaf := range files.root {
			spec.rootFiles[leaf] = windowsManagedRuntimeCleanupCanonicalFile
			if _, lock := windowsManagedRuntimeCleanupOwnedLocks[leaf]; lock {
				spec.rootFiles[leaf] = windowsManagedRuntimeCleanupOwnedLockFile
			}
			if _, private := windowsManagedRuntimeCleanupPrivateRootFiles[leaf]; private {
				spec.rootFiles[leaf] = windowsManagedRuntimeCleanupConnectorBackupFile
			}
		}
		for _, leaf := range files.hooks {
			spec.hookFiles[leaf] = windowsManagedRuntimeCleanupHookFile
		}
		if files.generation {
			spec.generationConnectors[name] = struct{}{}
		}
		if len(files.backups) > 0 {
			if spec.backupFiles == nil {
				spec.backupFiles = make(map[string]map[string]windowsManagedRuntimeCleanupFileContract)
			}
			backups := make(map[string]windowsManagedRuntimeCleanupFileContract, len(files.backups))
			for _, leaf := range files.backups {
				backups[leaf] = windowsManagedRuntimeCleanupConnectorBackupFile
			}
			spec.backupFiles[name] = backups
		}
		specs[key] = spec
	}
	return specs, nil
}

// windowsManagedRuntimeCleanupConnectorFiles is the bounded footprint one
// connector's managed install writes into a ~\.defenseclaw that the same
// transaction created (an absent baseline): leaves in the root, in hooks,
// and in the connector's own connector_backups\<connector> records, and
// whether it publishes immutable runtime generations. Rollback deletes
// exactly these names, each only with the canonical target-owned owner,
// DACL and single link; any other entry (an account's own file, the
// foreign-hook backups of displaced user hooks, a noncanonical inode)
// refuses the whole root.
type windowsManagedRuntimeCleanupConnectorFiles struct {
	root       []string
	hooks      []string
	backups    []string
	generation bool
}

// windowsManagedRuntimeCleanupBackupDir holds the per-connector config
// backup records (connector.managedFileBackupPath).
const windowsManagedRuntimeCleanupBackupDir = "connector_backups"

// windowsManagedRuntimeSharedHookScripts are the shell hook scripts and
// helper every script-rendering connector writes into hooks.
var windowsManagedRuntimeSharedHookScripts = []string{
	"_hardening.sh",
	"inspect-tool.sh",
	"inspect-request.sh",
	"inspect-response.sh",
	"inspect-tool-response.sh",
}

func windowsManagedRuntimeRuntimeLeaves(name string, extra ...string) []string {
	return append([]string{".hookcfg." + name, ".hook-" + name + ".token"}, extra...)
}

// windowsManagedRuntimeCleanupConnectors lists every connector a Windows
// managed manifest can enroll. codex, cursor and claudecode are machine
// policy rows; the rest are the standalone per-user connectors
// (WindowsStandalonePerUserConnectorNames). Copilot, and OpenCode while its
// machine policy is in force, write only the per-user runtime
// (install_windows_runtime_only.go). The other per-user rows also render
// their hook scripts or plugin token, record the guardian-selected
// executable (agent_selection.json) and back up the agent file they patch.
var windowsManagedRuntimeCleanupConnectors = map[string]windowsManagedRuntimeCleanupConnectorFiles{
	"codex":  {hooks: windowsManagedRuntimeRuntimeLeaves("codex"), generation: true},
	"cursor": {hooks: windowsManagedRuntimeRuntimeLeaves("cursor"), generation: true},
	"claudecode": {
		hooks:      windowsManagedRuntimeRuntimeLeaves("claudecode", append([]string{"claude-code-hook.sh"}, windowsManagedRuntimeSharedHookScripts...)...),
		generation: true,
	},
	"copilot": {hooks: windowsManagedRuntimeRuntimeLeaves("copilot"), generation: true},
	"antigravity": {
		hooks:      windowsManagedRuntimeRuntimeLeaves("antigravity", append([]string{"antigravity-hook.sh"}, windowsManagedRuntimeSharedHookScripts...)...),
		backups:    []string{"hooks.json.json"},
		generation: true,
	},
	"devin": {
		hooks:      windowsManagedRuntimeRuntimeLeaves("devin", append([]string{"devin-hook.sh"}, windowsManagedRuntimeSharedHookScripts...)...),
		backups:    []string{"config.json"},
		generation: true,
	},
	"hermes": {
		root:       []string{".hermes-lifecycle.lock", "agent_selection.json", "agent_selection.json.lock"},
		hooks:      windowsManagedRuntimeRuntimeLeaves("hermes", append([]string{"hermes-hook.sh", "hermes-direct-native-state.json"}, windowsManagedRuntimeSharedHookScripts...)...),
		backups:    []string{"config.yaml.json", "shell-hooks-allowlist.json.json"},
		generation: true,
	},
	"kiro": {
		// kiro-created-dirs.json lists the Kiro folders setup created
		// (connector.kiroCreatedDirsFile). Unlisted, it kept every failed
		// first install's root aside as .defenseclaw.rollback-<id> (GAP-1287).
		root:       []string{"kiro-created-dirs.json"},
		hooks:      windowsManagedRuntimeRuntimeLeaves("kiro", append([]string{"kiro-hook.sh"}, windowsManagedRuntimeSharedHookScripts...)...),
		backups:    []string{"hooks-global.json", "agent-defenseclaw.json", "settings-cli.json"},
		generation: true,
	},
	"opencode": {
		root:       []string{"agent_selection.json", "agent_selection.json.lock", ".hook-api-token-publish.lock"},
		hooks:      windowsManagedRuntimeRuntimeLeaves("opencode"),
		backups:    []string{"config.json"},
		generation: true,
	},
	"amp": {
		root:    []string{"agent_selection.json", "agent_selection.json.lock", ".hook-api-token-publish.lock"},
		hooks:   []string{".hook-amp.token"},
		backups: []string{"config.json"},
	},
}

// windowsManagedRuntimeCleanupLeaves is every leaf name the cleanup
// contracts can open below the root.
var windowsManagedRuntimeCleanupLeaves = func() map[string]struct{} {
	leaves := map[string]struct{}{windowsManagedRuntimeCleanupBackupDir: {}}
	for name, files := range windowsManagedRuntimeCleanupConnectors {
		leaves[name] = struct{}{}
		for _, group := range [][]string{files.root, files.hooks, files.backups} {
			for _, leaf := range group {
				leaves[leaf] = struct{}{}
			}
		}
	}
	return leaves
}()

func resolveWindowsManagedRuntimeTarget(userHome, rawSID, rawDataDir string) (windowsManagedRuntimeTarget, error) {
	home, target, err := validateWindowsEnterpriseHome(userHome, rawSID)
	if err != nil {
		return windowsManagedRuntimeTarget{}, err
	}
	// Profile roots are Windows/profile-manager anchors. Their owner may be the
	// target or a trusted profile-management principal such as Administrators;
	// exact target ownership is required only on the managed child created here.
	if err := validateWindowsEnterpriseHomeAnchor(home, target); err != nil {
		return windowsManagedRuntimeTarget{}, err
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	if strings.TrimSpace(rawDataDir) != "" {
		candidate, err := filepath.Abs(strings.TrimSpace(rawDataDir))
		if err != nil {
			return windowsManagedRuntimeTarget{}, fmt.Errorf("enterprise hooks: resolve managed runtime data_dir: %w", err)
		}
		candidate = filepath.Clean(candidate)
		if !sameWindowsEnterprisePath(candidate, dataDir) {
			return windowsManagedRuntimeTarget{}, fmt.Errorf("enterprise hooks: managed runtime data_dir must be exactly %s", dataDir)
		}
	}
	return windowsManagedRuntimeTarget{home: home, data: dataDir, sid: target}, nil
}

// PreflightWindowsManagedRuntimeRoots inspects, without changing anything,
// the .defenseclaw folder of every enabled manifest target the way the
// standalone install plan does, and returns the refusal the plan would
// return for the first folder it would not take: one DefenseClaw did not
// create, such as the data folder a per-user install left. The install
// found it only after minutes of work, and a run that got further committed
// and then failed on it (GAP-0741). A folder the plan takes over (one a
// standalone purge kept, or one the account created itself before
// enrollment) passes.
func PreflightWindowsManagedRuntimeRoots(manifest Manifest) error {
	if err := windowsManagedRuntimeSetupAuthorize(); err != nil {
		return err
	}
	targets, err := resolveWindowsManagedRuntimeTargets(manifest)
	if err != nil {
		return err
	}
	return windowsManagedRuntimeSetupPrivilege(func() error {
		for _, target := range targets {
			if err := inspectWindowsManagedRuntimeRoot(target); err != nil {
				return err
			}
		}
		return nil
	})
}

// inspectWindowsManagedRuntimeRoot is the read-only half of
// planWindowsManagedRuntimeRoot for a standalone install plan.
func inspectWindowsManagedRuntimeRoot(target windowsManagedRuntimeTarget) error {
	parent, err := openWindowsManagedRuntimeProfile(target)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(parent)
	final, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess(), false)
	if windowsManagedRuntimeRootMissing(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect managed runtime baseline: %w", err)
	}
	defer windows.CloseHandle(final)
	err = validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid)
	if err == nil || windowsManagedRuntimePurgeKeptAdoptable(final, target) || windowsManagedRuntimeAccountCreatedBaseline(final, target) {
		return nil
	}
	return fmt.Errorf("enterprise hooks: reject noncanonical managed runtime baseline: %w", err)
}

// windowsManagedRuntimePurgeKeptAdoptable reports the folder shape
// adoptWindowsManagedRuntimePurgeKeptRoot takes over: owned by the target
// account, with the owner-private DACL a standalone purge leaves.
func windowsManagedRuntimePurgeKeptAdoptable(final windows.Handle, target windowsManagedRuntimeTarget) bool {
	descriptor, err := windows.GetSecurityInfo(final, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(target.sid) {
		return false
	}
	relaxed, err := windowsSetupRelaxedDirectoryDACL(descriptor)
	return err == nil && relaxed
}

// windowsManagedRuntimeAccountCreatedBaseline reports whether the opened
// data directory is one the account created itself before enrollment
// (windowsAccountCreatedDataDir), which the guardian adopts at enrollment.
func windowsManagedRuntimeAccountCreatedBaseline(final windows.Handle, target windowsManagedRuntimeTarget) bool {
	descriptor, err := windows.GetSecurityInfo(final, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	ok, err := windowsAccountCreatedDataDir(target.data, descriptor, target.sid)
	return err == nil && ok
}

// planWindowsManagedRuntimeRoot inspects one target root. With pendingAllowed
// (a standalone validation plan of a profile whose rows are all deferred), an
// absent data directory, or one the account created itself before enrollment,
// is planned pending instead of absent or refused. With adoptPurgeKept (a
// standalone install plan), a data directory left by a standalone uninstall
// with purge is given the canonical DACL again and planned canonical.
func planWindowsManagedRuntimeRoot(target windowsManagedRuntimeTarget, pendingAllowed, adoptPurgeKept bool) (WindowsManagedRuntimeRootPlan, error) {
	parent, err := openWindowsManagedRuntimeProfile(target)
	if err != nil {
		return WindowsManagedRuntimeRootPlan{}, err
	}
	defer windows.CloseHandle(parent)
	root := WindowsManagedRuntimeRootPlan{
		UserHome: target.home,
		DataDir:  target.data,
		SID:      target.sid.String(),
	}
	final, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess(), false)
	if windowsManagedRuntimeRootMissing(err) {
		root.Baseline = windowsManagedRuntimeBaselineAbsent
		if pendingAllowed {
			root.Baseline = windowsManagedRuntimeBaselinePending
		}
	} else if err != nil {
		return WindowsManagedRuntimeRootPlan{}, fmt.Errorf("enterprise hooks: inspect managed runtime baseline: %w", err)
	} else {
		defer windows.CloseHandle(final)
		err := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid)
		if err != nil && adoptPurgeKept {
			adopted, adoptErr := adoptWindowsManagedRuntimePurgeKeptRoot(parent, final, target)
			if adoptErr != nil {
				return WindowsManagedRuntimeRootPlan{}, fmt.Errorf("enterprise hooks: restore the managed DACL on the folder a purge kept: %w", adoptErr)
			}
			if !adopted {
				// A folder the account created itself before enrollment (the
				// refused hook of an unenrolled account writes one) holds no
				// per-user product. The guardian takes it over at sign-in; a
				// fresh install takes it over here instead of failing for
				// every account on the machine (GAP-0416).
				adopted, adoptErr = adoptWindowsManagedRuntimeAccountCreatedRoot(parent, final, target)
				if adoptErr != nil {
					return WindowsManagedRuntimeRootPlan{}, fmt.Errorf("enterprise hooks: take over the folder the account created: %w", adoptErr)
				}
			}
			if adopted {
				err = validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid)
			}
		}
		if err != nil {
			if !pendingAllowed || !windowsManagedRuntimeAccountCreatedBaseline(final, target) {
				return WindowsManagedRuntimeRootPlan{}, fmt.Errorf("enterprise hooks: reject noncanonical managed runtime baseline: %w", err)
			}
			root.Baseline = windowsManagedRuntimeBaselinePending
		} else {
			identity, err := windowsManagedRuntimeHandleIdentity(final, true)
			if err != nil {
				return WindowsManagedRuntimeRootPlan{}, err
			}
			root.Baseline = windowsManagedRuntimeBaselineCanonical
			root.BaselineIdentity = identity
		}
	}
	randomLeaf := make([]byte, windowsManagedRuntimeStageRandomBytes)
	if _, err := io.ReadFull(windowsManagedRuntimeEntropy, randomLeaf); err != nil {
		return WindowsManagedRuntimeRootPlan{}, fmt.Errorf("enterprise hooks: generate managed runtime staging leaf: %w", err)
	}
	root.StagingLeaf = windowsManagedRuntimeStagePrefix + hex.EncodeToString(randomLeaf)
	marker, err := randomWindowsManagedRuntimeMarkerSID(windowsManagedRuntimeEntropy)
	if err != nil {
		return WindowsManagedRuntimeRootPlan{}, err
	}
	root.MarkerSID = marker.String()
	return root, nil
}

// adoptWindowsManagedRuntimePurgeKeptRoot restores the canonical DACL on a
// data directory that a standalone uninstall with purge kept. The purge keeps
// the disabled hook scripts and returns what it keeps to the owner-private
// shape (LocalSystem and OWNER RIGHTS full control) so that a later per-user
// install can protect its own folder. A later managed install then found 2
// ACEs instead of the canonical 7 and refused the folder, and only deleting
// it as LocalSystem let the machine enroll again. Only a plain, target-owned
// directory whose DACL is exactly that owner-private shape changes, through a
// second handle bound to the same inode; its hooks folder, which the purge
// relaxed the same way, gets the canonical DACL too. It reports whether it
// changed the folder.
func adoptWindowsManagedRuntimePurgeKeptRoot(parent, final windows.Handle, target windowsManagedRuntimeTarget) (bool, error) {
	descriptor, err := windows.GetSecurityInfo(final, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(target.sid) {
		return false, err
	}
	if relaxed, err := windowsSetupRelaxedDirectoryDACL(descriptor); err != nil || !relaxed {
		return false, err
	}
	identity, err := windowsManagedRuntimeHandleIdentity(final, true)
	if err != nil {
		return false, err
	}
	writer, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess()|windows.WRITE_DAC, false)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(writer)
	if got, err := windowsManagedRuntimeHandleIdentity(writer, true); err != nil || got != identity {
		return false, errors.Join(err, fmt.Errorf("enterprise hooks: %s changed while it was inspected", target.data))
	}
	acl, err := windowsUserPathProtectionACL(target.sid, true)
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(writer, acl, true); err != nil {
		return false, err
	}
	if _, err := windowsRecoverSetupRelaxedHookDirectory(target.data, target.sid); err != nil && !windowsManagedRuntimeRootMissing(err) {
		return true, err
	}
	return true, nil
}

// adoptWindowsManagedRuntimeAccountCreatedRoot gives the canonical DACL to a
// data directory the account created itself before it was enrolled
// (windowsAccountCreatedDataDir: owned by the account, an inherited DACL, no
// hooks folder, a small plain tree the account owns). It is the install-plan
// counterpart of the guardian adoption (adoptWindowsAccountCreatedDataDir). A
// folder a per-user install left has a hooks folder and is still refused.
func adoptWindowsManagedRuntimeAccountCreatedRoot(parent, final windows.Handle, target windowsManagedRuntimeTarget) (bool, error) {
	if !windowsManagedRuntimeAccountCreatedBaseline(final, target) {
		return false, nil
	}
	identity, err := windowsManagedRuntimeHandleIdentity(final, true)
	if err != nil {
		return false, err
	}
	writer, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess()|windows.WRITE_DAC, false)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(writer)
	if got, err := windowsManagedRuntimeHandleIdentity(writer, true); err != nil || got != identity {
		return false, errors.Join(err, fmt.Errorf("enterprise hooks: %s changed while it was inspected", target.data))
	}
	descriptor, err := windows.GetSecurityInfo(writer, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	if ok, err := windowsAccountCreatedDataDirDescriptor(descriptor, target.sid); err != nil || !ok {
		return false, errors.Join(err, fmt.Errorf("enterprise hooks: %s changed while it was inspected", target.data))
	}
	acl, err := windowsUserPathProtectionACL(target.sid, true)
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(writer, acl, true); err != nil {
		return false, err
	}
	return true, nil
}

func stageWindowsManagedRuntimeRoot(rootPlan WindowsManagedRuntimeRootPlan, journal func(WindowsManagedRuntimeClaim) error) (WindowsManagedRuntimeClaim, error) {
	claim := windowsManagedRuntimeClaimFromPlan(rootPlan)
	target, err := resolveWindowsManagedRuntimeTarget(rootPlan.UserHome, rootPlan.SID, rootPlan.DataDir)
	if err != nil {
		return claim, err
	}
	parent, err := openWindowsManagedRuntimeProfile(target)
	if err != nil {
		return claim, err
	}
	defer windows.CloseHandle(parent)
	if rootPlan.Baseline == windowsManagedRuntimeBaselineCanonical {
		final, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess(), false)
		if err != nil {
			return claim, fmt.Errorf("enterprise hooks: reopen canonical managed runtime baseline: %w", err)
		}
		defer windows.CloseHandle(final)
		if err := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid); err != nil {
			return claim, err
		}
		identity, err := windowsManagedRuntimeHandleIdentity(final, true)
		if err != nil || identity != rootPlan.BaselineIdentity {
			return claim, fmt.Errorf("enterprise hooks: canonical managed runtime baseline identity changed")
		}
		claim.Identity = identity
		claim.State = windowsManagedRuntimeStateCanonical
		if err := journal(claim); err != nil {
			return claim, fmt.Errorf("enterprise hooks: journal existing managed runtime identity: %w", err)
		}
		return claim, nil
	}
	if err := requireWindowsManagedRuntimeChildAbsent(parent, ".defenseclaw"); err != nil {
		return claim, fmt.Errorf("enterprise hooks: final managed runtime appeared after absent plan: %w", err)
	}
	marker, _ := windows.StringToSid(rootPlan.MarkerSID)
	descriptor, err := windowsManagedRuntimeStagingSecurityDescriptor(target.sid, marker)
	if err != nil {
		return claim, err
	}
	stage, created, err := openOrCreateWindowsManagedRuntimeStage(parent, rootPlan.StagingLeaf, descriptor)
	if err != nil {
		return claim, fmt.Errorf("enterprise hooks: create managed runtime staging root: %w", err)
	}
	defer windows.CloseHandle(stage)
	if err := validateWindowsManagedRuntimeStagingHandle(stage, target.sid, marker); err != nil {
		if created {
			err = errors.Join(err, deleteRejectedWindowsManagedRuntimeStage(stage))
		}
		return claim, fmt.Errorf("enterprise hooks: reject managed runtime staging root: %w", err)
	}
	identity, err := windowsManagedRuntimeHandleIdentity(stage, true)
	if err != nil {
		if created {
			err = errors.Join(err, deleteRejectedWindowsManagedRuntimeStage(stage))
		}
		return claim, err
	}
	claim.Identity = identity
	claim.Created = true
	claim.State = windowsManagedRuntimeStateStaged
	if err := journal(claim); err != nil {
		if created {
			err = errors.Join(err, deleteRejectedWindowsManagedRuntimeStage(stage))
		}
		return claim, fmt.Errorf("enterprise hooks: durably journal managed runtime staging identity: %w", err)
	}
	_ = created // A retry may authenticate the exact marker-staged inode.
	return claim, nil
}

func finalizeWindowsManagedRuntimeRoot(rootPlan WindowsManagedRuntimeRootPlan, expected WindowsManagedRuntimeClaim) (WindowsManagedRuntimeClaim, error) {
	claim := windowsManagedRuntimeClaimFromPlan(rootPlan)
	target, err := resolveWindowsManagedRuntimeTarget(rootPlan.UserHome, rootPlan.SID, rootPlan.DataDir)
	if err != nil {
		return claim, err
	}
	parent, err := openWindowsManagedRuntimeProfile(target)
	if err != nil {
		return claim, err
	}
	defer windows.CloseHandle(parent)
	if rootPlan.Baseline == windowsManagedRuntimeBaselineCanonical {
		return validateWindowsManagedRuntimeFinal(parent, target, rootPlan.BaselineIdentity, false)
	}
	if expected.Identity == "" {
		return claim, fmt.Errorf("enterprise hooks: finalize requires a journaled managed runtime identity")
	}
	// Idempotent crash re-entry after the handle-bound rename.
	final, finalErr := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeStageMutationAccess(), false)
	if finalErr == nil {
		defer windows.CloseHandle(final)
		identity, err := windowsManagedRuntimeHandleIdentity(final, true)
		if err != nil || identity != expected.Identity {
			return claim, fmt.Errorf("enterprise hooks: published managed runtime identity does not match journal")
		}
		marker, _ := windows.StringToSid(rootPlan.MarkerSID)
		canonical := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid) == nil
		staging := validateWindowsManagedRuntimeStagingHandle(final, target.sid, marker) == nil
		if !canonical && !staging {
			return claim, fmt.Errorf("enterprise hooks: published managed runtime inode has neither authenticated descriptor")
		}
		if staging {
			if err := requireWindowsManagedRuntimeDirectoryEmpty(final); err != nil {
				return claim, err
			}
			if err := setWindowsManagedRuntimeFinalSecurity(final, target.sid); err != nil {
				return claim, err
			}
		}
		if err := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid); err != nil {
			return claim, err
		}
		if err := requireWindowsManagedRuntimeChildAbsent(parent, rootPlan.StagingLeaf); err != nil {
			return claim, fmt.Errorf("enterprise hooks: staging name remains after publication: %w", err)
		}
		claim.Identity = identity
		claim.Created = true
		claim.State = windowsManagedRuntimeStateCanonical
		return claim, nil
	}
	if !windowsManagedRuntimeRootMissing(finalErr) {
		return claim, finalErr
	}
	stage, err := openWindowsManagedRuntimeChild(parent, rootPlan.StagingLeaf, windowsManagedRuntimeStageMutationAccess(), false)
	if err != nil {
		return claim, fmt.Errorf("enterprise hooks: open managed runtime staging root for finalize: %w", err)
	}
	defer windows.CloseHandle(stage)
	identity, err := windowsManagedRuntimeHandleIdentity(stage, true)
	if err != nil || identity != expected.Identity {
		return claim, fmt.Errorf("enterprise hooks: managed runtime staging identity does not match journal")
	}
	marker, _ := windows.StringToSid(rootPlan.MarkerSID)
	if err := validateWindowsManagedRuntimeStagingHandle(stage, target.sid, marker); err != nil {
		return claim, fmt.Errorf("enterprise hooks: staging inode lost its authenticated marker descriptor: %w", err)
	}
	if err := requireWindowsManagedRuntimeDirectoryEmpty(stage); err != nil {
		return claim, err
	}
	if err := renameWindowsManagedRuntimeHandle(stage, parent, ".defenseclaw"); err != nil {
		return claim, fmt.Errorf("enterprise hooks: publish managed runtime root without replacement: %w", err)
	}
	// The target remains unable to write the inode until after its exact final
	// name, marker descriptor, identity, and empty state have all been proved.
	// Applying the target-writable seven-ACE DACL before this point would allow
	// a target process to add content between the empty check and publication.
	if err := validateWindowsManagedRuntimeStagingHandle(stage, target.sid, marker); err != nil {
		return claim, fmt.Errorf("enterprise hooks: verify published marker descriptor: %w", err)
	}
	if got, err := windowsManagedRuntimeHandleIdentity(stage, true); err != nil || got != expected.Identity {
		return claim, fmt.Errorf("enterprise hooks: published managed runtime root changed identity")
	}
	if err := requireWindowsManagedRuntimeDirectoryEmpty(stage); err != nil {
		return claim, err
	}
	if err := requireWindowsManagedRuntimeChildAbsent(parent, rootPlan.StagingLeaf); err != nil {
		return claim, fmt.Errorf("enterprise hooks: staging binding survived publication: %w", err)
	}
	rebound, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess(), true)
	if err != nil {
		return claim, fmt.Errorf("enterprise hooks: rebind published managed runtime name: %w", err)
	}
	defer windows.CloseHandle(rebound)
	if got, err := windowsManagedRuntimeHandleIdentity(rebound, true); err != nil || got != expected.Identity {
		return claim, fmt.Errorf("enterprise hooks: published managed runtime name is not bound to journaled inode")
	}
	if err := validateWindowsManagedRuntimeStagingHandle(rebound, target.sid, marker); err != nil {
		return claim, fmt.Errorf("enterprise hooks: rebound final name lost marker descriptor: %w", err)
	}
	if err := setWindowsManagedRuntimeFinalSecurity(stage, target.sid); err != nil {
		return claim, err
	}
	if err := validateWindowsTargetOwnedDirectoryHandle(stage, target.data, target.sid); err != nil {
		return claim, fmt.Errorf("enterprise hooks: verify final managed runtime DACL: %w", err)
	}
	if err := validateWindowsTargetOwnedDirectoryHandle(rebound, target.data, target.sid); err != nil {
		return claim, err
	}
	claim.Identity = expected.Identity
	claim.Created = true
	claim.State = windowsManagedRuntimeStateCanonical
	return claim, nil
}

func cleanupWindowsManagedRuntimeRoot(
	rootPlan WindowsManagedRuntimeRootPlan,
	expected WindowsManagedRuntimeClaim,
	spec windowsManagedRuntimeCleanupSpec,
) (WindowsManagedRuntimeClaim, error) {
	claim := windowsManagedRuntimeClaimFromPlan(rootPlan)
	target, err := resolveWindowsManagedRuntimeTarget(rootPlan.UserHome, rootPlan.SID, rootPlan.DataDir)
	if err != nil {
		return claim, err
	}
	parent, err := openWindowsManagedRuntimeProfile(target)
	if err != nil {
		return claim, err
	}
	defer windows.CloseHandle(parent)
	if rootPlan.Baseline == windowsManagedRuntimeBaselineCanonical {
		validated, err := validateWindowsManagedRuntimeFinal(parent, target, rootPlan.BaselineIdentity, false)
		if err != nil {
			return claim, fmt.Errorf("enterprise hooks: canonical managed runtime baseline changed during cleanup: %w", err)
		}
		return validated, nil
	}
	// Preserve the last authenticated state until both possible names have been
	// proved absent. In particular, an ok:false cleanup report must never claim
	// that a root was removed when deletion stopped partway through.
	claim.Identity = expected.Identity
	claim.Created = expected.Created
	claim.State = expected.State
	marker, _ := windows.StringToSid(rootPlan.MarkerSID)
	final, finalErr := openWindowsManagedRuntimeChildWithShare(
		parent,
		".defenseclaw",
		windowsManagedRuntimeCleanupRootAccess(),
		windows.FILE_SHARE_READ,
	)
	if finalErr == nil {
		var refusal error
		staging := false
		identity, err := windowsManagedRuntimeHandleIdentity(final, true)
		if err != nil || (expected.Identity != "" && identity != expected.Identity) {
			refusal = fmt.Errorf("enterprise hooks: refuse cleanup of changed managed runtime root identity")
		} else {
			canonical := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid) == nil
			staging = validateWindowsManagedRuntimeCleanupMarkerHandle(final, target.sid, marker) == nil
			claim.Identity = identity
			claim.Created = true
			if canonical {
				claim.State = windowsManagedRuntimeStateCanonical
			} else if staging {
				claim.State = windowsManagedRuntimeStateStaged
			}
			if expected.Identity == "" && !staging {
				refusal = fmt.Errorf("enterprise hooks: refuse cleanup of canonical managed runtime root without journaled identity")
			} else if !canonical && !staging {
				refusal = fmt.Errorf("enterprise hooks: refuse cleanup of unauthenticated managed runtime root")
			}
		}
		if refusal != nil {
			if err := keepWindowsManagedRuntimeRootAside(refusal, final, parent, target, staging); err != nil {
				_ = windows.CloseHandle(final)
				return claim, err
			}
			err = nil
		} else if staging && expected.Identity == "" {
			err = requireWindowsManagedRuntimeDirectoryEmpty(final)
			if err == nil {
				var attributes uint32
				attributes, err = windowsQuarantineHandleAttributes(final)
				if err == nil {
					err = markWindowsQuarantineHandleForDeletion(final, attributes)
				}
			}
		} else {
			err = removeWindowsManagedRuntimeRootContents(final, target, marker, spec, staging)
			var refused *windowsManagedRuntimeCleanupRefusal
			if errors.As(err, &refused) {
				err = keepWindowsManagedRuntimeRootAside(err, final, parent, target, staging)
			}
		}
		if err != nil {
			claim = refreshWindowsManagedRuntimeFailedCleanupClaim(claim, final, target, marker)
			_ = windows.CloseHandle(final)
			return claim, err
		}
		if err := windows.CloseHandle(final); err != nil {
			return claim, err
		}
		if err := requireWindowsManagedRuntimeChildAbsent(parent, ".defenseclaw"); err != nil {
			return claim, fmt.Errorf("enterprise hooks: managed runtime root remains after cleanup: %w", err)
		}
	} else if !windowsManagedRuntimeRootMissing(finalErr) {
		return claim, finalErr
	}
	stage, stageErr := openWindowsManagedRuntimeChildWithShare(
		parent,
		rootPlan.StagingLeaf,
		windowsManagedRuntimeCleanupRootAccess(),
		windows.FILE_SHARE_READ,
	)
	if stageErr == nil {
		var refusal error
		staging := false
		identity, err := windowsManagedRuntimeHandleIdentity(stage, true)
		if err != nil {
			refusal = err
		} else if expected.Identity != "" && identity != expected.Identity {
			refusal = fmt.Errorf("enterprise hooks: refuse cleanup of changed staging identity")
		} else {
			staging = validateWindowsManagedRuntimeStagingHandle(stage, target.sid, marker) == nil
			canonical := expected.Identity != "" && validateWindowsTargetOwnedDirectoryHandle(stage, filepath.Join(target.home, rootPlan.StagingLeaf), target.sid) == nil
			claim.Identity = identity
			claim.Created = true
			if staging {
				claim.State = windowsManagedRuntimeStateStaged
			} else if canonical {
				claim.State = windowsManagedRuntimeStateCanonical
			}
			if !staging && !canonical {
				refusal = fmt.Errorf("enterprise hooks: refuse cleanup of unauthenticated staging root")
			} else if err := requireWindowsManagedRuntimeDirectoryEmpty(stage); err != nil {
				refusal = err
			}
		}
		if refusal != nil {
			err = keepWindowsManagedRuntimeRootAside(refusal, stage, parent, target, staging)
		} else {
			var attributes uint32
			attributes, err = windowsQuarantineHandleAttributes(stage)
			if err == nil {
				err = markWindowsQuarantineHandleForDeletion(stage, attributes)
			}
		}
		closeErr := windows.CloseHandle(stage)
		if err != nil {
			return claim, err
		}
		if closeErr != nil {
			return claim, closeErr
		}
		if err := requireWindowsManagedRuntimeChildAbsent(parent, rootPlan.StagingLeaf); err != nil {
			return claim, fmt.Errorf("enterprise hooks: managed runtime staging root remains after cleanup: %w", err)
		}
	} else if !windowsManagedRuntimeRootMissing(stageErr) {
		return claim, stageErr
	}
	claim.Identity = ""
	claim.Created = false
	claim.State = windowsManagedRuntimeStateAbsent
	return claim, nil
}

func refreshWindowsManagedRuntimeFailedCleanupClaim(
	claim WindowsManagedRuntimeClaim,
	handle windows.Handle,
	target windowsManagedRuntimeTarget,
	marker *windows.SID,
) WindowsManagedRuntimeClaim {
	switch {
	case validateWindowsManagedRuntimeCleanupMarkerHandle(handle, target.sid, marker) == nil:
		claim.State = windowsManagedRuntimeStateStaged
	case validateWindowsTargetOwnedDirectoryHandle(handle, target.data, target.sid) == nil:
		claim.State = windowsManagedRuntimeStateCanonical
	default:
		// A failed report is diagnostic only. Omitting a claim whose live handle
		// matches neither exact descriptor keeps the prior protected journal as
		// recovery authority instead of asserting an unauthenticated state.
		claim.State = ""
	}
	return claim
}

func openWindowsManagedRuntimeProfile(target windowsManagedRuntimeTarget) (windows.Handle, error) {
	if err := validateWindowsEnterpriseHomeAnchor(target.home, target.sid); err != nil {
		return 0, err
	}
	extended, err := winpath.Extended(target.home)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY|
			windows.FILE_APPEND_DATA|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: open managed runtime profile anchor: %w", err)
	}
	if err := validateWindowsGuardianACLHandle(handle, target.sid, true, false, true); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("enterprise hooks: reject managed runtime profile anchor: %w", err)
	}
	return handle, nil
}

func openOrCreateWindowsManagedRuntimeStage(parent windows.Handle, leaf string, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, bool, error) {
	name, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return 0, false, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         name,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windowsManagedRuntimeStageMutationAccess(),
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|
			windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err == nil {
		return handle, true, nil
	}
	if !errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		return 0, false, err
	}
	attributes.SecurityDescriptor = nil
	err = windows.NtCreateFile(
		&handle,
		windowsManagedRuntimeStageMutationAccess(),
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|
			windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return 0, false, err
	}
	return handle, false, nil
}

func openWindowsManagedRuntimeChild(parent windows.Handle, leaf string, access uint32, shareDelete bool) (windows.Handle, error) {
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if shareDelete {
		share |= windows.FILE_SHARE_DELETE
	}
	return openWindowsManagedRuntimeChildWithShare(parent, leaf, access, share)
}

func openWindowsManagedRuntimeChildWithShare(parent windows.Handle, leaf string, access, share uint32) (windows.Handle, error) {
	if err := validateWindowsManagedRuntimeLeaf(leaf); err != nil {
		return 0, err
	}
	// Every open below uses FILE_SYNCHRONOUS_IO_NONALERT. NtCreateFile requires
	// SYNCHRONIZE in DesiredAccess for either synchronous I/O option; enforce the
	// pairing here so read-only absence probes cannot accidentally become invalid
	// native calls.
	access |= windows.SYNCHRONIZE
	name, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		share,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	return handle, err
}

func windowsManagedRuntimeStageMutationAccess() uint32 {
	return windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.READ_CONTROL |
		windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE
}

func windowsManagedRuntimeFinalReadAccess() uint32 {
	return windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE
}

func windowsManagedRuntimeCleanupRootAccess() uint32 {
	return windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES |
		windows.FILE_LIST_DIRECTORY | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE
}

func windowsManagedRuntimeStagingSecurityDescriptor(target, marker *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	if target == nil || marker == nil || target.Equals(marker) {
		return nil, fmt.Errorf("enterprise hooks: invalid managed runtime staging principals")
	}
	sddl := fmt.Sprintf(
		"O:%sG:BAD:P(D;;RC;;;%s)(A;;0x%x;;;OW)(A;;0x001f01ff;;;SY)(A;;0x001f01ff;;;BA)",
		marker.String(), marker.String(), uint32(windowsManagedRuntimeOwnerMetadataMask),
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: build managed runtime staging descriptor: %w", err)
	}
	if err := validateWindowsManagedRuntimeStagingDescriptor(descriptor, target, marker); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func validateWindowsManagedRuntimeStagingHandle(handle windows.Handle, target, marker *windows.SID) error {
	return validateWindowsManagedRuntimeMarkerHandle(handle, target, marker, windowsManagedRuntimeStagingControl)
}

func validateWindowsManagedRuntimeQuarantineHandle(handle windows.Handle, target, marker *windows.SID) error {
	return validateWindowsManagedRuntimeMarkerHandle(handle, target, marker, windowsManagedRuntimeQuarantineControl)
}

func validateWindowsManagedRuntimeCleanupMarkerHandle(handle windows.Handle, target, marker *windows.SID) error {
	return validateWindowsManagedRuntimeMarkerHandle(
		handle,
		target,
		marker,
		windowsManagedRuntimeStagingControl,
		windowsManagedRuntimeQuarantineControl,
	)
}

func validateWindowsManagedRuntimeMarkerHandle(
	handle windows.Handle,
	target, marker *windows.SID,
	expectedControls ...windows.SECURITY_DESCRIPTOR_CONTROL,
) error {
	if _, err := windowsManagedRuntimeHandleIdentity(handle, true); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return validateWindowsManagedRuntimeMarkerDescriptor(descriptor, target, marker, expectedControls...)
}

func validateWindowsManagedRuntimeStagingDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, target, marker *windows.SID) error {
	return validateWindowsManagedRuntimeMarkerDescriptor(descriptor, target, marker, windowsManagedRuntimeStagingControl)
}

func validateWindowsManagedRuntimeMarkerDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	target, marker *windows.SID,
	expectedControls ...windows.SECURITY_DESCRIPTOR_CONTROL,
) error {
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || ownerDefaulted || owner == nil || !owner.Equals(marker) || owner.Equals(target) {
		return fmt.Errorf("enterprise hooks: managed runtime staging owner is not the exact random marker SID")
	}
	group, groupDefaulted, err := descriptor.Group()
	administrators, administratorsErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || administratorsErr != nil || group == nil || groupDefaulted || !group.Equals(administrators) {
		return fmt.Errorf("enterprise hooks: managed runtime staging group is noncanonical")
	}
	control, revision, err := descriptor.Control()
	if err != nil || revision != 1 || !windowsManagedRuntimeMarkerControlMatches(control, expectedControls...) {
		return fmt.Errorf("enterprise hooks: managed runtime marker descriptor control 0x%04x is noncanonical", uint16(control))
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount != 4 {
		return fmt.Errorf("enterprise hooks: managed runtime staging DACL is not exact")
	}
	ownerRights, _ := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	wantSIDs := []*windows.SID{marker, ownerRights, system, administrators}
	wantTypes := []uint8{windows.ACCESS_DENIED_ACE_TYPE, windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_ALLOWED_ACE_TYPE}
	wantMasks := []windows.ACCESS_MASK{windows.READ_CONTROL, windowsManagedRuntimeOwnerMetadataMask, 0x001f01ff, 0x001f01ff}
	header := (*windowsManagedRuntimeACLHeader)(unsafe.Pointer(dacl))
	if header.Revision != 2 || header.ACECount != 4 || header.Sbz1 != 0 || header.Sbz2 != 0 {
		return fmt.Errorf("enterprise hooks: managed runtime staging ACL header is noncanonical")
	}
	expectedACLSize := uint16(unsafe.Sizeof(windowsManagedRuntimeACLHeader{}))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Errorf("enterprise hooks: inspect managed runtime staging ACE %d: %w", index, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		wantSize := uint16(unsafe.Offsetof(ace.SidStart)) + uint16(wantSIDs[index].Len())
		if ace.Header.AceType != wantTypes[index] || ace.Header.AceFlags != 0 || ace.Header.AceSize != wantSize || ace.Mask != wantMasks[index] || !sid.Equals(wantSIDs[index]) {
			return fmt.Errorf("enterprise hooks: managed runtime staging ACE %d is noncanonical", index)
		}
		expectedACLSize += wantSize
	}
	if header.Size != expectedACLSize {
		return fmt.Errorf("enterprise hooks: managed runtime staging ACL size is noncanonical")
	}
	return nil
}

func windowsManagedRuntimeMarkerControlMatches(
	control windows.SECURITY_DESCRIPTOR_CONTROL,
	expectedControls ...windows.SECURITY_DESCRIPTOR_CONTROL,
) bool {
	for _, expected := range expectedControls {
		if control == expected {
			return true
		}
	}
	return false
}

func deleteRejectedWindowsManagedRuntimeStage(handle windows.Handle) error {
	attributes, err := windowsQuarantineHandleAttributes(handle)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect rejected fresh staging root: %w", err)
	}
	if err := markWindowsQuarantineHandleForDeletion(handle, attributes); err != nil {
		return fmt.Errorf("enterprise hooks: remove rejected fresh staging root: %w", err)
	}
	return nil
}

func setWindowsManagedRuntimeFinalSecurity(handle windows.Handle, target *windows.SID) error {
	descriptor, err := windowsTargetOwnedDirectorySecurityDescriptor(target)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: final managed runtime DACL is unavailable")
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		target,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: install final managed runtime owner and DACL: %w", err)
	}
	runtime.KeepAlive(descriptor)
	return nil
}

func setWindowsManagedRuntimeMarkerSecurity(handle windows.Handle, target, marker *windows.SID) error {
	descriptor, err := windowsManagedRuntimeStagingSecurityDescriptor(target, marker)
	if err != nil {
		return err
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return fmt.Errorf("enterprise hooks: managed runtime quarantine group is unavailable")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: managed runtime quarantine DACL is unavailable")
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		marker,
		group,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: quarantine managed runtime directory: %w", err)
	}
	runtime.KeepAlive(descriptor)
	if err := validateWindowsManagedRuntimeQuarantineHandle(handle, target, marker); err != nil {
		return fmt.Errorf("enterprise hooks: verify managed runtime quarantine descriptor: %w", err)
	}
	return nil
}

func renameWindowsManagedRuntimeHandle(handle, parent windows.Handle, finalLeaf string) error {
	name, err := windows.UTF16FromString(finalLeaf)
	if err != nil || len(name) < 2 {
		return windows.ERROR_INVALID_NAME
	}
	name = name[:len(name)-1]
	var layout windowsManagedRuntimeFileRenameInfo
	buffer := make([]byte, int(unsafe.Offsetof(layout.FileName))+len(name)*2)
	info := (*windowsManagedRuntimeFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.RootDirectory = parent
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	var status windows.IO_STATUS_BLOCK
	err = windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
	runtime.KeepAlive(buffer)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS) {
			return windows.ERROR_ALREADY_EXISTS
		}
		var ntStatus windows.NTStatus
		if errors.As(err, &ntStatus) {
			return ntStatus.Errno()
		}
	}
	return err
}

func validateWindowsManagedRuntimePlan(plan WindowsManagedRuntimePlan, manifest Manifest) error {
	return validateWindowsManagedRuntimePlanRows(plan, manifest, false, false)
}

// validateWindowsManagedRuntimePlanRows validates plan against manifest. With
// allowRowDrift the manifest's enabled row count may differ from the plan's
// (a republication that changed rows of the same users); the resolved profile
// roots must still match the plan exactly, in order. Only a validation plan
// (allowPending) may carry a pending root, and only for a profile whose rows
// are all deferred.
func validateWindowsManagedRuntimePlanRows(plan WindowsManagedRuntimePlan, manifest Manifest, allowRowDrift, allowPending bool) error {
	if plan.SchemaVersion != WindowsManagedRuntimePlanSchemaVersion {
		return fmt.Errorf("enterprise hooks: unsupported managed runtime plan schema %d", plan.SchemaVersion)
	}
	if !filepath.IsAbs(plan.ManifestPath) || filepath.Clean(plan.ManifestPath) != plan.ManifestPath {
		return fmt.Errorf("enterprise hooks: managed runtime plan manifest path is not canonical absolute")
	}
	if !validWindowsManagedRuntimeDigest(plan.ManifestSHA256) {
		return fmt.Errorf("enterprise hooks: managed runtime plan manifest digest is invalid")
	}
	targets, err := resolveWindowsManagedRuntimeTargets(manifest)
	if err != nil {
		return err
	}
	targetCount := 0
	for _, row := range manifest.Targets {
		if row.IsEnabled() {
			targetCount++
		}
	}
	if (!allowRowDrift && plan.TargetCount != targetCount) || targetCount > windowsManagedRuntimeMaxRoots*3 {
		return fmt.Errorf("enterprise hooks: managed runtime plan target count does not match manifest")
	}
	if len(plan.Roots) != len(targets) || len(plan.Roots) > windowsManagedRuntimeMaxRoots {
		return fmt.Errorf("enterprise hooks: managed runtime plan root count does not match manifest")
	}
	seenLeaf := make(map[string]bool)
	seenMarker := make(map[string]bool)
	var deferredOnly map[string]bool
	if allowPending {
		deferredOnly = windowsManagedRuntimeDeferredOnlyRoots(manifest)
	}
	for index, target := range targets {
		root := plan.Roots[index]
		if !sameWindowsEnterprisePath(root.UserHome, target.home) || !sameWindowsEnterprisePath(root.DataDir, target.data) || !strings.EqualFold(root.SID, target.sid.String()) {
			return fmt.Errorf("enterprise hooks: managed runtime plan root %d does not match manifest", index)
		}
		pending := root.Baseline == windowsManagedRuntimeBaselinePending &&
			deferredOnly[windowsManagedRuntimeRootKey(target.sid.String(), target.home)]
		if root.Baseline != windowsManagedRuntimeBaselineAbsent && root.Baseline != windowsManagedRuntimeBaselineCanonical && !pending {
			return fmt.Errorf("enterprise hooks: managed runtime plan root %d has invalid baseline", index)
		}
		if (root.Baseline == windowsManagedRuntimeBaselineCanonical) != (root.BaselineIdentity != "") || (root.BaselineIdentity != "" && !validWindowsManagedRuntimeIdentity(root.BaselineIdentity)) {
			return fmt.Errorf("enterprise hooks: managed runtime plan root %d has invalid baseline identity", index)
		}
		if !validWindowsManagedRuntimeStageLeaf(root.StagingLeaf) || seenLeaf[strings.ToLower(root.StagingLeaf)] {
			return fmt.Errorf("enterprise hooks: managed runtime plan root %d has invalid or duplicate staging leaf", index)
		}
		seenLeaf[strings.ToLower(root.StagingLeaf)] = true
		marker, err := parseWindowsManagedRuntimeMarkerSID(root.MarkerSID)
		if err != nil || marker == nil || marker.Equals(target.sid) || windowsEnterpriseSystemIdentity(marker) || windowsEnterpriseAdminIdentity(marker) || seenMarker[strings.ToUpper(root.MarkerSID)] {
			return fmt.Errorf("enterprise hooks: managed runtime plan root %d has invalid or duplicate marker SID", index)
		}
		seenMarker[strings.ToUpper(root.MarkerSID)] = true
	}
	return nil
}

func validateWindowsManagedRuntimeRequest(request WindowsManagedRuntimeRequest, manifest Manifest, requireClaims bool) (map[string]WindowsManagedRuntimeClaim, error) {
	return validateWindowsManagedRuntimeRequestRows(request, manifest, requireClaims, false)
}

func validateWindowsManagedRuntimeRequestRows(request WindowsManagedRuntimeRequest, manifest Manifest, requireClaims, allowRowDrift bool) (map[string]WindowsManagedRuntimeClaim, error) {
	if request.SchemaVersion != WindowsManagedRuntimeRequestSchemaVersion {
		return nil, fmt.Errorf("enterprise hooks: unsupported managed runtime request schema %d", request.SchemaVersion)
	}
	if err := validateWindowsManagedRuntimePlanRows(request.Plan, manifest, allowRowDrift, false); err != nil {
		return nil, err
	}
	planRoots := make(map[string]WindowsManagedRuntimeRootPlan, len(request.Plan.Roots))
	for _, root := range request.Plan.Roots {
		planRoots[windowsManagedRuntimeRootKey(root.SID, root.UserHome)] = root
	}
	if len(request.Claims) > len(request.Plan.Roots) {
		return nil, fmt.Errorf("enterprise hooks: managed runtime request has extra claims")
	}
	claims := make(map[string]WindowsManagedRuntimeClaim)
	for _, claim := range request.Claims {
		key := windowsManagedRuntimeRootKey(claim.SID, claim.UserHome)
		if _, exists := claims[key]; exists {
			return nil, fmt.Errorf("enterprise hooks: duplicate managed runtime claim")
		}
		root, planned := planRoots[key]
		if !planned || !sameWindowsEnterprisePath(claim.UserHome, root.UserHome) ||
			!sameWindowsEnterprisePath(claim.DataDir, root.DataDir) || !strings.EqualFold(claim.SID, root.SID) {
			return nil, fmt.Errorf("enterprise hooks: managed runtime claim is not in the protected plan")
		}
		if claim.Identity == "" || !validWindowsManagedRuntimeIdentity(claim.Identity) {
			return nil, fmt.Errorf("enterprise hooks: invalid managed runtime claim identity")
		}
		if root.Baseline == windowsManagedRuntimeBaselineAbsent {
			if !claim.Created || (claim.State != windowsManagedRuntimeStateStaged && claim.State != windowsManagedRuntimeStateCanonical) {
				return nil, fmt.Errorf("enterprise hooks: absent-baseline managed runtime claim is not an authenticated created state")
			}
		} else if claim.Created || claim.State != windowsManagedRuntimeStateCanonical || claim.Identity != root.BaselineIdentity {
			return nil, fmt.Errorf("enterprise hooks: existing-baseline managed runtime claim is noncanonical")
		}
		claims[key] = claim
	}
	for _, root := range request.Plan.Roots {
		key := windowsManagedRuntimeRootKey(root.SID, root.UserHome)
		claim, ok := claims[key]
		if root.Baseline == windowsManagedRuntimeBaselineCanonical {
			if ok && (claim.Identity != root.BaselineIdentity || claim.Created) {
				return nil, fmt.Errorf("enterprise hooks: existing managed runtime claim does not match baseline")
			}
			if !ok {
				claims[key] = WindowsManagedRuntimeClaim{UserHome: root.UserHome, DataDir: root.DataDir, SID: root.SID, Identity: root.BaselineIdentity, State: windowsManagedRuntimeStateCanonical}
			}
			continue
		}
		if requireClaims && (!ok || !claim.Created || claim.Identity == "") {
			return nil, fmt.Errorf("enterprise hooks: finalize is missing a journaled created-root claim")
		}
	}
	return claims, nil
}

func windowsManagedRuntimeClaimFromPlan(plan WindowsManagedRuntimeRootPlan) WindowsManagedRuntimeClaim {
	return WindowsManagedRuntimeClaim{UserHome: plan.UserHome, DataDir: plan.DataDir, SID: plan.SID}
}

func windowsManagedRuntimeRootKey(sid, home string) string {
	return strings.ToUpper(strings.TrimSpace(sid)) + "\x00" + strings.ToUpper(filepath.Clean(strings.TrimSpace(home)))
}

func validWindowsManagedRuntimeDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validWindowsManagedRuntimeStageLeaf(value string) bool {
	if !strings.HasPrefix(value, windowsManagedRuntimeStagePrefix) || len(value) != len(windowsManagedRuntimeStagePrefix)+windowsManagedRuntimeStageRandomBytes*2 {
		return false
	}
	_, err := hex.DecodeString(value[len(windowsManagedRuntimeStagePrefix):])
	return err == nil && value == strings.ToLower(value)
}

func parseWindowsManagedRuntimeMarkerSID(value string) (*windows.SID, error) {
	parts := strings.Split(value, "-")
	if len(parts) != 4+windowsManagedRuntimeMarkerSubAuths || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return nil, fmt.Errorf("enterprise hooks: invalid managed runtime marker SID form")
	}
	for _, part := range parts[4:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("enterprise hooks: invalid managed runtime marker SID subauthority")
		}
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return nil, fmt.Errorf("enterprise hooks: invalid managed runtime marker SID subauthority")
		}
	}
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || sid.String() != value {
		return nil, fmt.Errorf("enterprise hooks: invalid managed runtime marker SID")
	}
	return sid, nil
}

func validateWindowsManagedRuntimeLeaf(value string) error {
	if value == ".defenseclaw" || validWindowsManagedRuntimeStageLeaf(value) {
		return nil
	}
	if _, _, ok := parseWindowsManagedRuntimeBundleLeaf(value); ok {
		return nil
	}
	if _, ok := windowsManagedRuntimeCleanupLeaves[value]; ok {
		return nil
	}
	for _, leaf := range []string{
		"hooks",
		"inventory.db", "inventory.db-journal", "inventory.db-shm", "inventory.db-wal",
		"hook_contract_lock.json", "hook_contract_lock.json.lock",
		".token", ".hookcfg", ".hookcfg.lock",
	} {
		if value == leaf {
			return nil
		}
	}
	return fmt.Errorf("enterprise hooks: invalid managed runtime leaf %q", value)
}

func randomWindowsManagedRuntimeMarkerSID(source io.Reader) (*windows.SID, error) {
	buffer := make([]byte, windowsManagedRuntimeMarkerSubAuths*4)
	if _, err := io.ReadFull(source, buffer); err != nil {
		return nil, fmt.Errorf("enterprise hooks: generate managed runtime marker SID: %w", err)
	}
	parts := make([]string, 0, windowsManagedRuntimeMarkerSubAuths+1)
	parts = append(parts, "S-1-5-21")
	for index := 0; index < windowsManagedRuntimeMarkerSubAuths; index++ {
		parts = append(parts, fmt.Sprintf("%d", binary.LittleEndian.Uint32(buffer[index*4:])))
	}
	sid, err := windows.StringToSid(strings.Join(parts, "-"))
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse generated managed runtime marker SID: %w", err)
	}
	return sid, nil
}

func windowsManagedRuntimeHandleIdentity(handle windows.Handle, directory bool) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect managed runtime identity: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return "", fmt.Errorf("enterprise hooks: managed runtime identity has an unsafe object type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return "", fmt.Errorf("enterprise hooks: managed runtime cleanup file has %d hard links", info.NumberOfLinks)
	}
	return fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func validWindowsManagedRuntimeIdentity(value string) bool {
	if len(value) != 25 || value[8] != ':' {
		return false
	}
	for index, char := range value {
		if index == 8 {
			continue
		}
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func requireWindowsManagedRuntimeChildAbsent(parent windows.Handle, leaf string) error {
	handle, err := openWindowsManagedRuntimeChild(parent, leaf, windows.FILE_READ_ATTRIBUTES, true)
	if windowsManagedRuntimeRootMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = windows.CloseHandle(handle)
	return windows.ERROR_ALREADY_EXISTS
}

func requireWindowsManagedRuntimeDirectoryEmpty(handle windows.Handle) error {
	names, err := windowsQuarantineDirectoryNames(handle)
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return fmt.Errorf("enterprise hooks: managed runtime staging directory is not empty")
	}
	return nil
}

func validateWindowsManagedRuntimeFinal(parent windows.Handle, target windowsManagedRuntimeTarget, identity string, created bool) (WindowsManagedRuntimeClaim, error) {
	claim := WindowsManagedRuntimeClaim{UserHome: target.home, DataDir: target.data, SID: target.sid.String(), Identity: identity, Created: created, State: windowsManagedRuntimeStateCanonical}
	final, err := openWindowsManagedRuntimeChild(parent, ".defenseclaw", windowsManagedRuntimeFinalReadAccess(), false)
	if err != nil {
		return claim, err
	}
	defer windows.CloseHandle(final)
	if err := validateWindowsTargetOwnedDirectoryHandle(final, target.data, target.sid); err != nil {
		return claim, err
	}
	got, err := windowsManagedRuntimeHandleIdentity(final, true)
	if err != nil || got != identity {
		return claim, fmt.Errorf("enterprise hooks: managed runtime final identity changed")
	}
	return claim, nil
}

type windowsManagedRuntimePinnedCleanupFile struct {
	parent   windows.Handle
	name     string
	label    string
	handle   windows.Handle
	identity string
	contract windowsManagedRuntimeCleanupFileContract
}

// windowsManagedRuntimePinnedCleanupDir is one pinned subdirectory below the
// root: hooks, connector_backups, or one connector_backups\<connector>.
type windowsManagedRuntimePinnedCleanupDir struct {
	parent windows.Handle
	name   string
	path   string
	label  string
	handle windows.Handle
	id     string
	names  map[string]struct{}
	files  []*windowsManagedRuntimePinnedCleanupFile
	// connectorBackup marks connector_backups and its connector folders,
	// which may keep their connector setup descriptor.
	connectorBackup bool
}

type windowsManagedRuntimePinnedCleanupTree struct {
	rootNames map[string]struct{}
	rootFiles []*windowsManagedRuntimePinnedCleanupFile
	// dirs lists every pinned subdirectory, each one after its parent.
	dirs []*windowsManagedRuntimePinnedCleanupDir
}

func (tree *windowsManagedRuntimePinnedCleanupTree) files() []*windowsManagedRuntimePinnedCleanupFile {
	files := append([]*windowsManagedRuntimePinnedCleanupFile(nil), tree.rootFiles...)
	for _, dir := range tree.dirs {
		files = append(files, dir.files...)
	}
	return files
}

func (tree *windowsManagedRuntimePinnedCleanupTree) close() {
	if tree == nil {
		return
	}
	for _, file := range tree.files() {
		if file != nil && file.handle != 0 {
			_ = windows.CloseHandle(file.handle)
			file.handle = 0
		}
	}
	for index := len(tree.dirs) - 1; index >= 0; index-- {
		if dir := tree.dirs[index]; dir.handle != 0 {
			_ = windows.CloseHandle(dir.handle)
			dir.handle = 0
		}
	}
}

func removeWindowsManagedRuntimeRootContents(
	root windows.Handle,
	target windowsManagedRuntimeTarget,
	marker *windows.SID,
	spec windowsManagedRuntimeCleanupSpec,
	rootMarker bool,
) error {
	if spec.rootFiles == nil || spec.hookFiles == nil {
		return fmt.Errorf("enterprise hooks: absent-baseline cleanup has no protected manifest contract")
	}
	if marker == nil {
		return fmt.Errorf("enterprise hooks: absent-baseline cleanup marker is unavailable")
	}
	tree, err := pinWindowsManagedRuntimeCleanupTree(root, target, spec)
	if err != nil {
		if windowsManagedRuntimeCleanupTransient(err) {
			return err
		}
		return &windowsManagedRuntimeCleanupRefusal{err: err}
	}
	defer tree.close()

	// All names and every no-follow child handle are pinned before the first
	// deletion. Existing data writers conflict with read-only sharing. After
	// preflight, the root namespace is changed through that same handle to the
	// plan's unforgeable marker descriptor, closing the path-based create window
	// before any known inode is deleted. The pinned subdirectory handles reject
	// a pre-existing or newly opened FILE_ADD/DELETE-capable directory handle.
	requireNames := func() error {
		if err := requireWindowsManagedRuntimePinnedNames(root, tree.rootNames, "managed runtime root"); err != nil {
			return err
		}
		for _, dir := range tree.dirs {
			if err := requireWindowsManagedRuntimePinnedNames(dir.handle, dir.names, dir.label); err != nil {
				return err
			}
		}
		return nil
	}
	if err := requireNames(); err != nil {
		return err
	}
	for _, file := range tree.files() {
		identity, err := validateWindowsManagedRuntimeCleanupFileHandle(file.handle, target, file.contract, file.label)
		if err != nil || identity != file.identity {
			return fmt.Errorf("enterprise hooks: managed runtime cleanup file %q changed after preflight", file.name)
		}
	}
	if err := validateWindowsManagedRuntimeCleanupDirectoryHandle(root, target.data, target.sid, marker, rootMarker); err != nil {
		return fmt.Errorf("enterprise hooks: managed runtime cleanup root changed after preflight: %w", err)
	}
	for _, dir := range tree.dirs {
		if err := validateWindowsManagedRuntimeCleanupSubdirectoryHandle(dir.handle, dir.path, target.sid, dir.connectorBackup); err != nil {
			return fmt.Errorf("enterprise hooks: %s changed after preflight: %w", dir.label, err)
		}
		if identity, err := windowsManagedRuntimeHandleIdentity(dir.handle, true); err != nil || identity != dir.id {
			return fmt.Errorf("enterprise hooks: %s identity changed after preflight", dir.label)
		}
	}
	if !rootMarker {
		if err := setWindowsManagedRuntimeMarkerSecurity(root, target.sid, marker); err != nil {
			return err
		}
		rootMarker = true
	}
	if err := validateWindowsManagedRuntimeCleanupMarkerHandle(root, target.sid, marker); err != nil {
		return fmt.Errorf("enterprise hooks: managed runtime root quarantine changed: %w", err)
	}
	if windowsManagedRuntimeCleanupPostPreflight != nil {
		if err := windowsManagedRuntimeCleanupPostPreflight(target.data, filepath.Join(target.data, "hooks")); err != nil {
			return fmt.Errorf("enterprise hooks: managed runtime post-preflight check: %w", err)
		}
	}
	// Re-enumeration detects anything that raced before marker quarantine. Once
	// the root carries the marker descriptor, the enrolled target has no
	// path-based traversal, create, or rename capability through deletion.
	if err := requireNames(); err != nil {
		return err
	}

	// Children are deleted before their parents.
	for index := len(tree.dirs) - 1; index >= 0; index-- {
		dir := tree.dirs[index]
		for _, file := range dir.files {
			if err := deleteWindowsManagedRuntimePinnedFile(file, target); err != nil {
				return err
			}
		}
		if err := requireWindowsManagedRuntimeDirectoryEmpty(dir.handle); err != nil {
			return err
		}
		attributes, err := windowsQuarantineHandleAttributes(dir.handle)
		if err == nil {
			err = markWindowsQuarantineHandleForDeletion(dir.handle, attributes)
		}
		closeErr := windows.CloseHandle(dir.handle)
		dir.handle = 0
		if err != nil {
			return err
		}
		if closeErr != nil {
			return fmt.Errorf("enterprise hooks: close deleted %s: %w", dir.label, closeErr)
		}
		if err := requireWindowsManagedRuntimeChildAbsent(dir.parent, dir.name); err != nil {
			return fmt.Errorf("enterprise hooks: %s remains after cleanup: %w", dir.label, err)
		}
	}
	for _, file := range tree.rootFiles {
		if err := deleteWindowsManagedRuntimePinnedFile(file, target); err != nil {
			return err
		}
	}
	if err := requireWindowsManagedRuntimeDirectoryEmpty(root); err != nil {
		return err
	}
	attributes, err := windowsQuarantineHandleAttributes(root)
	if err != nil {
		return err
	}
	return markWindowsQuarantineHandleForDeletion(root, attributes)
}

// windowsManagedRuntimeCleanupRefusal is a cleanup preflight that refused the
// root's content before anything was changed. Nothing in the root is deleted;
// cleanupWindowsManagedRuntimeRoot keeps the root aside instead.
type windowsManagedRuntimeCleanupRefusal struct{ err error }

func (r *windowsManagedRuntimeCleanupRefusal) Error() string { return r.err.Error() }
func (r *windowsManagedRuntimeCleanupRefusal) Unwrap() error { return r.err }

// windowsManagedRuntimeCleanupTransient reports a preflight failure a retry
// can clear: a live handle on the root's content, or an entry that went away
// while it was pinned. Those keep the transaction pending as before.
func windowsManagedRuntimeCleanupTransient(err error) bool {
	return errors.Is(err, windows.STATUS_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) || windowsManagedRuntimeRootMissing(err)
}

// keepWindowsManagedRuntimeRootAside ends a cleanup that refused root before
// deleting anything. The Secure Client profile returns the refusal, so its
// rollback stays pending as before. The standalone profile renames root aside
// (detachWindowsManagedRuntimeRoot) and the rollback goes on.
func keepWindowsManagedRuntimeRootAside(refusal error, root, parent windows.Handle, target windowsManagedRuntimeTarget, markerOwned bool) error {
	if !windowsEnterpriseStandaloneProcess() {
		return refusal
	}
	if err := detachWindowsManagedRuntimeRoot(root, parent, target, markerOwned); err != nil {
		return errors.Join(refusal, err)
	}
	return nil
}

// detachWindowsManagedRuntimeRoot renames a journaled root whose content the
// preflight refused to .defenseclaw.rollback-<random> beside it, so neither
// managed name remains and the rollback completes without deleting anything
// it could not authenticate. A marker-quarantined root goes back to the
// account's own owner and DACL, best effort, so the account can review it.
func detachWindowsManagedRuntimeRoot(root, parent windows.Handle, target windowsManagedRuntimeTarget, markerOwned bool) error {
	random := make([]byte, windowsManagedRuntimeStageRandomBytes)
	if _, err := io.ReadFull(windowsManagedRuntimeEntropy, random); err != nil {
		return fmt.Errorf("enterprise hooks: name the kept managed runtime root: %w", err)
	}
	leaf := windowsManagedRuntimeRollbackPrefix + hex.EncodeToString(random)
	if err := renameWindowsManagedRuntimeHandle(root, parent, leaf); err != nil {
		return fmt.Errorf("enterprise hooks: keep the refused managed runtime root aside as %s: %w", leaf, err)
	}
	if markerOwned {
		_ = setWindowsManagedRuntimeFinalSecurity(root, target.sid)
	}
	return nil
}

func pinWindowsManagedRuntimeCleanupTree(
	root windows.Handle,
	target windowsManagedRuntimeTarget,
	spec windowsManagedRuntimeCleanupSpec,
) (*windowsManagedRuntimePinnedCleanupTree, error) {
	tree := &windowsManagedRuntimePinnedCleanupTree{rootNames: make(map[string]struct{})}
	fail := func(err error) (*windowsManagedRuntimePinnedCleanupTree, error) {
		tree.close()
		return nil, err
	}
	// pinDir pins one subdirectory and records its names; the caller then
	// admits each name.
	pinDir := func(parent windows.Handle, name, path, label string, connectorBackup bool) (*windowsManagedRuntimePinnedCleanupDir, []string, error) {
		handle, err := openWindowsManagedRuntimeCleanupChild(parent, name, true)
		if err != nil {
			return nil, nil, fmt.Errorf("enterprise hooks: pin %s: %w", label, err)
		}
		dir := &windowsManagedRuntimePinnedCleanupDir{parent: parent, name: name, path: path, label: label, handle: handle, names: make(map[string]struct{}), connectorBackup: connectorBackup}
		tree.dirs = append(tree.dirs, dir)
		if err := validateWindowsManagedRuntimeCleanupSubdirectoryHandle(handle, path, target.sid, connectorBackup); err != nil {
			return nil, nil, err
		}
		if dir.id, err = windowsManagedRuntimeHandleIdentity(handle, true); err != nil {
			return nil, nil, err
		}
		names, err := windowsQuarantineDirectoryNames(handle)
		if err != nil {
			return nil, nil, fmt.Errorf("enterprise hooks: enumerate %s for cleanup: %w", label, err)
		}
		for _, child := range names {
			dir.names[child] = struct{}{}
		}
		return dir, names, nil
	}
	pinFile := func(dir *windowsManagedRuntimePinnedCleanupDir, name string, contract windowsManagedRuntimeCleanupFileContract) error {
		file, err := pinWindowsManagedRuntimeCleanupFile(dir.handle, name, target, contract, filepath.Join(dir.path, name))
		if err != nil {
			return err
		}
		dir.files = append(dir.files, file)
		return nil
	}
	names, err := windowsQuarantineDirectoryNames(root)
	if err != nil {
		return fail(fmt.Errorf("enterprise hooks: enumerate managed runtime cleanup root: %w", err))
	}
	var hooks, backups []string
	var hookDir, backupDir *windowsManagedRuntimePinnedCleanupDir
	for _, name := range names {
		tree.rootNames[name] = struct{}{}
		switch {
		case name == "hooks":
			hookDir, hooks, err = pinDir(root, name, filepath.Join(target.data, name), "managed hooks directory", false)
			if err != nil {
				return fail(err)
			}
			continue
		case name == windowsManagedRuntimeCleanupBackupDir && len(spec.backupFiles) > 0:
			backupDir, backups, err = pinDir(root, name, filepath.Join(target.data, name), "managed connector backup directory", true)
			if err != nil {
				return fail(err)
			}
			continue
		}
		contract, allowed := spec.rootFiles[name]
		if !allowed {
			return fail(fmt.Errorf("enterprise hooks: refuse managed runtime cleanup with unexpected entry %q", name))
		}
		file, err := pinWindowsManagedRuntimeCleanupFile(root, name, target, contract, filepath.Join(target.data, name))
		if err != nil {
			return fail(err)
		}
		tree.rootFiles = append(tree.rootFiles, file)
	}
	for _, name := range hooks {
		contract, allowed := spec.hookFiles[name]
		if !allowed {
			connectorName, _, parsed := parseWindowsManagedRuntimeBundleLeaf(name)
			_, allowed = spec.generationConnectors[connectorName]
			if parsed && allowed {
				contract = windowsManagedRuntimeCleanupCanonicalFile
			} else {
				allowed = false
			}
		}
		if !allowed {
			return fail(fmt.Errorf("enterprise hooks: refuse managed hooks cleanup with unexpected entry %q", name))
		}
		if err := pinFile(hookDir, name, contract); err != nil {
			return fail(err)
		}
	}
	for _, connectorName := range backups {
		records, allowed := spec.backupFiles[connectorName]
		if !allowed {
			return fail(fmt.Errorf("enterprise hooks: refuse managed connector backup cleanup with unexpected entry %q", connectorName))
		}
		dir, leaves, err := pinDir(backupDir.handle, connectorName, filepath.Join(backupDir.path, connectorName), "managed "+connectorName+" backup directory", true)
		if err != nil {
			return fail(err)
		}
		for _, leaf := range leaves {
			contract, allowed := records[leaf]
			if !allowed {
				return fail(fmt.Errorf("enterprise hooks: refuse managed %s backup cleanup with unexpected entry %q", connectorName, leaf))
			}
			if err := pinFile(dir, leaf, contract); err != nil {
				return fail(err)
			}
		}
	}
	return tree, nil
}

func validateWindowsManagedRuntimeCleanupDirectoryHandle(
	handle windows.Handle,
	path string,
	target, marker *windows.SID,
	markerOwned bool,
) error {
	if markerOwned {
		return validateWindowsManagedRuntimeCleanupMarkerHandle(handle, target, marker)
	}
	return validateWindowsTargetOwnedDirectoryHandle(handle, path, target)
}

func pinWindowsManagedRuntimeCleanupFile(
	parent windows.Handle,
	name string,
	target windowsManagedRuntimeTarget,
	contract windowsManagedRuntimeCleanupFileContract,
	label string,
) (*windowsManagedRuntimePinnedCleanupFile, error) {
	handle, err := openWindowsManagedRuntimeCleanupChild(parent, name, false)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: pin managed runtime cleanup file %q: %w", name, err)
	}
	identity, err := validateWindowsManagedRuntimeCleanupFileHandle(handle, target, contract, label)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("enterprise hooks: reject managed runtime cleanup file %q: %w", name, err)
	}
	return &windowsManagedRuntimePinnedCleanupFile{parent: parent, name: name, label: label, handle: handle, identity: identity, contract: contract}, nil
}

func validateWindowsManagedRuntimeCleanupFileHandle(
	handle windows.Handle,
	target windowsManagedRuntimeTarget,
	contract windowsManagedRuntimeCleanupFileContract,
	label string,
) (string, error) {
	identity, err := windowsManagedRuntimeHandleIdentity(handle, false)
	if err != nil {
		return "", err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || owner == nil {
		return "", fmt.Errorf("enterprise hooks: cleanup file owner is unavailable")
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if contract == windowsManagedRuntimeCleanupHookFile && windowsEnterpriseStandaloneProcess() {
		// Standalone profile only. The handle identity already proves a
		// regular, single-link file reached without a reparse point inside
		// the authenticated root, and the hooks folder only ever holds
		// DefenseClaw scripts and tombstones, so the DACL is not provenance
		// here: removing the file fails safe, refusing it wedged the rollback.
		if ownerDefaulted || !windowsManagedRuntimeHookCleanupOwner(owner, target.sid) {
			return "", fmt.Errorf("enterprise hooks: hook cleanup file has foreign owner %s", windowsSIDString(owner))
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return "", err
		}
		size := int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
		if size > windowsEnterpriseUserFileMaxBytes {
			return "", fmt.Errorf("enterprise hooks: hook cleanup file exceeds %d bytes", windowsEnterpriseUserFileMaxBytes)
		}
		return identity, nil
	}
	if err != nil || dacl == nil {
		return "", fmt.Errorf("enterprise hooks: cleanup file DACL is unavailable")
	}
	switch contract {
	case windowsManagedRuntimeCleanupCanonicalFile:
		if ownerDefaulted || daclDefaulted || !owner.Equals(target.sid) {
			return "", fmt.Errorf("enterprise hooks: canonical cleanup file owner or DACL provenance is invalid")
		}
		if err := validateWindowsUserPathProtectionACL(label, descriptor, dacl, target.sid, false); err != nil {
			return "", err
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return "", err
		}
		size := int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
		if size > windowsEnterpriseUserFileMaxBytes {
			return "", fmt.Errorf("enterprise hooks: canonical cleanup file exceeds %d bytes", windowsEnterpriseUserFileMaxBytes)
		}
	case windowsManagedRuntimeCleanupOwnedLockFile:
		if ownerDefaulted || daclDefaulted || !owner.Equals(target.sid) {
			return "", fmt.Errorf("enterprise hooks: owned lock cleanup file owner or DACL provenance is invalid")
		}
		if canonicalErr := validateWindowsUserPathProtectionACL(label, descriptor, dacl, target.sid, false); canonicalErr != nil {
			if err := validateWindowsManagedRuntimeOwnedLockACL(label, descriptor, dacl, target.sid); err != nil {
				return "", err
			}
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return "", err
		}
		size := int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
		if size > windowsEnterpriseUserFileMaxBytes {
			return "", fmt.Errorf("enterprise hooks: owned lock cleanup file exceeds %d bytes", windowsEnterpriseUserFileMaxBytes)
		}
	case windowsManagedRuntimeCleanupConnectorBackupFile, windowsManagedRuntimeCleanupHookFile:
		kind := "connector backup"
		if contract == windowsManagedRuntimeCleanupHookFile {
			kind = "hook"
		}
		if ownerDefaulted || daclDefaulted || !owner.Equals(target.sid) {
			return "", fmt.Errorf("enterprise hooks: %s cleanup file owner or DACL provenance is invalid", kind)
		}
		if canonicalErr := validateWindowsUserPathProtectionACL(label, descriptor, dacl, target.sid, false); canonicalErr != nil {
			system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
			if err != nil {
				return "", err
			}
			if err := validateWindowsManagedRuntimeExactFileACL(label, kind, descriptor, dacl, []*windows.SID{target.sid, system}); err != nil {
				return "", err
			}
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return "", err
		}
		size := int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
		if size > windowsEnterpriseUserFileMaxBytes {
			return "", fmt.Errorf("enterprise hooks: %s cleanup file exceeds %d bytes", kind, windowsEnterpriseUserFileMaxBytes)
		}
	case windowsManagedRuntimeCleanupGatewayFile:
		administrators, administratorsErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if administratorsErr != nil || ownerDefaulted || (!owner.Equals(target.sid) && !owner.Equals(administrators)) {
			return "", fmt.Errorf("enterprise hooks: gateway cleanup file has foreign owner %s", windowsSIDString(owner))
		}
		if err := rejectWindowsUserRuntimeWriteACEs(label, dacl, target.sid, false, false); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("enterprise hooks: unknown cleanup file contract")
	}
	return identity, nil
}

// windowsManagedRuntimeHookCleanupOwner reports whether owner is one a
// DefenseClaw writer leaves on a hook file: the account (writes under its
// token) or the machine (writes as LocalSystem, owned by LocalSystem or
// Administrators).
func windowsManagedRuntimeHookCleanupOwner(owner, target *windows.SID) bool {
	if owner.Equals(target) {
		return true
	}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(known)
		if err == nil && owner.Equals(sid) {
			return true
		}
	}
	return false
}

// validateWindowsManagedRuntimeOwnedLockACL accepts exactly the descriptor
// connector.withOwnedFileLock creates a lock with: a protected DACL of three
// non-inherited full-control ACEs, one each for the account, LocalSystem and
// Administrators.
func validateWindowsManagedRuntimeOwnedLockACL(
	label string,
	descriptor *windows.SECURITY_DESCRIPTOR,
	dacl *windows.ACL,
	target *windows.SID,
) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return validateWindowsManagedRuntimeExactFileACL(label, "owned lock", descriptor, dacl, []*windows.SID{target, system, administrators})
}

// validateWindowsManagedRuntimeExactFileACL requires a protected DACL of
// exactly one non-inherited full-control ACE for each expected principal.
func validateWindowsManagedRuntimeExactFileACL(
	label, kind string,
	descriptor *windows.SECURITY_DESCRIPTOR,
	dacl *windows.ACL,
	expected []*windows.SID,
) error {
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s DACL control for %s: %w", kind, label, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("enterprise hooks: %s DACL is not protected on %s", kind, label)
	}
	if int(dacl.AceCount) != len(expected) {
		return fmt.Errorf(
			"enterprise hooks: %s DACL on %s has %d ACEs, expected %d",
			kind,
			label,
			dacl.AceCount,
			len(expected),
		)
	}
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect %s ACE %d for %s: %w", kind, index, label, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			mapWindowsUserPathGenericMask(ace.Mask) != windows.ACCESS_MASK(0x001f01ff) {
			return fmt.Errorf("enterprise hooks: %s DACL on %s contains a non-canonical ACE at index %d", kind, label, index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		match := -1
		for candidate, want := range expected {
			if !seen[candidate] && sid.Equals(want) {
				match = candidate
				break
			}
		}
		if match < 0 {
			return fmt.Errorf(
				"enterprise hooks: %s DACL on %s contains unexpected or duplicate ACE for principal %s",
				kind,
				label,
				windowsSIDString(sid),
			)
		}
		seen[match] = true
	}
	return nil
}

// validateWindowsManagedRuntimeCleanupSubdirectoryHandle requires the
// canonical target-owned directory DACL. connector_backups and its connector folders
// may instead keep the descriptor per-user connector setup creates them with
// (safefile.ProtectDirectory as the account: owned by the account, LocalSystem
// and OWNER RIGHTS full control, inherited). The guardian never hardens them.
func validateWindowsManagedRuntimeCleanupSubdirectoryHandle(
	handle windows.Handle,
	path string,
	target *windows.SID,
	connectorBackup bool,
) error {
	canonicalErr := validateWindowsTargetOwnedDirectoryHandle(handle, path, target)
	if canonicalErr == nil || !connectorBackup {
		return canonicalErr
	}
	if err := validateWindowsGuardianACLHandle(handle, target, true, true, false); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	if setup, err := windowsSetupRelaxedDirectoryDACL(descriptor); err != nil {
		return err
	} else if !setup {
		return canonicalErr
	}
	return nil
}

func requireWindowsManagedRuntimePinnedNames(handle windows.Handle, expected map[string]struct{}, label string) error {
	names, err := windowsQuarantineDirectoryNames(handle)
	if err != nil {
		return err
	}
	if len(names) != len(expected) {
		return fmt.Errorf("enterprise hooks: %s changed after full preflight", label)
	}
	for _, name := range names {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("enterprise hooks: %s gained unexpected entry %q after full preflight", label, name)
		}
	}
	return nil
}

func deleteWindowsManagedRuntimePinnedFile(file *windowsManagedRuntimePinnedCleanupFile, target windowsManagedRuntimeTarget) error {
	if file == nil || file.handle == 0 {
		return fmt.Errorf("enterprise hooks: managed runtime cleanup file handle is unavailable")
	}
	identity, err := validateWindowsManagedRuntimeCleanupFileHandle(file.handle, target, file.contract, file.label)
	if err != nil || identity != file.identity {
		return fmt.Errorf("enterprise hooks: managed runtime cleanup file %q changed before deletion", file.name)
	}
	attributes, err := windowsQuarantineHandleAttributes(file.handle)
	if err == nil {
		err = markWindowsQuarantineHandleForDeletion(file.handle, attributes)
	}
	closeErr := windows.CloseHandle(file.handle)
	file.handle = 0
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("enterprise hooks: close deleted cleanup file %q: %w", file.name, closeErr)
	}
	return requireWindowsManagedRuntimeChildAbsent(file.parent, file.name)
}

func openWindowsManagedRuntimeCleanupChild(parent windows.Handle, name string, directory bool) (windows.Handle, error) {
	if err := validateWindowsManagedRuntimeLeaf(name); err != nil {
		return 0, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	access := uint32(windows.DELETE | windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_LIST_DIRECTORY | windows.WRITE_DAC | windows.WRITE_OWNER
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0, windows.FILE_SHARE_READ, windows.FILE_OPEN, options, 0, 0)
	return handle, err
}

func windowsManagedRuntimeRootMissing(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) || errors.Is(err, windows.STATUS_DELETE_PENDING) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func runWindowsManagedRuntimeSetupPrivilege(fn func() error) error {
	if fn == nil {
		return fmt.Errorf("enterprise hooks: managed runtime Setup callback is required")
	}
	if err := requireWindowsEnterpriseAdministrator(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create dedicated Setup privilege token: %w", err)
			return
		}
		var token windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token); err != nil {
			revertErr := revertWindowsManagedRuntimeSetupThread()
			if revertErr == nil {
				runtime.UnlockOSThread()
				result <- fmt.Errorf("enterprise hooks: open Setup privilege token: %w", err)
				return
			}
			result <- fmt.Errorf("enterprise hooks: open Setup privilege token: %v (revert failed: %v)", err, revertErr)
			return
		}
		privilegeErr := enableWindowsThreadPrivilege(token, "SeBackupPrivilege")
		if privilegeErr == nil {
			privilegeErr = enableWindowsThreadPrivilege(token, "SeRestorePrivilege")
		}
		callErr := privilegeErr
		if callErr == nil {
			callErr = fn()
		}
		token.Close()
		if revertErr := revertWindowsManagedRuntimeSetupThread(); revertErr != nil {
			if callErr == nil {
				result <- fmt.Errorf("enterprise hooks: revert Setup privilege token: %w", revertErr)
			} else {
				result <- fmt.Errorf("%v (revert Setup privilege token failed: %v)", callErr, revertErr)
			}
			return
		}
		runtime.UnlockOSThread()
		result <- callErr
	}()
	return <-result
}

func revertWindowsManagedRuntimeSetupThread() error {
	if err := windows.RevertToSelf(); err != nil {
		return err
	}
	// Keep the dedicated OS thread quarantined unless RevertToSelf actually
	// removed its privileged impersonation token. A successful return from the
	// public operation therefore proves no SeBackup/SeRestore thread token was
	// returned to the Go runtime pool.
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token)
	if err == nil {
		_ = token.Close()
		return fmt.Errorf("enterprise hooks: Setup privilege thread retained an impersonation token")
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return fmt.Errorf("enterprise hooks: verify Setup privilege token removal: %w", err)
	}
	return nil
}
