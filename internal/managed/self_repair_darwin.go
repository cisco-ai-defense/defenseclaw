//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// selfRepairOwner, when set, replaces root:wheel as the owner a self repair
// stamps, so tests can exercise the repair path without root.
var selfRepairOwner atomic.Pointer[UnixOwnership]

// OverrideSelfRepairForTesting enables RepairOwnedObject for an unprivileged
// test process and stamps owner instead of root:wheel. The returned function
// restores the previous state. Production code never calls it.
func OverrideSelfRepairForTesting(owner UnixOwnership) (restore func()) {
	previous := selfRepairOwner.Swap(&owner)
	return func() { selfRepairOwner.Store(previous) }
}

// SelfRepairEnabled reports whether this process may repair managed objects
// in place: it runs as root under a managed_enterprise pin. Only the root
// LaunchDaemons (the gateway and the hook guardian) and the installer qualify.
func SelfRepairEnabled() bool {
	if selfRepairOwner.Load() != nil {
		return true
	}
	return os.Geteuid() == 0 && IsManagedEnterprise(PinnedDeploymentMode())
}

func selfRepairOptions(mode os.FileMode) CanonicalOptions {
	// A DefenseClaw-owned object owned by another principal is taken back:
	// nobody else has a claim on it, and the takeover is logged as a
	// boundary finding naming the previous owner.
	opts := CanonicalOptions{AllowUntrustedOwnerTransfer: true, UnixMode: mode, Quiet: true}
	if owner := selfRepairOwner.Load(); owner != nil {
		copied := *owner
		opts.UnixOwner = &copied
	}
	return opts
}

// IsAdministratorUID reports whether uid is root or a member of the admin
// group. Validators accept an administrator owner as drift, never as an
// untrusted principal.
func IsAdministratorUID(uid uint32) bool {
	return uid == 0 || darwinAdminMember(uid)
}

// RepairOwnedObject re-stamps one DefenseClaw-owned object through
// EnsureCanonical and logs the result once: MarkerRepair for a repair,
// MarkerBoundary when an untrusted principal owned or could write it, and
// MarkerAccept for drift left in place. A symlink, extra hard link or wrong
// object type is never followed; with MoveAsideStructural it is renamed aside
// and, with Recreate, a canonical directory is made in its place. A missing
// directory with Recreate is made too. It never fails: the outcome tells the
// caller what happened, and CanonicalUnsupported means this process may not
// repair.
func RepairOwnedObject(object OwnedObject) CanonicalResult {
	result := CanonicalResult{Path: object.Path, Kind: object.Kind, Outcome: CanonicalUnsupported}
	if strings.TrimSpace(object.Path) == "" || !SelfRepairEnabled() {
		return result
	}
	object.Path = filepath.Clean(object.Path)
	opts := selfRepairOptions(object.Mode)
	previousOwner, untrustedOwner := darwinUntrustedOwner(object.Path, object.Kind, opts)

	result, err := EnsureCanonical(object.Path, object.Kind, opts)
	switch result.Outcome {
	case CanonicalMissing:
		if object.Recreate && object.Kind.Directory() {
			return recreateOwnedDirectory(object, opts, "missing")
		}
		return result
	case CanonicalStructural:
		reportCanonicalResult(result, CanonicalOptions{})
		if !object.MoveAsideStructural || !darwinStructuralMovable(object.Path, object.Kind) {
			return result
		}
		reason := "structural"
		if err != nil {
			reason = err.Error()
		}
		if _, moveErr := MoveAsideStructural(object.Path, reason); moveErr != nil {
			return result
		}
		if object.Recreate && object.Kind.Directory() {
			return recreateOwnedDirectory(object, opts, "moved aside: "+reason)
		}
		result.Outcome = CanonicalMissing
		return result
	case CanonicalRepaired:
		fields := map[string]string{
			"path":   result.Path,
			"object": string(result.Kind),
			"reason": strings.Join(result.Drift, "; "),
		}
		EmitResilienceEvent(MarkerRepair, fields)
		if untrustedOwner || len(result.UntrustedWriters) > 0 {
			boundary := map[string]string{
				"path":   result.Path,
				"object": string(result.Kind),
				"action": "repaired",
				"reason": "an untrusted principal owned or could write a DefenseClaw object",
			}
			principals := append([]string(nil), result.UntrustedWriters...)
			if untrustedOwner {
				principals = append(principals, "owner:"+previousOwner)
			}
			boundary["principal"] = strings.Join(principals, ",")
			if advisoryLogDedupe.shouldEmit(result.Path, MarkerBoundary, FormatResilienceEvent(MarkerBoundary, boundary)) {
				EmitResilienceEvent(MarkerBoundary, boundary)
			}
		}
	default:
		reportCanonicalResult(result, CanonicalOptions{})
	}
	return result
}

// RepairOwnedObjects repairs objects in order, parents before children. The
// children of a directory that is still structurally wrong are skipped, so a
// repair never runs through a symlinked or swapped folder.
func RepairOwnedObjects(objects []OwnedObject) []CanonicalResult {
	results := make([]CanonicalResult, 0, len(objects))
	var blocked []string
	for _, object := range objects {
		skip := false
		for _, parent := range blocked {
			if pathAtOrUnder(filepath.Clean(object.Path), parent) {
				skip = true
				break
			}
		}
		if skip {
			results = append(results, CanonicalResult{Path: object.Path, Kind: object.Kind, Outcome: CanonicalStructural})
			continue
		}
		result := RepairOwnedObject(object)
		if object.Kind.Directory() && result.Outcome == CanonicalStructural {
			blocked = append(blocked, filepath.Clean(object.Path))
		}
		results = append(results, result)
	}
	return results
}

// darwinUntrustedOwner reports whether path is owned by a principal that is
// neither the repair's canonical owner, root, nor an administrator.
func darwinUntrustedOwner(path string, kind ObjectKind, opts CanonicalOptions) (string, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return "", false
	}
	form, ok := darwinCanonicalFormFor(kind, opts)
	if !ok || st.Uid == form.UID || st.Uid == 0 {
		return "", false
	}
	if darwinAdminMember(st.Uid) {
		return "", false
	}
	return "uid:" + strconv.FormatUint(uint64(st.Uid), 10), true
}

// darwinStructuralMovable reports whether path is a structural finding a
// rename can clear: a symlink, a hard-linked file or the wrong object type.
// A non-local volume or a swap during inspection is left alone.
func darwinStructuralMovable(path string, kind ObjectKind) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	format := uint32(st.Mode) & unix.S_IFMT
	switch {
	case format == unix.S_IFLNK:
		return true
	case kind.Directory():
		return format != unix.S_IFDIR
	case format != unix.S_IFREG:
		return true
	default:
		return st.Nlink > 1
	}
}

func recreateOwnedDirectory(object OwnedObject, opts CanonicalOptions, why string) CanonicalResult {
	result := CanonicalResult{Path: object.Path, Kind: object.Kind, Outcome: CanonicalMissing}
	form, ok := darwinCanonicalFormFor(object.Kind, opts)
	if !ok {
		return result
	}
	if err := unix.Mkdir(object.Path, uint32(form.Mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
		result.RepairError = fmt.Sprintf("recreate directory: %v", err)
		EmitResilienceEvent(MarkerDegraded, map[string]string{
			"path":   object.Path,
			"reason": "could not recreate a DefenseClaw directory (" + why + "): " + err.Error(),
		})
		return result
	}
	stamped, err := EnsureCanonical(object.Path, object.Kind, opts)
	// Only a folder that now has its canonical form counts as repaired; an
	// accepted, boundary or vanished result is reported as what it is.
	if err != nil || (stamped.Outcome != CanonicalOK && stamped.Outcome != CanonicalRepaired) {
		reportCanonicalResult(stamped, CanonicalOptions{})
		return stamped
	}
	stamped.Outcome = CanonicalRepaired
	EmitResilienceEvent(MarkerRepair, map[string]string{
		"path":   object.Path,
		"object": string(object.Kind),
		"reason": "directory recreated (" + why + ")",
	})
	return stamped
}
