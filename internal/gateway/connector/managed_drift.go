// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The descriptor model below is the platform-neutral half of the Windows
// drift handling for managed connector files: Windows code converts a live
// security descriptor into a managedDescriptor, and every decision about
// whether the object is canonical, harmless drift, or an untrusted writer is
// made here so it can be unit tested on every platform. Decisions are based on
// effective write authority for untrusted principals, never on exact SDDL
// equality: extra read entries, inherited entries, OWNER RIGHTS, inherit-only
// CREATOR OWNER and a TrustedInstaller or Administrators owner are harmless.
const (
	managedSIDAdministrators   = "S-1-5-32-544"
	managedSIDUsers            = "S-1-5-32-545"
	managedSIDLocalSystem      = "S-1-5-18"
	managedSIDTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	managedSIDOwnerRights      = "S-1-3-4"
	managedSIDCreatorOwner     = "S-1-3-0"
	managedSIDEveryone         = "S-1-1-0"

	managedACETypeAllowed = 0x0
	managedACETypeDenied  = 0x1

	managedACEFlagObjectInherit    = 0x01
	managedACEFlagContainerInherit = 0x02
	managedACEFlagInheritOnly      = 0x08
	managedACEFlagInherited        = 0x10

	managedFileAllAccess     uint32 = 0x001F01FF
	managedFileGenericRead   uint32 = 0x00120089
	managedFileGenericWrite  uint32 = 0x00120116
	managedFileGenericExec   uint32 = 0x001200A0
	managedGenericAll        uint32 = 0x10000000
	managedGenericExecute    uint32 = 0x20000000
	managedGenericWrite      uint32 = 0x40000000
	managedGenericRead       uint32 = 0x80000000
	managedFileWriteData     uint32 = 0x00000002
	managedFileAppendData    uint32 = 0x00000004
	managedFileWriteEA       uint32 = 0x00000010
	managedFileDeleteChild   uint32 = 0x00000040
	managedFileWriteAttrs    uint32 = 0x00000100
	managedDelete            uint32 = 0x00010000
	managedWriteDAC          uint32 = 0x00040000
	managedWriteOwner        uint32 = 0x00080000
	managedFileAttrReadOnly  uint32 = 0x00000001
	managedFileAttrHidden    uint32 = 0x00000002
	managedFileAttrSystem    uint32 = 0x00000004
	managedFileAttrDirectory uint32 = 0x00000010
	managedFileAttrReparse   uint32 = 0x00000400
)

// managedACE is one discretionary ACE in string-SID form.
type managedACE struct {
	SID   string
	Type  uint8
	Flags uint8
	Mask  uint32
}

// managedDescriptor is the owner, protection flag and DACL of one object.
type managedDescriptor struct {
	Owner     string
	Protected bool
	NullDACL  bool
	ACEs      []managedACE
}

// managedDrift is the verdict on one live descriptor against its canonical
// form.
type managedDrift struct {
	// Canonical: owner, protection and the effective entries match exactly.
	Canonical bool
	// OwnerDrift: the owner is not the canonical owner.
	OwnerDrift bool
	// UntrustedOwner: the owner is neither canonical nor a trusted
	// administrator principal. An untrusted owner can rewrite the DACL.
	UntrustedOwner bool
	// Unprotected: the DACL inherits from the parent.
	Unprotected bool
	// Inherited: at least one effective entry is inherited.
	Inherited bool
	// Extra: entries beyond the canonical set that grant no untrusted write.
	Extra bool
	// Missing: a canonical entry is absent or narrower than canonical.
	Missing bool
	// UntrustedWriters lists principals outside the trusted set that hold
	// write-like rights on the object.
	UntrustedWriters []string
}

// Boundary reports whether an untrusted principal can change the object.
func (d managedDrift) Boundary() bool {
	return d.UntrustedOwner || len(d.UntrustedWriters) > 0
}

// Reason renders the drift for a resilience log line.
func (d managedDrift) Reason() string {
	if d.Canonical {
		return "canonical"
	}
	parts := make([]string, 0, 7)
	if d.UntrustedOwner {
		parts = append(parts, "untrusted owner")
	} else if d.OwnerDrift {
		parts = append(parts, "owner drift")
	}
	if len(d.UntrustedWriters) > 0 {
		parts = append(parts, "untrusted writer "+strings.Join(d.UntrustedWriters, ","))
	}
	if d.Unprotected {
		parts = append(parts, "inheritable DACL")
	}
	if d.Inherited {
		parts = append(parts, "inherited entries")
	}
	if d.Extra {
		parts = append(parts, "extra entries")
	}
	if d.Missing {
		parts = append(parts, "missing entries")
	}
	if len(parts) == 0 {
		parts = append(parts, "noncanonical entries")
	}
	return strings.Join(parts, "; ")
}

// managedDriftPolicy says who may hold write rights on an object without that
// being a boundary finding. Administrators, LocalSystem and TrustedInstaller
// are always trusted; extraTrusted adds the target user or a pinned service.
type managedDriftPolicy struct {
	Canonical    managedDescriptor
	ExtraTrusted []string
}

func managedTrustedAdminSID(sid string) bool {
	switch strings.ToUpper(strings.TrimSpace(sid)) {
	case managedSIDAdministrators, managedSIDLocalSystem, managedSIDTrustedInstaller:
		return true
	}
	return false
}

func (policy managedDriftPolicy) trustedWriter(sid string) bool {
	if managedTrustedAdminSID(sid) || strings.EqualFold(sid, managedSIDOwnerRights) {
		return true
	}
	for _, trusted := range policy.ExtraTrusted {
		if trusted != "" && strings.EqualFold(sid, trusted) {
			return true
		}
	}
	return false
}

// normalizeManagedFileMask maps generic rights onto the NTFS file rights they
// grant, so GENERIC_ALL and FILE_ALL_ACCESS compare equal.
func normalizeManagedFileMask(mask uint32) uint32 {
	normalized := mask &^ (managedGenericAll | managedGenericRead | managedGenericWrite | managedGenericExecute)
	if mask&managedGenericAll != 0 {
		normalized |= managedFileAllAccess
	}
	if mask&managedGenericRead != 0 {
		normalized |= managedFileGenericRead
	}
	if mask&managedGenericWrite != 0 {
		normalized |= managedFileGenericWrite
	}
	if mask&managedGenericExecute != 0 {
		normalized |= managedFileGenericExec
	}
	return normalized
}

// managedWriteLikeMask reports whether mask lets a principal change the
// object's data, attributes, DACL, owner or name.
func managedWriteLikeMask(mask uint32) bool {
	writeLike := managedFileWriteData | managedFileAppendData | managedFileWriteEA |
		managedFileDeleteChild | managedFileWriteAttrs | managedDelete |
		managedWriteDAC | managedWriteOwner
	return normalizeManagedFileMask(mask)&writeLike != 0
}

// effectiveManagedACE reports whether the ACE applies to the object itself.
// Inherit-only entries only shape children; a CREATOR OWNER entry on the
// object is a template that matches no token.
func effectiveManagedACE(ace managedACE) bool {
	if ace.Flags&managedACEFlagInheritOnly != 0 {
		return false
	}
	return !strings.EqualFold(ace.SID, managedSIDCreatorOwner)
}

// classifyManagedDrift compares a live descriptor with policy.Canonical.
// Only allow and deny entries are understood; any other entry type makes the
// descriptor noncanonical but is never counted as a writer here, because the
// Windows caller rejects types it cannot parse before classifying.
func classifyManagedDrift(actual managedDescriptor, policy managedDriftPolicy) managedDrift {
	var drift managedDrift
	want := policy.Canonical
	if !strings.EqualFold(actual.Owner, want.Owner) {
		drift.OwnerDrift = true
		if !policy.trustedWriter(actual.Owner) {
			drift.UntrustedOwner = true
		}
	}
	if want.Protected && !actual.Protected {
		drift.Unprotected = true
	}
	if actual.NullDACL {
		drift.UntrustedWriters = append(drift.UntrustedWriters, managedSIDEveryone)
		drift.Missing = len(want.ACEs) > 0
		return drift
	}

	type key struct {
		sid  string
		mask uint32
	}
	wanted := map[key]int{}
	for _, ace := range want.ACEs {
		wanted[key{strings.ToUpper(ace.SID), normalizeManagedFileMask(ace.Mask)}]++
	}
	writers := map[string]struct{}{}
	for _, ace := range actual.ACEs {
		if ace.Flags&managedACEFlagInherited != 0 {
			drift.Inherited = true
		}
		if !effectiveManagedACE(ace) {
			drift.Extra = true
			continue
		}
		mask := normalizeManagedFileMask(ace.Mask)
		switch ace.Type {
		case managedACETypeAllowed:
			k := key{strings.ToUpper(ace.SID), mask}
			if wanted[k] > 0 && ace.Flags&managedACEFlagInherited == 0 {
				wanted[k]--
				continue
			}
			drift.Extra = true
			if managedWriteLikeMask(mask) && !policy.trustedWriter(ace.SID) {
				writers[strings.ToUpper(ace.SID)] = struct{}{}
			}
		case managedACETypeDenied:
			// A deny entry only narrows access. It is drift, never a writer.
			drift.Extra = true
		default:
			drift.Extra = true
		}
	}
	for _, remaining := range wanted {
		if remaining > 0 {
			drift.Missing = true
			break
		}
	}
	for sid := range writers {
		drift.UntrustedWriters = append(drift.UntrustedWriters, sid)
	}
	sort.Strings(drift.UntrustedWriters)
	drift.Canonical = !drift.OwnerDrift && !drift.Unprotected && !drift.Inherited &&
		!drift.Extra && !drift.Missing && len(drift.UntrustedWriters) == 0
	return drift
}

// managedDriftAction is what a caller does with a noncanonical object.
type managedDriftAction int

const (
	// managedDriftNone: the object is canonical.
	managedDriftNone managedDriftAction = iota
	// managedDriftRepair: a privileged caller re-stamps the canonical form.
	managedDriftRepair
	// managedDriftAccept: the caller cannot repair; the drift is tolerated and
	// logged.
	managedDriftAccept
)

// decideManagedDrift applies the repair authority rule: only a privileged
// caller (the installer or the LocalSystem guardian) repairs; a user-token
// caller accepts and logs whatever it cannot repair.
func decideManagedDrift(drift managedDrift, privileged bool) managedDriftAction {
	if drift.Canonical {
		return managedDriftNone
	}
	if privileged {
		return managedDriftRepair
	}
	return managedDriftAccept
}

// managedDriftMarker picks the resilience marker for a drift outcome. An
// untrusted writer on policy or code is a boundary finding even when it was
// repaired, so DART triage sees it; everything else is a repair or an accept.
func managedDriftMarker(drift managedDrift, repaired, policyOrCode bool) string {
	if policyOrCode && drift.Boundary() {
		return managed.MarkerBoundary
	}
	if repaired {
		return managed.MarkerRepair
	}
	return managed.MarkerAccept
}

// managedReadOnlyPlan reports which attribute bits must be cleared so a
// replace or write can proceed, and which to put back afterwards. Only
// ReadOnly blocks writes and replacement; Hidden, System and Archive are left
// alone, and ReplaceFileW carries them across on its own.
func managedReadOnlyPlan(attributes uint32) (clear, restore uint32) {
	if attributes&(managedFileAttrDirectory|managedFileAttrReparse) != 0 {
		return 0, 0
	}
	if attributes&managedFileAttrReadOnly == 0 {
		return 0, 0
	}
	return managedFileAttrReadOnly, managedFileAttrReadOnly
}

// managedTransientRetry is a bounded backoff for sharing and lock violations
// held by an editor, indexer or AV scanner. Access-denied is never transient.
type managedTransientRetry struct {
	Attempts int
	Initial  time.Duration
	Max      time.Duration
}

var defaultManagedTransientRetry = managedTransientRetry{
	Attempts: 8,
	Initial:  25 * time.Millisecond,
	Max:      800 * time.Millisecond,
}

// delay returns the wait before retry number attempt (zero based).
func (r managedTransientRetry) delay(attempt int) time.Duration {
	d := r.Initial
	for i := 0; i < attempt && d < r.Max; i++ {
		d *= 2
	}
	if d > r.Max {
		d = r.Max
	}
	return d
}

// run calls fn until it succeeds, returns a non-transient error, or the
// attempt budget is spent.
func (r managedTransientRetry) run(
	fn func() error,
	transient func(error) bool,
	sleep func(time.Duration),
) error {
	attempts := r.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		err = fn()
		if err == nil || !transient(err) || attempt+1 == attempts {
			return err
		}
		sleep(r.delay(attempt))
	}
	return err
}

// emitManagedResilience logs one resilience event for a managed connector
// object. Accepts are reported once per process for the same path and reason
// so a long-running guardian or a hot hook path does not repeat the line on
// every pass; repairs and boundary findings are actions and always logged.
// emitManagedRepairResilience logs a completed repair. The re-stamp itself is
// always a MarkerRepair line, so every repair is visible under one marker; an
// untrusted writer on policy or code is additionally reported as a boundary
// finding first, as managedDriftMarker decides.
func emitManagedRepairResilience(drift managedDrift, policyOrCode bool, path, reason string, extra map[string]string) {
	if marker := managedDriftMarker(drift, true, policyOrCode); marker != managed.MarkerRepair {
		emitManagedResilience(marker, path, reason, extra)
	}
	emitManagedResilience(managed.MarkerRepair, path, reason, extra)
}

func emitManagedResilience(marker, path, reason string, extra map[string]string) {
	if marker == managed.MarkerAccept && !managedAcceptDedupe.first(path, reason) {
		return
	}
	fields := map[string]string{"path": path, "reason": reason}
	for key, value := range extra {
		fields[key] = value
	}
	managed.EmitResilienceEvent(marker, fields)
}

type managedResilienceDedupe struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

var managedAcceptDedupe = &managedResilienceDedupe{}

func (d *managedResilienceDedupe) first(path, reason string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]struct{}{}
	}
	key := strings.ToLower(path) + "\x00" + reason
	if _, ok := d.seen[key]; ok {
		return false
	}
	if len(d.seen) >= 4096 {
		d.seen = map[string]struct{}{}
	}
	d.seen[key] = struct{}{}
	return true
}

// managedPinMismatch reports an advisory content-hash pin mismatch. Pins never
// fail an action on their own: the mismatch is logged with both hashes and a
// privileged reconcile refreshes the pin.
func managedPinMismatch(path, pin, pinned, live string) {
	emitManagedResilience(
		managed.MarkerAccept,
		path,
		fmt.Sprintf("%s pin differs from live content", pin),
		map[string]string{"pinned_sha256": pinned, "live_sha256": live},
	)
}

const managedReadControl uint32 = 0x00020000

// managedTargetRuntimeCanonicalModel is the canonical descriptor of a
// per-user managed runtime file (locks, the hook contract, shared hook
// scripts, scoped tokens): owned by the target, protected, OWNER RIGHTS
// limited to READ_CONTROL, the target read/write/execute/delete, and full
// control for LocalSystem and Administrators.
func managedTargetRuntimeCanonicalModel(target string) managedDescriptor {
	return managedDescriptor{
		Owner:     target,
		Protected: true,
		ACEs: []managedACE{
			{SID: managedSIDOwnerRights, Mask: managedReadControl},
			{SID: target, Mask: managedFileGenericRead | managedFileGenericWrite | managedFileGenericExec | managedDelete},
			{SID: managedSIDLocalSystem, Mask: managedFileAllAccess},
			{SID: managedSIDAdministrators, Mask: managedFileAllAccess},
		},
	}
}

// managedPrivateCanonicalModel is the private per-user descriptor used for
// configuration transaction state: owned by the user, protected, full control
// for LocalSystem and the user only.
func managedPrivateCanonicalModel(user string) managedDescriptor {
	return managedDescriptor{
		Owner:     user,
		Protected: true,
		ACEs: []managedACE{
			{SID: managedSIDLocalSystem, Mask: managedFileAllAccess},
			{SID: user, Mask: managedFileAllAccess},
		},
	}
}

// managedDriftError marks a validation failure that is permission drift
// (owner, DACL entries, inheritance, protection) rather than structure.
type managedDriftError struct{ err error }

func (e managedDriftError) Error() string { return e.err.Error() }
func (e managedDriftError) Unwrap() error { return e.err }

func managedPermissionDrift(format string, args ...any) error {
	return managedDriftError{err: fmt.Errorf(format, args...)}
}

func isManagedPermissionDrift(err error) bool {
	var drift managedDriftError
	return errors.As(err, &drift)
}

// IsManagedPermissionDrift reports whether err from a managed connector file
// read (a hook API token, an OTLP path token, a managed lock) is permission
// drift rather than a structural failure or a missing file. A reader that
// cannot repair, such as the gateway, keeps using its last good value on
// drift and leaves the repair to the installer or the LocalSystem guardian.
func IsManagedPermissionDrift(err error) bool {
	return isManagedPermissionDrift(err)
}
