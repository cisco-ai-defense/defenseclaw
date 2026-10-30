// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ObjectKind names the canonical security descriptor DefenseClaw stamps on a
// managed Windows object. The kinds and their descriptors match the installer
// module's New-DefenseClawCanonicalPathAcl kinds of the same name; keep the
// two in step.
type ObjectKind string

const (
	// ObjectRuntimeDirectory is a gateway-writable data directory: data_dir,
	// the audit and judge-body directories, the redaction key directory and the
	// gateway log directory. Owner Administrators; SYSTEM and Administrators
	// full control and the gateway service Modify, all inheritable.
	ObjectRuntimeDirectory ObjectKind = "RuntimeDirectory"
	// ObjectRuntimeFile is a gateway-writable data file: the audit and
	// judge-body databases and their SQLite side files, the gateway log.
	ObjectRuntimeFile ObjectKind = "RuntimeFile"
	// ObjectRuntimeSecretFile is the redaction correlation key: owned by the
	// gateway service, OWNER RIGHTS limited to READ_CONTROL, gateway read only.
	ObjectRuntimeSecretFile ObjectKind = "RuntimeSecretFile"
	// ObjectConfigFile is config.yaml: gateway read only.
	ObjectConfigFile ObjectKind = "ConfigFile"
	// ObjectConfigDirectory is the config directory: gateway read and traverse.
	ObjectConfigDirectory ObjectKind = "ConfigDirectory"
	// ObjectInstallDirectory is libexec: Users read and execute, inheritable.
	ObjectInstallDirectory ObjectKind = "InstallDirectory"
	// ObjectInstallFile is an installed file the gateway does not run: the
	// CLI, hook and broker executables, the installer script and module.
	ObjectInstallFile ObjectKind = "InstallFile"
	// ObjectServiceInstallDirectory is InstallRoot and bin: Users and the
	// gateway service read and execute, inheritable.
	ObjectServiceInstallDirectory ObjectKind = "ServiceInstallDirectory"
	// ObjectServiceInstallFile is the gateway executable.
	ObjectServiceInstallFile ObjectKind = "ServiceInstallFile"
	// ObjectStateDirectory is StateRoot: gateway read and traverse.
	ObjectStateDirectory ObjectKind = "StateDirectory"
	// ObjectAdminDirectory is a SYSTEM and Administrators only directory: the
	// guardian and install-state folders, the guardian and broker log folders.
	ObjectAdminDirectory ObjectKind = "AdminDirectory"
	// ObjectAdminFile is a SYSTEM and Administrators only file: targets.yaml,
	// deployment.json and the other install-state records, admin logs.
	ObjectAdminFile ObjectKind = "AdminFile"
	// ObjectAuthorizationDirectory is the broker state folder: gateway read
	// and traverse.
	ObjectAuthorizationDirectory ObjectKind = "AuthorizationDirectory"
	// ObjectLogDirectory is the logs root: SYSTEM and Administrators only.
	ObjectLogDirectory ObjectKind = "LogDirectory"
	// ObjectManagedIPCDirectory is the IPC socket folder: the gateway service
	// full control, Authenticated Users read and traverse, nothing inheritable.
	ObjectManagedIPCDirectory ObjectKind = "ManagedIPCDirectory"
)

// Directory reports whether the kind describes a directory.
func (kind ObjectKind) Directory() bool {
	switch kind {
	case ObjectRuntimeDirectory, ObjectConfigDirectory, ObjectInstallDirectory,
		ObjectServiceInstallDirectory, ObjectStateDirectory, ObjectAdminDirectory,
		ObjectAuthorizationDirectory, ObjectLogDirectory, ObjectManagedIPCDirectory:
		return true
	}
	return false
}

// propagatesRepair reports whether a repair of this directory kind also
// pushes its inheritable entries into existing children. Only the gateway's
// data and config folders do, as they always have; every other folder holds
// children DefenseClaw stamps one by one (or does not own), so only the
// folder's own descriptor is written.
func (kind ObjectKind) propagatesRepair() bool {
	return kind == ObjectRuntimeDirectory || kind == ObjectConfigDirectory
}

// CanonicalOutcome is what EnsureCanonical or AssessCanonical concluded about
// one object.
type CanonicalOutcome string

const (
	// CanonicalOK: the descriptor already has the canonical form; nothing was
	// written and nothing is logged.
	CanonicalOK CanonicalOutcome = "ok"
	// CanonicalRepaired: drift was found and the canonical descriptor was
	// stamped. Logged with MarkerRepair.
	CanonicalRepaired CanonicalOutcome = "repaired"
	// CanonicalAccepted: drift that grants no untrusted principal write
	// authority. Assess left it as it is; Ensure could not repair it. Logged
	// with MarkerAccept.
	CanonicalAccepted CanonicalOutcome = "accepted"
	// CanonicalBoundary: an untrusted principal can write the object, or owns
	// it, and the drift was not (or could not be) repaired. Logged with
	// MarkerBoundary. Callers decide whether to refuse the object.
	CanonicalBoundary CanonicalOutcome = "boundary"
	// CanonicalMissing: the object does not exist. Not logged.
	CanonicalMissing CanonicalOutcome = "missing"
	// CanonicalStructural: a structural failure (reparse point, hard link,
	// wrong type, non-NTFS or remote volume). Returned with an error.
	CanonicalStructural CanonicalOutcome = "structural"
	// CanonicalUnsupported: the platform has no Windows descriptors.
	CanonicalUnsupported CanonicalOutcome = "unsupported"
)

// CanonicalResult is the per-object result of EnsureCanonical and
// AssessCanonical.
type CanonicalResult struct {
	Path    string
	Kind    ObjectKind
	Outcome CanonicalOutcome
	// Drift lists every way the descriptor differed from the canonical form
	// before any repair.
	Drift []string
	// UntrustedWriters lists principals (SIDs) outside the trusted set that
	// held write-like access before any repair.
	UntrustedWriters []string
	// GatewayAccessMissing is set when the gateway service lacked the access
	// this kind requires (write for runtime kinds, read for secret and config
	// kinds). The gateway cannot work with the object until it is repaired.
	GatewayAccessMissing bool
	// RepairError is set when a repair was attempted and failed.
	RepairError string
	// Err is set for structural and API failures.
	Err error
}

// CanonicalOptions tunes EnsureCanonical and AssessCanonical.
type CanonicalOptions struct {
	// GatewayServiceAccount is the gateway's NT SERVICE account. Empty uses
	// WindowsServiceAccountEnv.
	GatewayServiceAccount string
	// AllowUntrustedOwnerTransfer lets a privileged repair take ownership of
	// an object owned by a principal outside the trusted and
	// administrator-equivalent set. Off by default: such an object may have
	// been planted, so it is reported as a boundary instead.
	AllowUntrustedOwnerTransfer bool
	// Quiet suppresses the resilience log line, for callers that log the
	// result themselves.
	Quiet bool
}

// Well-known SID strings the canonical descriptors use.
const (
	sidLocalSystem       = "S-1-5-18"
	sidAdministrators    = "S-1-5-32-544"
	sidUsers             = "S-1-5-32-545"
	sidAuthenticatedUser = "S-1-5-11"
	sidEveryone          = "S-1-1-0"
	sidOwnerRights       = "S-1-3-4"
	sidCreatorOwner      = "S-1-3-0"
	sidTrustedInstaller  = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// Access masks, as .NET FileSystemRights writes them.
const (
	maskFullControl    uint32 = 0x001f01ff
	maskModify         uint32 = 0x001301bf
	maskReadAndExecute uint32 = 0x001200a9
	maskRead           uint32 = 0x00120089
	maskReadControl    uint32 = 0x00020000

	maskGenericAll     uint32 = 0x10000000
	maskGenericExecute uint32 = 0x20000000
	maskGenericWrite   uint32 = 0x40000000
	maskGenericRead    uint32 = 0x80000000
	maskDelete         uint32 = 0x00010000
	maskWriteDAC       uint32 = 0x00040000
	maskWriteOwner     uint32 = 0x00080000
	maskReadData       uint32 = 0x00000001
	maskWriteData      uint32 = 0x00000002
	maskAppendData     uint32 = 0x00000004
	maskWriteEA        uint32 = 0x00000010
	maskDeleteChild    uint32 = 0x00000040
	maskWriteAttrs     uint32 = 0x00000100
	maskReadAttrs      uint32 = 0x00000080
	maskReadEA         uint32 = 0x00000008
	maskExecute        uint32 = 0x00000020
	maskSynchronize    uint32 = 0x00100000
)

// ACE header values.
const (
	aceTypeAllowed               uint8 = 0x0
	aceTypeDenied                uint8 = 0x1
	aceTypeAllowedObject         uint8 = 0x5
	aceTypeAllowedCallback       uint8 = 0x9
	aceTypeAllowedCallbackObject uint8 = 0xb

	aceFlagObjectInherit    uint8 = 0x1
	aceFlagContainerInherit uint8 = 0x2
	aceFlagInheritOnly      uint8 = 0x8
	aceFlagInherited        uint8 = 0x10
)

// descriptorACE is one DACL entry in a platform-neutral form, so the drift
// decision can be unit tested on every platform. SID is empty when the entry's
// layout could not be read (an object ACE).
type descriptorACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   string
}

// objectDescriptor is the owner, protection and DACL of one object.
type objectDescriptor struct {
	Owner string
	// Group is read only where a canonical form pins it (service keys).
	Group     string
	Protected bool
	// NullDACL means the object has no DACL at all: everyone has full access.
	NullDACL bool
	ACEs     []descriptorACE
}

// canonicalACE is one entry of a canonical form.
type canonicalACE struct {
	SID   string
	Mask  uint32
	Flags uint8
}

// canonicalForm is one acceptable exact descriptor for a kind.
type canonicalForm struct {
	Owner string
	ACEs  []canonicalACE
}

// canonicalSpec lists the acceptable forms for a kind; the first is the one a
// repair stamps.
type canonicalSpec struct {
	Forms []canonicalForm
	// GatewayNeedsAccess: the forms name the gateway service, so its entry
	// is required. Kinds the gateway never opens leave it unset.
	GatewayNeedsAccess bool
	// GatewayNeedsWrite: the gateway must hold write access (runtime kinds);
	// otherwise read access.
	GatewayNeedsWrite bool
	// GatewayInherit is the inheritance a gateway write entry must carry to
	// count: object and container inherit for an inheritable runtime folder,
	// none for a file or the IPC folder.
	GatewayInherit uint8
}

// canonicalSpecFor builds the spec for kind with the gateway SID filled in.
// gatewaySID may be empty when the identity cannot be resolved; the spec then
// carries no gateway entry and the gateway access check is skipped. The forms
// mirror the installer module's New-DefenseClawCanonicalPathAcl.
func canonicalSpecFor(kind ObjectKind, gatewaySID string) canonicalSpec {
	inherit := uint8(0)
	if kind.Directory() && kind != ObjectManagedIPCDirectory {
		inherit = aceFlagObjectInherit | aceFlagContainerInherit
	}
	base := []canonicalACE{
		{SID: sidLocalSystem, Mask: maskFullControl, Flags: inherit},
		{SID: sidAdministrators, Mask: maskFullControl, Flags: inherit},
	}
	withGateway := func(mask uint32) []canonicalACE {
		aces := append([]canonicalACE(nil), base...)
		if gatewaySID != "" {
			aces = append(aces, canonicalACE{SID: gatewaySID, Mask: mask, Flags: inherit})
		}
		return aces
	}
	withUsers := func(aces []canonicalACE) []canonicalACE {
		return append(append([]canonicalACE(nil), aces...),
			canonicalACE{SID: sidUsers, Mask: maskReadAndExecute, Flags: inherit})
	}
	gatewayRead := func(aces []canonicalACE) canonicalSpec {
		return canonicalSpec{
			Forms:              []canonicalForm{{Owner: sidAdministrators, ACEs: aces}},
			GatewayNeedsAccess: true,
		}
	}
	switch kind {
	case ObjectRuntimeDirectory:
		return canonicalSpec{
			Forms:              []canonicalForm{{Owner: sidAdministrators, ACEs: withGateway(maskModify)}},
			GatewayNeedsAccess: true,
			GatewayNeedsWrite:  true,
			GatewayInherit:     inherit,
		}
	case ObjectRuntimeFile:
		forms := []canonicalForm{{Owner: sidAdministrators, ACEs: withGateway(maskModify)}}
		if gatewaySID != "" {
			// A file the gateway created itself is owned by its service SID and
			// carries OWNER RIGHTS READ_CONTROL to suppress the owner's
			// implicit WRITE_DAC. That is the gateway's own canonical form, not
			// drift.
			owned := append([]canonicalACE{{SID: sidOwnerRights, Mask: maskReadControl}}, withGateway(maskModify)...)
			forms = append(forms, canonicalForm{Owner: gatewaySID, ACEs: owned})
		}
		return canonicalSpec{Forms: forms, GatewayNeedsAccess: true, GatewayNeedsWrite: true}
	case ObjectRuntimeSecretFile:
		owner := gatewaySID
		if owner == "" {
			owner = sidAdministrators
		}
		aces := append([]canonicalACE{{SID: sidOwnerRights, Mask: maskReadControl}}, withGateway(maskRead)...)
		return canonicalSpec{Forms: []canonicalForm{{Owner: owner, ACEs: aces}}, GatewayNeedsAccess: true}
	case ObjectConfigFile:
		return gatewayRead(withGateway(maskRead))
	case ObjectConfigDirectory, ObjectStateDirectory, ObjectAuthorizationDirectory:
		return gatewayRead(withGateway(maskReadAndExecute))
	case ObjectServiceInstallDirectory, ObjectServiceInstallFile:
		return gatewayRead(withUsers(withGateway(maskReadAndExecute)))
	case ObjectInstallDirectory, ObjectInstallFile:
		return canonicalSpec{Forms: []canonicalForm{{Owner: sidAdministrators, ACEs: withUsers(base)}}}
	case ObjectAdminDirectory, ObjectAdminFile, ObjectLogDirectory:
		return canonicalSpec{Forms: []canonicalForm{{Owner: sidAdministrators, ACEs: base}}}
	case ObjectManagedIPCDirectory:
		aces := append(withGateway(maskFullControl),
			canonicalACE{SID: sidAuthenticatedUser, Mask: maskReadAndExecute})
		forms := []canonicalForm{{Owner: sidAdministrators, ACEs: aces}}
		if gatewaySID != "" {
			// The gateway re-applies its own IPC baseline at every bind, with
			// generic full control for the trusted principals. That shape is
			// equivalent and is not drift.
			forms = append(forms, canonicalForm{Owner: sidAdministrators, ACEs: []canonicalACE{
				{SID: sidLocalSystem, Mask: maskGenericAll},
				{SID: sidAdministrators, Mask: maskGenericAll},
				{SID: gatewaySID, Mask: maskGenericAll},
				{SID: sidAuthenticatedUser, Mask: maskReadAndExecute},
			}})
		}
		return canonicalSpec{Forms: forms, GatewayNeedsAccess: true, GatewayNeedsWrite: true}
	}
	return canonicalSpec{}
}

// canonicalSDDL renders the stamp form of spec as SDDL.
func (spec canonicalSpec) canonicalSDDL() string {
	if len(spec.Forms) == 0 {
		return ""
	}
	form := spec.Forms[0]
	var b strings.Builder
	fmt.Fprintf(&b, "O:%sG:BAD:P", form.Owner)
	for _, ace := range form.ACEs {
		flags := ""
		if ace.Flags&aceFlagObjectInherit != 0 {
			flags += "OI"
		}
		if ace.Flags&aceFlagContainerInherit != 0 {
			flags += "CI"
		}
		fmt.Fprintf(&b, "(A;%s;0x%x;;;%s)", flags, ace.Mask, ace.SID)
	}
	return b.String()
}

// ownerClass sorts an owner SID for the drift decision.
type ownerClass int

const (
	ownerCanonical ownerClass = iota
	// ownerTrusted: SYSTEM, Administrators, TrustedInstaller or the gateway
	// service, but not the canonical owner.
	ownerTrusted
	// ownerAdminEquivalent: an administrator account or a domain admin group.
	ownerAdminEquivalent
	// ownerUntrusted: anyone else. The owner has implicit WRITE_DAC.
	ownerUntrusted
)

// canonicalAssessment is the pure drift decision for one descriptor.
type canonicalAssessment struct {
	Canonical            bool
	Drift                []string
	UntrustedWriters     []string
	Owner                ownerClass
	GatewayAccessMissing bool
}

// boundary reports whether the descriptor lets an untrusted principal write
// the object, directly or through ownership.
func (a canonicalAssessment) boundary() bool {
	return len(a.UntrustedWriters) > 0 || a.Owner == ownerUntrusted
}

// adminEquivalentSID reports whether sid is a well-known administrator
// account or group that is not in the core trusted set: the built-in
// Administrator account (RID 500), Domain Admins (512) and Enterprise Admins
// (519). A Windows build may add local Administrators membership on top.
func adminEquivalentSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	index := strings.LastIndexByte(sid, '-')
	switch sid[index+1:] {
	case "500", "512", "519":
		return true
	}
	return false
}

// coreTrustedSID reports whether sid is SYSTEM, Administrators or
// TrustedInstaller.
func coreTrustedSID(sid string) bool {
	return sid == sidLocalSystem || sid == sidAdministrators || sid == sidTrustedInstaller
}

// writeLikeMask mirrors windowsWriteLikeAccess.
func writeLikeMask(mask uint32) bool {
	const writeLike = maskGenericAll | maskGenericWrite | maskDelete | maskWriteDAC | maskWriteOwner |
		maskWriteData | maskAppendData | maskWriteEA | maskWriteAttrs | maskDeleteChild
	return mask&writeLike != 0
}

// createChildOnlyMask reports a directory grant that adds files or
// subdirectories and reads, but cannot replace, delete or re-ACL an existing
// child: the stock ProgramData "Users create" shape.
func createChildOnlyMask(mask uint32) bool {
	const harmlessDirectoryWrite = maskWriteData | maskAppendData | maskWriteEA | maskWriteAttrs
	const readish = maskReadData | maskReadEA | maskExecute | maskReadAttrs | maskReadControl | maskSynchronize |
		maskGenericRead | maskGenericExecute
	return mask&^(harmlessDirectoryWrite|readish) == 0
}

func grantsWrite(mask uint32) bool {
	return mask&(maskGenericAll|maskGenericWrite|maskWriteData|maskAppendData) != 0
}

func grantsRead(mask uint32) bool {
	return mask&(maskGenericAll|maskGenericRead|maskReadData) != 0
}

// assessCanonicalDescriptor decides how desc differs from kind's canonical
// forms. It judges effective write authority for untrusted principals, not
// exact SDDL equality: extra read entries, inherited trusted entries, deny
// entries, inherit-only CREATOR OWNER, generic-versus-specific rights and a
// TrustedInstaller or administrator owner are drift, never a boundary.
// adminMember, when set, reports local Administrators membership for an owner
// or writer SID that is not otherwise recognised.
func assessCanonicalDescriptor(
	desc objectDescriptor,
	kind ObjectKind,
	gatewaySID string,
	adminMember func(string) bool,
) canonicalAssessment {
	spec := canonicalSpecFor(kind, gatewaySID)
	var a canonicalAssessment
	isAdminEquivalent := func(sid string) bool {
		return adminEquivalentSID(sid) || (adminMember != nil && sid != "" && adminMember(sid))
	}

	// Owner.
	a.Owner = ownerUntrusted
	for _, form := range spec.Forms {
		if desc.Owner == form.Owner {
			a.Owner = ownerCanonical
			break
		}
	}
	if a.Owner != ownerCanonical {
		switch {
		case coreTrustedSID(desc.Owner) || (gatewaySID != "" && desc.Owner == gatewaySID):
			a.Owner = ownerTrusted
			a.Drift = append(a.Drift, fmt.Sprintf("owner %s is not the canonical owner", desc.Owner))
		case isAdminEquivalent(desc.Owner):
			a.Owner = ownerAdminEquivalent
			a.Drift = append(a.Drift, fmt.Sprintf("owner %s is an administrator, not the canonical owner", desc.Owner))
		default:
			a.Drift = append(a.Drift, fmt.Sprintf("owner %s is not trusted", ownerText(desc.Owner)))
		}
	}

	if !desc.Protected {
		a.Drift = append(a.Drift, "DACL inherits from its parent")
	}
	if desc.NullDACL {
		a.Drift = append(a.Drift, "DACL is null")
		// A null DACL grants everyone everything, the gateway included.
		a.UntrustedWriters = append(a.UntrustedWriters, sidEveryone)
		return a
	}

	// Entries.
	gatewayHas := false
	systemHas := false
	for index, ace := range desc.ACEs {
		inheritOnly := ace.Flags&aceFlagInheritOnly != 0
		switch ace.Type {
		case aceTypeAllowed, aceTypeAllowedCallback:
		case aceTypeAllowedObject, aceTypeAllowedCallbackObject:
			// The trustee of an object entry is not read here, so it cannot
			// be proven trusted. A write-like object grant counts as an
			// untrusted writer; a repair removes it.
			if !inheritOnly && writeLikeMask(ace.Mask) {
				a.UntrustedWriters = append(a.UntrustedWriters, fmt.Sprintf("object-ace-%d", index))
			}
			a.Drift = append(a.Drift, fmt.Sprintf("entry %d has object type 0x%x", index, ace.Type))
			continue
		default:
			// Deny and audit entries never widen access.
			if ace.Type == aceTypeDenied {
				a.Drift = append(a.Drift, fmt.Sprintf("deny entry %d for %s", index, ace.SID))
			}
			continue
		}
		if ace.Type == aceTypeAllowedCallback {
			a.Drift = append(a.Drift, fmt.Sprintf("entry %d for %s is conditional", index, ace.SID))
		}
		if inheritOnly {
			if ace.SID != sidCreatorOwner && writeLikeMask(ace.Mask) && !trustedWriterSID(ace.SID, gatewaySID, isAdminEquivalent) {
				a.Drift = append(a.Drift, fmt.Sprintf("inheritable entry %d grants %s write to new children", index, ace.SID))
			}
			continue
		}
		if ace.SID == gatewaySID && gatewaySID != "" {
			if spec.GatewayNeedsWrite {
				if grantsWrite(ace.Mask) && ace.Flags&spec.GatewayInherit == spec.GatewayInherit {
					gatewayHas = true
				}
			} else if grantsRead(ace.Mask) {
				gatewayHas = true
			}
		}
		if ace.SID == sidLocalSystem && grantsWrite(ace.Mask) && grantsRead(ace.Mask) {
			systemHas = true
		}
		if !writeLikeMask(ace.Mask) {
			continue
		}
		if trustedWriterSID(ace.SID, gatewaySID, isAdminEquivalent) {
			continue
		}
		if ace.SID == sidOwnerRights {
			// OWNER RIGHTS write only extends what the owner already holds.
			continue
		}
		if kind.Directory() && ace.Flags&aceFlagInherited != 0 &&
			(ace.SID == sidUsers || ace.SID == sidAuthenticatedUser) && createChildOnlyMask(ace.Mask) {
			a.Drift = append(a.Drift, fmt.Sprintf("inherited create-child entry for %s", ace.SID))
			continue
		}
		a.UntrustedWriters = append(a.UntrustedWriters, ace.SID)
	}
	if !systemHas {
		a.Drift = append(a.Drift, "SYSTEM full access is missing")
	}
	if gatewaySID != "" && spec.GatewayNeedsAccess && !gatewayHas {
		a.GatewayAccessMissing = true
		if spec.GatewayNeedsWrite {
			a.Drift = append(a.Drift, "gateway service write entry is missing")
		} else {
			a.Drift = append(a.Drift, "gateway service read entry is missing")
		}
	}
	for _, sid := range a.UntrustedWriters {
		a.Drift = append(a.Drift, fmt.Sprintf("untrusted principal %s has write access", sid))
	}

	a.Canonical = a.Owner == ownerCanonical && desc.Protected && matchesCanonicalForm(desc, spec)
	if a.Canonical {
		a.Drift = nil
	} else if len(a.Drift) == 0 {
		a.Drift = append(a.Drift, "DACL entries differ from the canonical form")
	}
	return a
}

func trustedWriterSID(sid, gatewaySID string, isAdminEquivalent func(string) bool) bool {
	return coreTrustedSID(sid) || (gatewaySID != "" && sid == gatewaySID) || isAdminEquivalent(sid)
}

// matchesCanonicalForm reports whether desc's explicit entries equal one of
// spec's forms exactly, in any order, with the matching owner.
func matchesCanonicalForm(desc objectDescriptor, spec canonicalSpec) bool {
	for _, form := range spec.Forms {
		if desc.Owner != form.Owner || len(desc.ACEs) != len(form.ACEs) {
			continue
		}
		used := make([]bool, len(form.ACEs))
		matched := true
		for _, ace := range desc.ACEs {
			if ace.Type != aceTypeAllowed {
				matched = false
				break
			}
			found := false
			for index, want := range form.ACEs {
				if !used[index] && ace.SID == want.SID && ace.Mask == want.Mask && ace.Flags == want.Flags {
					used[index] = true
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func ownerText(owner string) string {
	if owner == "" {
		return "<none>"
	}
	return owner
}

// outcome turns an assessment into the outcome before any repair.
func (a canonicalAssessment) outcome() CanonicalOutcome {
	switch {
	case a.Canonical:
		return CanonicalOK
	case a.boundary():
		return CanonicalBoundary
	default:
		return CanonicalAccepted
	}
}

// reportCanonicalResult logs a non-trivial result once with the matching
// resilience marker. Accepted and boundary lines are deduplicated per process
// so a guardian tick does not repeat them; a repair is always logged because
// it only happens when drift came back.
func reportCanonicalResult(result CanonicalResult, opts CanonicalOptions) {
	if opts.Quiet {
		return
	}
	var marker string
	switch result.Outcome {
	case CanonicalRepaired:
		marker = MarkerRepair
	case CanonicalAccepted:
		marker = MarkerAccept
	case CanonicalBoundary:
		marker = MarkerBoundary
	case CanonicalStructural:
		marker = MarkerBoundary
	default:
		return
	}
	fields := map[string]string{
		"path":   result.Path,
		"object": string(result.Kind),
		"reason": strings.Join(result.Drift, "; "),
	}
	if result.Outcome == CanonicalStructural && result.Err != nil {
		fields["reason"] = result.Err.Error()
	}
	if result.RepairError != "" {
		fields["repair_error"] = result.RepairError
	}
	if len(result.UntrustedWriters) > 0 {
		fields["principal"] = strings.Join(result.UntrustedWriters, ",")
	}
	if result.GatewayAccessMissing {
		fields["gateway_access"] = "missing"
	}
	if marker != MarkerRepair {
		if !advisoryLogDedupe.shouldEmit(result.Path, marker, FormatResilienceEvent(marker, fields)) {
			return
		}
	}
	EmitResilienceEvent(marker, fields)
}

// ManagedDataPaths names the gateway's managed data objects for
// RepairWindowsManagedDataPaths and AssessWindowsManagedDataPaths. Empty
// fields are skipped. Paths that do not exist are reported as
// CanonicalMissing and are not created.
type ManagedDataPaths struct {
	// DataDir is the managed data_dir.
	DataDir string
	// AuditDBPath is audit.db. Its directory and the SQLite side files
	// (-wal, -shm, -journal) are covered too.
	AuditDBPath string
	// JudgeBodyDBPath is the judge-body store database. Its directory and
	// SQLite side files are covered too.
	JudgeBodyDBPath string
	// RedactionKeyPath is the redaction correlation key. Its directory is
	// covered too.
	RedactionKeyPath string
	// LogPaths are gateway log files. Their directories are covered too.
	LogPaths []string
	// RuntimeDirs are further gateway-writable directories below DataDir,
	// such as the hooks directory.
	RuntimeDirs []string
}

// sqliteSideFileSuffixes are the SQLite side files repaired with each
// database.
var sqliteSideFileSuffixes = []string{"-wal", "-shm", "-journal"}

type managedDataTarget struct {
	path string
	kind ObjectKind
}

// targets expands paths into the ordered, de-duplicated object list:
// directories first, parents before children, then files.
func (paths ManagedDataPaths) targets() []managedDataTarget {
	var dirs, files []managedDataTarget
	seen := map[string]bool{}
	key := func(path string) string { return strings.ToLower(filepath.Clean(path)) }
	addDir := func(path string) {
		if strings.TrimSpace(path) == "" || seen[key(path)] {
			return
		}
		seen[key(path)] = true
		dirs = append(dirs, managedDataTarget{path: filepath.Clean(path), kind: ObjectRuntimeDirectory})
	}
	addFile := func(path string, kind ObjectKind) {
		if strings.TrimSpace(path) == "" || seen[key(path)] {
			return
		}
		seen[key(path)] = true
		files = append(files, managedDataTarget{path: filepath.Clean(path), kind: kind})
	}
	addDir(paths.DataDir)
	for _, dir := range paths.RuntimeDirs {
		addDir(dir)
	}
	for _, db := range []string{paths.AuditDBPath, paths.JudgeBodyDBPath} {
		if strings.TrimSpace(db) == "" {
			continue
		}
		addDir(filepath.Dir(db))
		addFile(db, ObjectRuntimeFile)
		for _, suffix := range sqliteSideFileSuffixes {
			addFile(db+suffix, ObjectRuntimeFile)
		}
	}
	if strings.TrimSpace(paths.RedactionKeyPath) != "" {
		addDir(filepath.Dir(paths.RedactionKeyPath))
		addFile(paths.RedactionKeyPath, ObjectRuntimeSecretFile)
	}
	for _, logPath := range paths.LogPaths {
		if strings.TrimSpace(logPath) == "" {
			continue
		}
		addDir(filepath.Dir(logPath))
		addFile(logPath, ObjectRuntimeFile)
	}
	// Parents before children.
	sort.SliceStable(dirs, func(i, j int) bool {
		return strings.Count(dirs[i].path, string(filepath.Separator)) <
			strings.Count(dirs[j].path, string(filepath.Separator))
	})
	return append(dirs, files...)
}

// RepairWindowsManagedDataPaths runs EnsureCanonical over every managed data
// object in paths and returns one result per object, in the order handled.
// One object's failure never stops the others. Only a privileged component
// (the hook guardian, the CMID broker, the installer) may call it; inside the
// gateway service it degrades to AssessWindowsManagedDataPaths. On other
// platforms every result is CanonicalUnsupported.
func RepairWindowsManagedDataPaths(paths ManagedDataPaths, opts CanonicalOptions) []CanonicalResult {
	targets := paths.targets()
	results := make([]CanonicalResult, 0, len(targets))
	for _, target := range targets {
		result, _ := EnsureCanonical(target.path, target.kind, opts)
		results = append(results, result)
	}
	return results
}

// AssessWindowsManagedDataPaths is the read-only counterpart for the gateway:
// it writes nothing, logs each drift once as accepted (or boundary when an
// untrusted principal can write), and returns the per-object results.
func AssessWindowsManagedDataPaths(paths ManagedDataPaths, opts CanonicalOptions) []CanonicalResult {
	targets := paths.targets()
	results := make([]CanonicalResult, 0, len(targets))
	for _, target := range targets {
		result, _ := AssessCanonical(target.path, target.kind, opts)
		results = append(results, result)
	}
	return results
}
