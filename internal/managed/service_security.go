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
	"regexp"
	"strings"
)

// Service and registry access masks used by the canonical forms.
const (
	maskServiceAll          uint32 = 0x000f01ff // CCDCLCSWRPWPDTLOCRSDRCWDWO
	maskServiceUserQuery    uint32 = 0x0002008d // CCLCSWLORC
	maskServiceChangeConfig uint32 = 0x00000002
	maskKeyAll              uint32 = 0x000f003f // KA
	maskKeyRead             uint32 = 0x00020019 // KR
	maskKeySetValue         uint32 = 0x00000002
	maskKeyCreateSubKey     uint32 = 0x00000004
)

// managedServiceDACLForm is managedServiceSDDL as a canonical form. The SCM
// descriptor is compared on its DACL only, so the form carries no owner.
func managedServiceDACLForm() canonicalForm {
	return canonicalForm{ACEs: []canonicalACE{
		{SID: sidLocalSystem, Mask: maskServiceAll},
		{SID: sidAdministrators, Mask: maskServiceAll},
		{SID: sidUsers, Mask: maskServiceUserQuery},
	}}
}

// managedServiceRegistryForm is managedServiceRegistrySDDL as a canonical
// form; the group must also be Administrators.
func managedServiceRegistryForm() canonicalForm {
	return canonicalForm{Owner: sidAdministrators, ACEs: []canonicalACE{
		{SID: sidLocalSystem, Mask: maskKeyAll, Flags: aceFlagContainerInherit},
		{SID: sidAdministrators, Mask: maskKeyAll, Flags: aceFlagContainerInherit},
		{SID: sidUsers, Mask: maskKeyRead, Flags: aceFlagContainerInherit},
	}}
}

// exactDescriptorMatch reports whether desc is protected, has a DACL, and
// carries exactly form's owner and allow entries, in any order. It is the
// strict equality the installer applies to the service descriptors.
func exactDescriptorMatch(desc objectDescriptor, form canonicalForm) bool {
	if !desc.Protected || desc.NullDACL {
		return false
	}
	return matchesCanonicalForm(desc, canonicalSpec{Forms: []canonicalForm{form}})
}

// descriptorUntrustedWriters lists the principals outside SYSTEM,
// Administrators and TrustedInstaller that an allow entry gives any of
// writeMask (or generic write or all), plus an untrusted owner. Inherit-only
// entries do not apply to the object and are skipped.
func descriptorUntrustedWriters(desc objectDescriptor, writeMask uint32) []string {
	var writers []string
	if desc.Owner != "" && !coreTrustedSID(desc.Owner) {
		writers = append(writers, "owner "+desc.Owner)
	}
	if desc.NullDACL {
		return append(writers, sidEveryone)
	}
	writeMask |= maskGenericAll | maskGenericWrite
	for index, ace := range desc.ACEs {
		if ace.Flags&aceFlagInheritOnly != 0 || ace.Mask&writeMask == 0 {
			continue
		}
		switch ace.Type {
		case aceTypeAllowed, aceTypeAllowedCallback:
			if !coreTrustedSID(ace.SID) {
				writers = append(writers, ace.SID)
			}
		case aceTypeAllowedObject, aceTypeAllowedCallbackObject:
			writers = append(writers, fmt.Sprintf("object-ace-%d", index))
		}
	}
	return writers
}

// serviceDescriptorWriteMask is what lets a principal reconfigure, re-ACL,
// take or delete a service: SERVICE_CHANGE_CONFIG, DELETE, WRITE_DAC and
// WRITE_OWNER.
const serviceDescriptorWriteMask = maskServiceChangeConfig | maskDelete | maskWriteDAC | maskWriteOwner

// registryKeyWriteMask is what lets a principal change a service key's
// values (ImagePath runs as LocalSystem), add subkeys, delete or re-ACL it.
const registryKeyWriteMask = maskKeySetValue | maskKeyCreateSubKey | maskDelete | maskWriteDAC | maskWriteOwner

var (
	managedServiceCertGateway  = regexp.MustCompile(`^DefenseClawCertGateway_([a-f0-9]{10})$`)
	managedServiceCertGuardian = regexp.MustCompile(`^DefenseClawCertGuardian_([a-f0-9]{10})$`)
)

// ManagedServiceNames returns the four managed service names derived from the
// gateway and guardian names, as the installer derives them: the credential
// broker from the gateway and the enumerator from the guardian. A name that
// is neither the production name nor a certification-scoped one is dropped,
// with the service derived from it, so an unexpected environment value never
// names a service DefenseClaw does not own.
func ManagedServiceNames(gatewayService, guardianService string) []string {
	var names []string
	gatewayService = strings.TrimSpace(gatewayService)
	guardianService = strings.TrimSpace(guardianService)
	switch {
	case gatewayService == "DefenseClawGateway":
		names = append(names, gatewayService, "DefenseClawCMIDBroker")
	case managedServiceCertGateway.MatchString(gatewayService):
		suffix := managedServiceCertGateway.FindStringSubmatch(gatewayService)[1]
		names = append(names, gatewayService, "DefenseClawCMIDBroker_"+suffix)
	}
	switch {
	case guardianService == "DefenseClawHookGuardian":
		names = append(names, guardianService, "DefenseClawHookEnumerator")
	case managedServiceCertGuardian.MatchString(guardianService):
		suffix := managedServiceCertGuardian.FindStringSubmatch(guardianService)[1]
		names = append(names, guardianService, "DefenseClawCertEnumerator_"+suffix)
	}
	return names
}

// ServiceSecurityResult is the outcome for one service object: its SCM
// descriptor ("scm") or its service registry key ("registry").
type ServiceSecurityResult struct {
	Service string
	Object  string
	Outcome CanonicalOutcome
	// Drift describes the descriptor before any repair.
	Drift string
	// RepairError is set when a repair was attempted and did not hold.
	RepairError string
	Err         error
}

// reportServiceSecurityResult logs a non-trivial result once with the
// matching resilience marker. Accepted and boundary lines are deduplicated per
// process so a guardian tick does not repeat them; a repair is always logged
// because it only happens when drift came back.
func reportServiceSecurityResult(result ServiceSecurityResult) {
	var marker string
	switch result.Outcome {
	case CanonicalRepaired:
		marker = MarkerRepair
	case CanonicalAccepted:
		marker = MarkerAccept
	case CanonicalBoundary:
		marker = MarkerBoundary
	default:
		return
	}
	fields := map[string]string{
		"service": result.Service,
		"object":  result.Object,
		"reason":  result.Drift,
	}
	if result.RepairError != "" {
		fields["repair_error"] = result.RepairError
	}
	if marker != MarkerRepair {
		key := "service:" + result.Service + ":" + result.Object
		if !advisoryLogDedupe.shouldEmit(key, marker, FormatResilienceEvent(marker, fields)) {
			return
		}
	}
	EmitResilienceEvent(marker, fields)
}
