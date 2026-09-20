// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import "sort"

// TraceProjectionContract is a detached read-only view of the generated span
// builder contract. Destination compatibility projectors use it to preserve
// every registered field while rejecting handwritten vocabulary drift.
type TraceProjectionContract struct {
	AttributeKeys         []string
	EventAttributeKeys    map[string][]string
	LinkRelations         []string
	LinkAttributeKeys     []string
	ResourceAttributeKeys []string
	ScopeAttributeKeys    []string
}

// RegisteredTraceProjectionContract returns generated structural vocabulary
// for one exact trace identity. It exposes names only, never descriptors,
// constraints, field classes, values, or a construction capability.
func RegisteredTraceProjectionContract(identity EventIdentity) (TraceProjectionContract, bool) {
	if identity.Signal != SignalTraces {
		return TraceProjectionContract{}, false
	}
	for _, candidate := range generatedFamilyIdentityDescriptors() {
		if candidate.Identity != identity {
			continue
		}
		generated, ok := candidate.Descriptor.(generatedTraceFamilyContract)
		if !ok {
			return TraceProjectionContract{}, false
		}
		contract := generated.familyTraceContract()
		result := TraceProjectionContract{
			AttributeKeys:         descriptorKeys(contract.fields),
			EventAttributeKeys:    make(map[string][]string, len(contract.allowedEvents)),
			LinkRelations:         append([]string(nil), contract.allowedLinks...),
			LinkAttributeKeys:     descriptorKeys(contract.linkFields),
			ResourceAttributeKeys: descriptorKeys(contract.resourceFields),
			ScopeAttributeKeys:    descriptorKeys(contract.scopeFields),
		}
		for _, event := range contract.allowedEvents {
			result.EventAttributeKeys[event.name] = descriptorKeys(event.fields)
		}
		sort.Strings(result.LinkRelations)
		return result, true
	}
	return TraceProjectionContract{}, false
}

func descriptorKeys(descriptors []familyFieldDescriptor) []string {
	keys := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		keys = append(keys, descriptor.key)
	}
	sort.Strings(keys)
	return keys
}
