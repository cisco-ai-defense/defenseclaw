// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package observability

import "sort"

var registeredEventNameSet, registeredEventNameOrder, registeredLogEventNameSet,
	registeredTraceEventNameSet, registeredMetricEventNameSet, registeredEventIdentitySet = buildEventNameRegistry()

// buildEventNameRegistry derives the runtime routing vocabulary from the sole
// generated family catalog. The generated producer catalog contributes only
// explicitly compatibility-only log identities; it cannot redefine a family
// identity or create a second canonical authority.
func buildEventNameRegistry() (
	map[EventName]struct{},
	[]EventName,
	map[EventName]struct{},
	map[EventName]struct{},
	map[EventName]struct{},
	map[EventIdentity]struct{},
) {
	type signalNameKey struct {
		signal Signal
		name   EventName
	}
	families := generatedFamilyIdentityDescriptors()
	registered := make(map[EventName]struct{}, len(families))
	logs := make(map[EventName]struct{}, len(families))
	traces := make(map[EventName]struct{}, len(families))
	metrics := make(map[EventName]struct{}, len(families))
	identities := make(map[EventIdentity]struct{}, len(families))
	canonicalIdentities := make(map[EventIdentity]struct{}, len(families))
	compatibilityIdentities := make(map[EventIdentity]struct{})
	familyIdentities := make(map[string]EventIdentity, len(families))
	signalNameOwners := make(map[signalNameKey]Bucket, len(families))

	signalNames := func(signal Signal) map[EventName]struct{} {
		switch signal {
		case SignalLogs:
			return logs
		case SignalTraces:
			return traces
		case SignalMetrics:
			return metrics
		default:
			panic("generated observability family has an unknown signal")
		}
	}
	addIdentity := func(identity EventIdentity) {
		if !IsBucket(identity.Bucket) || !IsSignal(identity.Signal) {
			panic("generated observability family has an unknown bucket or signal")
		}
		if err := identity.Name.Validate(); err != nil {
			panic("invalid generated observability event name: " + err.Error())
		}
		registered[identity.Name] = struct{}{}
		signalNames(identity.Signal)[identity.Name] = struct{}{}
		identities[identity] = struct{}{}
	}

	for _, family := range families {
		if family.FamilyID == "" || family.Descriptor == nil {
			panic("generated observability family identity is incomplete")
		}
		if _, duplicate := familyIdentities[family.FamilyID]; duplicate {
			panic("duplicate generated observability family ID")
		}
		if _, duplicate := identities[family.Identity]; duplicate {
			panic("duplicate generated observability family identity")
		}
		contract := family.Descriptor.familyDescriptorContract()
		if contract.id != family.FamilyID || contract.identity != family.Identity {
			panic("generated observability family identity disagrees with its descriptor")
		}
		signalName := signalNameKey{signal: family.Identity.Signal, name: family.Identity.Name}
		if owner, exists := signalNameOwners[signalName]; exists && owner != family.Identity.Bucket {
			panic("generated observability family name has conflicting bucket owners")
		}
		familyIdentities[family.FamilyID] = family.Identity
		canonicalIdentities[family.Identity] = struct{}{}
		signalNameOwners[signalName] = family.Identity.Bucket
		addIdentity(family.Identity)
	}

	for _, producer := range generatedProducerGroups {
		for _, producerIdentity := range generatedProducerGroupIdentities(producer) {
			identity := EventIdentity{
				Bucket: producerIdentity.Bucket,
				Signal: SignalLogs,
				Name:   producerIdentity.EventName,
			}
			familyID := producerIdentity.FamilyRefs.FamilyDescriptorID
			if producerIdentity.CompatibilityOnly {
				if familyID != "" || producerIdentity.FamilyRefs.SelectedFamilyFloorID != "" {
					panic("compatibility-only generated producer identity references a canonical family")
				}
				if _, canonical := canonicalIdentities[identity]; canonical {
					panic("compatibility-only generated producer identity duplicates a canonical family")
				}
				signalName := signalNameKey{signal: identity.Signal, name: identity.Name}
				if owner, exists := signalNameOwners[signalName]; exists && owner != identity.Bucket {
					panic("compatibility-only generated producer identity conflicts with an existing bucket owner")
				}
				if _, duplicate := compatibilityIdentities[identity]; duplicate {
					continue
				}
				compatibilityIdentities[identity] = struct{}{}
				signalNameOwners[signalName] = identity.Bucket
				addIdentity(identity)
				continue
			}
			canonical, ok := familyIdentities[familyID]
			if !ok || canonical != identity {
				panic("generated producer identity disagrees with the canonical family catalog")
			}
		}
	}

	ordered := make([]EventName, 0, len(registered))
	for name := range registered {
		ordered = append(ordered, name)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return registered, ordered, logs, traces, metrics, identities
}

// IsRegisteredEventName reports whether name is a declared v8 family or an
// explicitly generated compatibility identity. Lexical validity alone is
// deliberately insufficient.
func IsRegisteredEventName(name EventName) bool {
	_, ok := registeredEventNameSet[name]
	return ok
}

// IsRegisteredEventNameForSignal reports whether name belongs to the closed
// generated vocabulary for signal.
func IsRegisteredEventNameForSignal(signal Signal, name EventName) bool {
	var names map[EventName]struct{}
	switch signal {
	case SignalLogs:
		names = registeredLogEventNameSet
	case SignalTraces:
		names = registeredTraceEventNameSet
	case SignalMetrics:
		names = registeredMetricEventNameSet
	default:
		return false
	}
	_, ok := names[name]
	return ok
}

// IsRegisteredEventIdentity reports whether the exact bucket, signal, and name
// tuple is owned by a generated canonical family or compatibility identity.
func IsRegisteredEventIdentity(identity EventIdentity) bool {
	if !IsBucket(identity.Bucket) || !IsSignal(identity.Signal) || identity.Name.Validate() != nil {
		return false
	}
	_, ok := registeredEventIdentitySet[identity]
	return ok
}

// EventNames returns the complete registry in deterministic lexical order. The
// returned slice is a copy and can be modified safely by the caller.
func EventNames() []EventName {
	return append([]EventName(nil), registeredEventNameOrder...)
}
