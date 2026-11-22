// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bounded

import (
	"sort"
	"sync"
)

// The cap registry (DET111 step 2, one bound model). Every cap a reader
// package (hookpaths, actionfacts, effects, shellparse, psparse, toolshape)
// compares a count against is declared here, once, by name, unit and limit:
//
//	const maxStateGlobMatches = 64
//	var _ = bounded.Register("actionfacts.maxStateGlobMatches", bounded.Items, maxStateGlobMatches)
//
// TestAdopters fails on a max* cap of a reader package that is compared in
// its code and not registered, so a new cap cannot be added without being
// named in the one list the audit and the shadow report read. A registered cap
// reports its hit through the call's one Truncated (Hit, Within, Counter);
// the registry is the inventory, the Truncated is the signal.

// Spec is one registered cap.
type Spec struct {
	// Name is "<package>.<constant>", unique in the process.
	Name string
	// Unit is the kind of bound the cap measures.
	Unit Cap
	// Limit is the cap's value at start-up.
	Limit int
}

var registry struct {
	sync.Mutex
	specs []Spec
	names map[string]bool
}

// Register declares one cap and returns its limit, so a declaration can stay
// a constant: var _ = bounded.Register(name, unit, limit). A name is kept
// once (TestCapRegistry checks the names are unique across the module).
func Register(name string, unit Cap, limit int) int {
	registry.Lock()
	defer registry.Unlock()
	if registry.names == nil {
		registry.names = make(map[string]bool)
	}
	if registry.names[name] {
		return limit
	}
	registry.names[name] = true
	registry.specs = append(registry.specs, Spec{Name: name, Unit: unit, Limit: limit})
	return limit
}

// Registered is every cap registered in this process, sorted by name.
func Registered() []Spec {
	registry.Lock()
	out := append([]Spec(nil), registry.specs...)
	registry.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
