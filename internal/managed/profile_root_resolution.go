// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"slices"
	"sync"
	"time"
)

// profileRootResolutionReuse is how long the resolved destinations of
// unchanged profile roots are reused (profileRootResolution).
const profileRootResolutionReuse = 5 * time.Second

// profileRootResolution keeps the last resolution of the Windows profile
// roots for the LocalSystem gateway path check
// (RequireWindowsGatewayPathOutsideUserProfiles). The root names are read
// from the registry on every check, so a profile added, removed or moved is
// seen at once. Resolving each root through junctions and short names opens
// it, and a managed hook call checks several paths: a 60-way parallel tool
// turn spent about a sixth of the gateway hook time re-resolving the same
// roots (GAP-0050). The resolution is reused only for the same names and for
// a few seconds; only an administrator can redirect a profile root.
type profileRootResolution struct {
	mu       sync.Mutex
	names    []string
	physical []string
	at       time.Time
}

// resolve returns names followed, root by root, by the destination resolve
// gives it, as each name and its destination, reusing the last resolution
// of the same names for profileRootResolutionReuse. An error is not kept.
func (c *profileRootResolution) resolve(names []string, now time.Time, resolve func(string) (string, error)) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if age := now.Sub(c.at); c.physical != nil && age >= 0 && age < profileRootResolutionReuse && slices.Equal(c.names, names) {
		return slices.Clone(c.physical), nil
	}
	c.physical = nil
	physical := make([]string, 0, len(names)*2)
	for _, root := range names {
		resolved, err := resolve(root)
		if err != nil {
			return nil, err
		}
		physical = append(physical, root, resolved)
	}
	c.names, c.physical, c.at = slices.Clone(names), physical, now
	return slices.Clone(physical), nil
}
