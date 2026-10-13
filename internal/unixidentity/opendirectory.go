// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unixidentity

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Open Directory's view of a bound Mac's Active Directory nodes.
//
// With the domain controller out of reach Open Directory still answers at
// once and without an error: a mobile account resolves from the local node,
// its primary group (Domain Users) keeps its name, and its other domain groups
// are simply gone. Nothing in that answer says it is incomplete, so the
// account's facts looked resolved, a groups assignment silently fell to the
// default profile as "default", and an assignment group was reported as
// renamed or deleted in the directory (GAP-0496, GAP-0517). Open Directory
// does say the domain is unreachable: `odutil show nodenames` lists its
// Active Directory nodes Offline. OpenDirectoryOffline reads that list.

// openDirectoryStateTTL is how long one reading of the node list is reused,
// so the lookups of many accounts share one odutil call.
const openDirectoryStateTTL = 5 * time.Second

// openDirectoryNodeStates returns the output of `odutil show nodenames`.
// Tests replace it.
var openDirectoryNodeStates = platformOpenDirectoryNodeStates

var openDirectoryState struct {
	sync.Mutex
	at      time.Time
	offline bool
}

// OpenDirectoryOffline reports whether this Mac's Open Directory lists the
// node of a bound Active Directory domain as offline. It is false on other
// platforms, on a Mac bound to no domain, and when the list cannot be read.
func OpenDirectoryOffline(ctx context.Context) bool {
	openDirectoryState.Lock()
	defer openDirectoryState.Unlock()
	now := time.Now()
	if !openDirectoryState.at.IsZero() && now.Sub(openDirectoryState.at) >= 0 && now.Sub(openDirectoryState.at) < openDirectoryStateTTL {
		return openDirectoryState.offline
	}
	out, err := openDirectoryNodeStates(ctx)
	openDirectoryState.offline = err == nil && ActiveDirectoryNodeOffline(ParseODUtilNodeStates(out))
	openDirectoryState.at = now
	return openDirectoryState.offline
}

// ParseODUtilNodeStates reads the node table `odutil show nodenames` prints
// (Name, State, Refs, ...) into node name -> lower-case state. A row with no
// Online or Offline state (the /Local container) is left out. Node names
// hold spaces ("/Active Directory/CORP/All Domains"), so the state is the
// first Online or Offline word after the name.
func ParseODUtilNodeStates(out string) map[string]string {
	states := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "/") {
			continue
		}
		for i := 1; i < len(fields); i++ {
			if state := strings.ToLower(fields[i]); state == "online" || state == "offline" {
				states[strings.Join(fields[:i], " ")] = state
				break
			}
		}
	}
	return states
}

// ActiveDirectoryNodeOffline reports whether a domain node of a bound Active
// Directory domain (/Active Directory/CORP) or its forest search node
// (/Active Directory/CORP/All Domains) is offline. The other virtual nodes
// (one domain of the forest, the global catalog) are not read: one of them
// can be out of reach while the account's own domain answers.
func ActiveDirectoryNodeOffline(states map[string]string) bool {
	for name, state := range states {
		rest, ok := strings.CutPrefix(name, "/Active Directory/")
		if !ok || rest == "" || state != "offline" {
			continue
		}
		if _, sub, nested := strings.Cut(rest, "/"); !nested || sub == "All Domains" {
			return true
		}
	}
	return false
}
