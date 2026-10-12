// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unixidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const odutilOnline = `Nodenames:

Name                                   State  Refs Type         External Locked Hidden 
-------------------------------------- ------ ---- ------------ -------- ------ ------ 
/Active Directory                      Online 2                          X      X      
/Active Directory/DCLAB                Online 12                                       
/Active Directory/DCLAB/All Domains    Online 6    Virtual node                        
/Active Directory/DCLAB/Global Catalog Online 679  Virtual node                 X      
/Active Directory/DCLAB/dclab.test     Online 6    Virtual node                 X      
/Local                                        2                          X      X      
/Local/Default                         Online 33                         X             
/Search                                Online 8                                        
`

// TestOpenDirectoryOfflineReadsTheDomainNodes pins GAP-0496 and GAP-0517:
// a bound Mac whose domain controller does not answer lists its Active
// Directory domain node Offline, and only that node or its forest search
// node says so; an unreadable list or an unbound Mac says nothing.
func TestOpenDirectoryOfflineReadsTheDomainNodes(t *testing.T) {
	states := ParseODUtilNodeStates(odutilOnline)
	if states["/Active Directory/DCLAB/All Domains"] != "online" || states["/Local/Default"] != "online" {
		t.Fatalf("states = %v", states)
	}
	if _, ok := states["/Local"]; ok {
		t.Fatalf("/Local has no state: %v", states)
	}
	if ActiveDirectoryNodeOffline(states) {
		t.Fatal("every node online, want not offline")
	}
	offline := strings.Replace(odutilOnline, "/Active Directory/DCLAB                Online", "/Active Directory/DCLAB                Offline", 1)
	if !ActiveDirectoryNodeOffline(ParseODUtilNodeStates(offline)) {
		t.Fatal("domain node offline, want offline")
	}
	forest := strings.Replace(odutilOnline, "All Domains    Online", "All Domains    Offline", 1)
	if !ActiveDirectoryNodeOffline(ParseODUtilNodeStates(forest)) {
		t.Fatal("All Domains offline, want offline")
	}
	catalog := strings.Replace(odutilOnline, "Global Catalog Online", "Global Catalog Offline", 1)
	if ActiveDirectoryNodeOffline(ParseODUtilNodeStates(catalog)) {
		t.Fatal("only the global catalog offline, want not offline")
	}

	prev := openDirectoryNodeStates
	t.Cleanup(func() {
		openDirectoryNodeStates = prev
		openDirectoryState.Lock()
		openDirectoryState.at = time.Time{}
		openDirectoryState.Unlock()
	})
	calls := 0
	openDirectoryNodeStates = func(context.Context) (string, error) { calls++; return offline, nil }
	if !OpenDirectoryOffline(context.Background()) || !OpenDirectoryOffline(context.Background()) || calls != 1 {
		t.Fatalf("offline list: calls = %d, want one call reused", calls)
	}
	openDirectoryState.Lock()
	openDirectoryState.at = time.Time{}
	openDirectoryState.Unlock()
	openDirectoryNodeStates = func(context.Context) (string, error) { return "", errors.New("odutil missing") }
	if OpenDirectoryOffline(context.Background()) {
		t.Fatal("unreadable list, want not offline")
	}
}
