// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"strings"
	"testing"
)

// On a managed computer a user is never told another account's name, uid or
// PID (privacy rule); root and unmanaged hosts keep the full description.
func TestPortHolderStringManagedHidesOtherAccounts(t *testing.T) {
	prev := managedHost
	t.Cleanup(func() { managedHost = prev })
	other := PortHolder{PID: 4242, UID: 1999, Command: "openshell-gateway"}

	managedHost = func() bool { return true }
	for _, holder := range []PortHolder{other, {PID: 0, UID: 1999}} {
		got := holder.String(1000)
		if got != "a process of another account" {
			t.Errorf("managed user sees %q for %+v", got, holder)
		}
		for _, leak := range []string{"4242", "1999", "openshell-gateway", "uid"} {
			if strings.Contains(got, leak) {
				t.Errorf("managed user text %q leaks %q", got, leak)
			}
		}
	}
	if got := (PortHolder{PID: 7, UID: 1000, Command: "dc"}).String(1000); got != "PID 7 (dc)" {
		t.Errorf("own process = %q", got)
	}
	if got := (PortHolder{PID: 0, UID: -1}).String(1000); got != "another process" {
		t.Errorf("unknown holder = %q", got)
	}
	if got := other.String(0); !strings.Contains(got, "PID 4242") || !strings.Contains(got, "uid 1999") {
		t.Errorf("root should see the full description, got %q", got)
	}

	managedHost = func() bool { return false }
	if got := other.String(1000); !strings.Contains(got, "PID 4242") || !strings.Contains(got, "of another account (uid 1999") {
		t.Errorf("unmanaged host should keep the full description, got %q", got)
	}
}
