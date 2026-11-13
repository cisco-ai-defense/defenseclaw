// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

func TestFleetKeysComeFromTheDeviceCredential(t *testing.T) {
	subject, err := budgetstore.NewSubjectKey(bytes.Repeat([]byte{7}, budgetstore.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	budgets := []config.RoutingBudget{
		{ID: "daily", Scope: "user", Subject: "*"},
		{ID: "named", Scope: "user", Subject: "S-1-5-21-1-2-3-1001"},
		{ID: "eng", Scope: "group", Subject: `DCLAB\eng`},
		{ID: "codex", Scope: "connector", Subject: "codex"},
		{ID: "anyconn", Scope: "connector", Subject: "*"},
	}
	cred, _, err := budgetstore.Issue(subject, budgetstore.IssueInput{Budgets: budgets,
		Users: []string{"S-1-5-21-1-2-3-1001"}, Groups: []string{`DCLAB\eng`}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fleetState{}
	f.installLocked(cred, &budgetstore.Client{})

	local := "user:daily:*:S-1-5-21-1-2-3-1001"
	if _, ok := f.ToFleet(local); ok {
		t.Fatal("a caller not yet seen has no fleet form")
	}
	f.noteUser("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001", "")
	f.noteUser("2001", "", "someone@dclab.test") // not in the credential: stays on this device
	fleetKey, ok := f.ToFleet(local)
	if !ok || fleetKey != "user:daily:*:"+cred.Users[0].ID {
		t.Fatalf("fleet key %q %v", fleetKey, ok)
	}
	if back, ok := f.FromFleet(fleetKey); !ok || back != local {
		t.Fatalf("round trip %q", back)
	}
	if _, ok := f.ToFleet("user:daily:*:2001"); ok {
		t.Fatal("a user the credential does not name must not be sent")
	}
	if _, ok := f.FromFleet("user:daily:*:uhsomeoneelse"); ok {
		t.Fatal("another device's user has no local form")
	}
	group := "group:eng:" + routingadmin.LocalSubjectHash(`DCLAB\eng`)
	if k, ok := f.ToFleet(group); !ok || !strings.HasPrefix(k, "group:eng:h") || k == group {
		t.Fatalf("group key %q %v", k, ok)
	}
	if _, ok := f.ToFleet("group:other:" + routingadmin.LocalSubjectHash(`DCLAB\other`)); ok {
		t.Fatal("a group the credential does not name must not be sent")
	}
	for _, k := range []string{"connector:codex:codex", "connector:anyconn:claudecode"} {
		if got, ok := f.ToFleet(k); !ok || got != k {
			t.Fatalf("connector key %s: %q %v", k, got, ok)
		}
	}
	f.bundle = map[string]bool{"daily": true, "named": true, "codex": true, "anyconn": true} // eng retired
	if _, ok := f.ToFleet(group); ok {
		t.Fatal("a budget no longer in the bundle is never sent")
	}
	for _, k := range f.Wanted() {
		if strings.HasPrefix(k, "group:eng:") {
			t.Fatal("a budget no longer in the bundle is never asked about")
		}
	}
	wanted := f.Wanted()
	joined := strings.ToLower(strings.Join(wanted, " "))
	for _, name := range []string{"dclab", "s-1-5-21"} {
		if strings.Contains(joined, name) {
			t.Fatalf("fleet keys %q name %q", joined, name)
		}
	}
	for _, k := range wanted {
		if !budgetstore.ValidKey(k) {
			t.Fatalf("wanted key %q is not a store key", k)
		}
	}
}
