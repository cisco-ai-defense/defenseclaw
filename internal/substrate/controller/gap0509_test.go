// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// GAP-0509: a separated kit image's container must end with exactly KILL,
// SETGID and SETUID. A hand-written template that adds SETUID and SETGID but
// keeps Substrate's other defaults (AUDIT_WRITE, NET_BIND_SERVICE) is
// refused with the capability named; template publish's adjustment, and a
// template that drops more, are admitted.
func TestGAP0509SeparatedImageGetsExactlyTheRelayCapabilities(t *testing.T) {
	sc := func(add, drop []string) func(*ateapi.ActorTemplate) {
		return func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &ateapi.SecurityContext{Capabilities: &ateapi.Capabilities{Add: add, Drop: drop}}
		}
	}
	two, three := []string{"SETUID", "SETGID"}, []string{"SETUID", "SETGID", "KILL"}
	for name, c := range map[string]struct {
		mut  func(*ateapi.ActorTemplate)
		ok   bool
		name string
	}{
		"template publish's adjustment":           {nil, true, ""},
		"add SETUID and SETGID, no drop":          {sc(two, nil), false, "AUDIT_WRITE"},
		"add the three, no drop":                  {sc(three, nil), false, "AUDIT_WRITE"},
		"drop AUDIT_WRITE only":                   {sc(two, []string{"AUDIT_WRITE"}), false, "NET_BIND_SERVICE"},
		"drop NET_BIND_SERVICE only":              {sc(two, []string{"NET_BIND_SERVICE"}), false, "AUDIT_WRITE"},
		"drop ALL, add the three":                 {sc(three, []string{"ALL"}), true, ""},
		"drop more than template publish":         {sc(two, []string{"AUDIT_WRITE", "NET_BIND_SERVICE", "CHOWN"}), true, ""},
		"template publish's, CAP_ and lower case": {sc([]string{"CAP_SETUID", "cap_setgid"}, []string{"cap_audit_write", "NET_BIND_SERVICE"}), true, ""},
	} {
		att := kitAttest(t, c.mut)
		if att.Attested != c.ok {
			t.Errorf("%s: attested %v, want %v (%q)", name, att.Attested, c.ok, att.Reason)
			continue
		}
		if !c.ok && (!att.Allowlist || !strings.Contains(att.Reason, "security_context") || !strings.Contains(att.Reason, "leaves the container "+c.name)) {
			t.Errorf("%s: reason %q does not name %s", name, att.Reason, c.name)
		}
	}
}
