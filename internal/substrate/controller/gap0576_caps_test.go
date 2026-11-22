// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// GAP-0576 item 4: admission normalised capability names (lower case,
// CAP_, padding) and ignored unknown drop names, so a template that drops
// "all" was read as dropping everything while Substrate might keep its
// defaults. Admission takes only Substrate's spelling: a known capability,
// upper case, no CAP_ prefix, no padding, or ALL in drop. The template
// publish adjustment is admitted.
func TestGAP0576CapabilityNamesMustBeSubstratesSpelling(t *testing.T) {
	sc := func(add, drop []string) func(*ateapi.ActorTemplate) {
		return func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &ateapi.SecurityContext{Capabilities: &ateapi.Capabilities{Add: add, Drop: drop}}
		}
	}
	two := []string{"SETUID", "SETGID"}
	three := []string{"SETUID", "SETGID", "KILL"}
	for name, c := range map[string]struct {
		mut func(*ateapi.ActorTemplate)
		ok  bool
	}{
		"template publish's adjustment":    {nil, true},
		"drop ALL, add the three":          {sc(three, []string{"ALL"}), true},
		"drop all (lower case), add three": {sc(three, []string{"all"}), false},
		"add CAP_SETUID":                   {sc([]string{"CAP_SETUID", "SETGID"}, []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}), false},
		"add setgid (lower case)":          {sc([]string{"SETUID", "setgid"}, []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}), false},
		"add padded SETUID":                {sc([]string{" SETUID", "SETGID"}, []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}), false},
		"drop cap_audit_write":             {sc(two, []string{"cap_audit_write", "NET_BIND_SERVICE"}), false},
		"drop an unknown name too":         {sc(two, []string{"AUDIT_WRITE", "NET_BIND_SERVICE", "NOT_A_CAP"}), false},
	} {
		att := kitAttest(t, c.mut)
		if att.Attested != c.ok {
			t.Errorf("%s: attested %v, want %v (%q)", name, att.Attested, c.ok, att.Reason)
			continue
		}
		if !c.ok && (!att.Allowlist || !strings.Contains(att.Reason, "security_context.capabilities")) {
			t.Errorf("%s: reason %q", name, att.Reason)
		}
	}
}
