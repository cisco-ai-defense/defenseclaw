// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

func TestHookCredentialBindingIsRecordedWithoutCredentials(t *testing.T) {
	perUser := SetupOpts{
		HookCredentialIdentity: "1001",
		APIToken:               "hook-credential-value",
		OTLPPathToken:          "otlp-credential-value",
	}
	binding := hookCredentialBinding(perUser)
	if !strings.HasPrefix(binding, "1001:") || len(binding) != len("1001:")+32 {
		t.Fatalf("binding = %q", binding)
	}
	if strings.Contains(binding, perUser.APIToken) || strings.Contains(binding, perUser.OTLPPathToken) {
		t.Fatal("binding contains a credential")
	}
	if hookCredentialBinding(SetupOpts{APIToken: "x"}) != "" {
		t.Fatal("an install without a bound identity records no binding")
	}
	lock := HookContractLockEntry{RegistrationPosture: &HookRegistrationPosture{HookCredentialBinding: binding}}
	other := perUser
	other.HookCredentialIdentity = "1002"
	rotated := perUser
	rotated.OTLPPathToken = "rotated"
	for _, tc := range []struct {
		name  string
		lock  HookContractLockEntry
		opts  SetupOpts
		drift bool
	}{
		{"same credentials", lock, perUser, false},
		{"another user", lock, other, true},
		{"rotated credential", lock, rotated, true},
		{"lock from before per-user credentials", HookContractLockEntry{}, perUser, true},
		{"posture without binding", HookContractLockEntry{RegistrationPosture: &HookRegistrationPosture{}}, perUser, true},
		{"install without a bound identity", HookContractLockEntry{}, SetupOpts{APIToken: "x"}, false},
	} {
		if got := HookCredentialDrifted(tc.lock, tc.opts); got != tc.drift {
			t.Errorf("%s: HookCredentialDrifted = %v, want %v", tc.name, got, tc.drift)
		}
	}
}
