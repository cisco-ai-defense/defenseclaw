// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import "testing"

func TestValidateIdentityBinding(t *testing.T) {
	for _, test := range []struct {
		name    string
		broker  string
		gateway string
		pipe    string
		valid   bool
	}{
		{
			name: "production", broker: "DefenseClawCMIDBroker", gateway: "DefenseClawGateway",
			pipe: `\\.\pipe\DefenseClawCMIDBroker`, valid: true,
		},
		{
			name: "certification", broker: "DefenseClawCMIDBroker_0123456789", gateway: "DefenseClawCertGateway_0123456789",
			pipe: `\\.\pipe\DefenseClawCMIDBroker_0123456789`, valid: true,
		},
		{
			name: "wrong_scope", broker: "DefenseClawCMIDBroker_0123456789", gateway: "DefenseClawCertGateway_aaaaaaaaaa",
			pipe: `\\.\pipe\DefenseClawCMIDBroker_0123456789`,
		},
		{
			name: "remote_pipe", broker: "DefenseClawCMIDBroker", gateway: "DefenseClawGateway",
			pipe: `\\host\pipe\DefenseClawCMIDBroker`,
		},
		{
			name: "subnamespace", broker: "DefenseClawCMIDBroker", gateway: "DefenseClawGateway",
			pipe: `\\.\pipe\DefenseClawCMIDBroker\other`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateIdentityBinding(test.broker, test.gateway, test.pipe)
			if (err == nil) != test.valid {
				t.Fatalf("error = %v, valid = %v", err, test.valid)
			}
		})
	}
}
