// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package identity

import "testing"

// TestIssuerRefusesKeyDelimiters: the person key hashes issuer#subject, so
// an issuer with '#' or '?' anywhere, even an empty fragment or query, is
// refused; otherwise https://idp# with subject x and https://idp with
// subject #x would be one person (RV2 P4-1).
func TestIssuerRefusesKeyDelimiters(t *testing.T) {
	for _, raw := range []string{"https://idp.example#", "https://idp.example?", "https://idp.example/a#b", "https://idp.example/realm?x=1"} {
		if _, err := validIssuer(raw); err == nil {
			t.Errorf("issuer %q accepted", raw)
		}
	}
	if _, err := validIssuer("https://idp.example/realms/eng"); err != nil {
		t.Errorf("plain issuer refused: %v", err)
	}
}
