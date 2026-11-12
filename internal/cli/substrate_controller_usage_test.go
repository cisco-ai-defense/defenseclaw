// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// GAP-0105: the usage listener is loopback only unless it is mutual TLS.
func TestSubstrateUsageListenerAuth(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:4319", "[::1]:4319", "localhost:4319"} {
		if cfg, err := substrateUsageTLS(addr, "", "", ""); err != nil || cfg != nil {
			t.Errorf("%s: %v %v", addr, cfg, err)
		}
	}
	for _, addr := range []string{":4319", "0.0.0.0:4319", "10.0.0.5:4319"} {
		if _, err := substrateUsageTLS(addr, "", "", ""); err == nil {
			t.Errorf("%s: plain listener allowed off loopback", addr)
		}
	}
	if _, err := substrateUsageTLS(":4319", "c.pem", "", ""); err == nil {
		t.Error("partial TLS flags accepted")
	}
	if _, err := substrateUsageTLS(":4319", "/nonexistent/c.pem", "/nonexistent/k.pem", "/nonexistent/ca.pem"); err == nil {
		t.Error("missing key pair accepted")
	}
}
