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

package config

import "testing"

// GAP-0194: the actor key set comes from the idp Service of the Substrate
// namespace, whatever the issuer is.
func TestSubstrateEffectiveKeysURL(t *testing.T) {
	cases := []struct {
		name string
		s    SubstrateConfig
		want string
	}{
		{"defaults", SubstrateConfig{}, "https://idp.ate-system.svc/openid/v1/jwks"},
		{"unique issuer", SubstrateConfig{Identity: SubstrateIdentityConfig{Issuer: "https://substrate-e2.idp.invalid"}},
			"https://idp.ate-system.svc/openid/v1/jwks"},
		{"namespace from the API address", SubstrateConfig{API: SubstrateAPIConfig{Address: "api.sub-x.svc:443"}},
			"https://idp.sub-x.svc/openid/v1/jwks"},
		{"cluster.local API address", SubstrateConfig{API: SubstrateAPIConfig{Address: "api.sub-y.svc.cluster.local:443"}},
			"https://idp.sub-y.svc/openid/v1/jwks"},
		{"an API address of another shape", SubstrateConfig{API: SubstrateAPIConfig{Address: "ate.example.com:443"}},
			"https://idp.ate-system.svc/openid/v1/jwks"},
		{"set", SubstrateConfig{Identity: SubstrateIdentityConfig{KeysURL: "https://keys.example.com/jwks"}},
			"https://keys.example.com/jwks"},
	}
	for _, c := range cases {
		if got := c.s.EffectiveKeysURL(); got != c.want {
			t.Errorf("%s: keys URL %q, want %q", c.name, got, c.want)
		}
	}
	if got := (SubstrateConfig{}).EffectiveKeysCAFile(); got != DefaultSubstrateKeysCAFile {
		t.Errorf("keys CA %q", got)
	}
	if got := (SubstrateConfig{Identity: SubstrateIdentityConfig{KeysCAFile: "/etc/ca.pem"}}).EffectiveKeysCAFile(); got != "/etc/ca.pem" {
		t.Errorf("keys CA %q", got)
	}
}
