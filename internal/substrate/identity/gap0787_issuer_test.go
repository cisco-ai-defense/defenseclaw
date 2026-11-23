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

package identity

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The trusted-issuer check reads the issuer however the claims are encoded.
func TestGAP0787TokenIssuerIsLenient(t *testing.T) {
	cb := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://idp.example","sub":"a"}`))
	for _, tok := range []string{"h." + cb + ".s", " h." + cb + "==.s\n", "h." + cb[:3] + "\r\n" + cb[3:] + ".s",
		"h." + strings.NewReplacer("-", "+", "_", "/").Replace(cb) + ".s"} {
		if got := tokenIssuer(tok); got != "https://idp.example" {
			t.Errorf("tokenIssuer(%q) = %q", tok, got)
		}
	}
	for _, tok := range []string{"", "opaque", "a.b", "h.e30.s", "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":5}`)) + ".s"} {
		if got := tokenIssuer(tok); got != "" {
			t.Errorf("tokenIssuer(%q) = %q, want none", tok, got)
		}
	}
}
