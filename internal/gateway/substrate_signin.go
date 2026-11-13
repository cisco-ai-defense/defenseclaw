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

package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/signin"
)

// substrateSigninRefusedCode is the reason of an E9 refusal.
const substrateSigninRefusedCode = signin.RefusedCode

// signinDecision applies E9 to a connector and the secrets bound to the
// actor (names, resolved to the placeholders egress replaces).
func (c SubstrateConfig) signinDecision(connector string, secrets []string) signin.Decision {
	var placeholders []string
	if c.SecretPlaceholders != nil {
		placeholders = c.SecretPlaceholders(secrets)
	}
	return signin.Evaluate(sandboxauth.CanonicalConnector(connector), c.Managed, placeholders)
}

// writeSubstrateSigninRefusal answers 403 with the reason code and the text
// a person (or the actor kit, for its agent's screen) shows.
func writeSubstrateSigninRefusal(w http.ResponseWriter, d signin.Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": http.StatusText(http.StatusForbidden), "reason": d.Code, "message": d.Message,
	})
}
