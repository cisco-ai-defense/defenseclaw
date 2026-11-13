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

package fleet

import "testing"

// GAP-0194: a unique issuer passes when the keys URL answers and Substrate
// signs with the configured issuer; anything else refuses every actor.
func TestCheckActorKeysVerify(t *testing.T) {
	n := func(i int) *int { return &i }
	const uniq = "https://substrate-e2.idp.invalid"
	base := Observed{Issuer: uniq, KeysURL: "https://idp.ate-system.svc/openid/v1/jwks", Keys: n(1), ServedIssuer: uniq, InstallIssuer: uniq}
	expect(t, CheckActorKeysVerify(base), Pass, "signs actor tokens with substrate.identity.issuer")

	o := base
	o.InstallIssuer = "https://idp.ate-system.svc"
	expect(t, CheckActorKeysVerify(o), Fail, "actorJWT.issuer differs")
	o = base
	o.Keys, o.KeysErr = n(0), "503"
	expect(t, CheckActorKeysVerify(o), Fail, "does not answer")
	o = base
	o.ServedIssuer = "https://idp.ate-system.svc"
	expect(t, CheckActorKeysVerify(o), Fail, "another issuer")
	o = base
	o.ServedIssuer = ""
	expect(t, CheckActorKeysVerify(o), Warn, "could not be read")
	o = base
	o.Keys, o.KeysNote = nil, "it is not a Service of this cluster"
	expect(t, CheckActorKeysVerify(o), Warn, "substrate doctor --cluster")
	o = base
	o.Issuer = ""
	expect(t, CheckActorKeysVerify(o), Skip, "not set")
}
