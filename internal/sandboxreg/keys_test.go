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

package sandboxreg

import (
	"strings"
	"testing"
)

const testActorUID = "25a1da0f-1c9b-4ef7-8248-c276138c7f77"

func TestOpenShellIDsStayKeysUnchanged(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(id)
	if err != nil || key.Runtime != "openshell" || key.ID != id || key.String() != id || !ValidKey(id) {
		t.Fatalf("ParseKey(%q) = %+v, %v", id, key, err)
	}
}

func TestSubstrateKeys(t *testing.T) {
	key, err := SubstrateKey("eng-web", testActorUID)
	if err != nil || key != "substrate:eng-web/"+testActorUID {
		t.Fatalf("SubstrateKey = %q, %v", key, err)
	}
	parsed, err := ParseKey(key)
	if err != nil || parsed != (Key{Runtime: "substrate", Atespace: "eng-web", ActorUID: testActorUID}) || parsed.String() != key {
		t.Fatalf("ParseKey(%q) = %+v, %v", key, parsed, err)
	}
	// The per-uid file store keeps OpenShell ids only.
	if ValidID(key) {
		t.Fatal("ValidID accepted a substrate key")
	}
	for _, bad := range []string{
		"", "reg-", "substrate:", "substrate:eng-web", "substrate:eng-web/", "substrate:/" + testActorUID,
		"Substrate:eng-web/" + testActorUID, "substrate:Eng-Web/" + testActorUID, "substrate:-eng/" + testActorUID,
		"substrate:eng-web/" + strings.ToUpper(testActorUID), "substrate:eng-web/" + testActorUID + "/x",
		"substrate:eng.web/" + testActorUID, "substrate:" + strings.Repeat("a", 64) + "/" + testActorUID,
		"openshell:reg-aaaaaaaaaaaaaaaaaaaaaaaaaa", " substrate:eng-web/" + testActorUID, "substrate:eng-web/not-a-uuid",
	} {
		if ValidKey(bad) {
			t.Errorf("ValidKey(%q) accepted", bad)
		}
	}
	if _, err := SubstrateKey("eng-web", "x"); err == nil {
		t.Fatal("bad UID accepted")
	}
}
