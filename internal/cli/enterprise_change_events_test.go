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

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// changeAnchorsDoc is a valid anchor file with the given key ids.
func changeAnchorsDoc(t *testing.T, ids ...string) []byte {
	t.Helper()
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, fmt.Sprintf(`{"key_id":%q,"alg":"ed25519","public_key":%q,"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","status":"active"}`,
			id, base64.StdEncoding.EncodeToString(spki)))
	}
	return []byte(`{"schema_version":1,"tenant_id":"acme","device_groups":[],"min_version":0,"keys":[` + strings.Join(keys, ",") + `]}`)
}

// The anchor change event (Windows TRUSTANCHORS= and the bundle commit)
// carries the two hashes and the key ids only; identical bytes record
// nothing.
func TestAnchorsChangeEvent(t *testing.T) {
	first, second := changeAnchorsDoc(t, "k1"), changeAnchorsDoc(t, "k1", "k2")
	ev, ok := anchorsChangeEvent(nil, first)
	if !ok || ev.Outcome != enterprisestatus.ChangeApplied || ev.SHA256 != anchorsSHA256(first) ||
		ev.PreviousSHA256 != "" || !reflect.DeepEqual(ev.KeyIDsAdded, []string{"k1"}) || ev.Validate() != nil {
		t.Fatalf("first install = %+v ok %v (%v)", ev, ok, ev.Validate())
	}
	ev, ok = anchorsChangeEvent(first, second)
	if !ok || ev.PreviousSHA256 != anchorsSHA256(first) || ev.SHA256 != anchorsSHA256(second) ||
		!reflect.DeepEqual(ev.KeyIDsAdded, []string{"k2"}) || len(ev.KeyIDsRemoved) != 0 {
		t.Fatalf("replace = %+v", ev)
	}
	if _, ok := anchorsChangeEvent(second, second); ok {
		t.Fatal("identical bytes recorded a change")
	}
	failed, ok := anchorsFailureEvent("anchor_invalid", false, second)
	if !ok || failed.Outcome != enterprisestatus.ChangeRefused || failed.ReasonCode != "anchor_invalid" ||
		failed.SHA256 != anchorsSHA256(second) || failed.Validate() != nil {
		t.Fatalf("refusal = %+v", failed)
	}
}

func TestSecretChangeEventOutcomes(t *testing.T) {
	refused := errors.New("refused")
	for _, tc := range []struct {
		name, code, outcome string
		changed, attempted  bool
		err                 error
		ok                  bool
	}{
		{"applied", "", enterprisestatus.ChangeApplied, true, false, nil, true},
		{"nothing changed", "", "", false, false, nil, false},
		{"refused", "elevation_required", enterprisestatus.ChangeRefused, false, false, refused, true},
		{"write failed", "change_failed", enterprisestatus.ChangeFailed, false, false, refused, true},
		{"restart failed", "restart_failed", enterprisestatus.ChangeFailed, false, false, refused, true},
		{"lifecycle failed", "apply_failed", enterprisestatus.ChangeFailed, false, true, refused, true},
	} {
		ev, ok := secretChangeEvent("set", "splunk-hec-token", tc.changed, tc.code, tc.err, tc.attempted)
		if ok != tc.ok || (ok && (ev.Outcome != tc.outcome || ev.Validate() != nil || ev.SecretName != "splunk-hec-token")) {
			t.Fatalf("%s: %+v ok %v (%v)", tc.name, ev, ok, ev.Validate())
		}
	}
	if ev, ok := secretChangeEvent("set", "Bad Name", false, "invalid_arguments", refused, false); !ok || ev.SecretName != "" {
		t.Fatalf("a refused name was recorded: %+v", ev)
	}
}
