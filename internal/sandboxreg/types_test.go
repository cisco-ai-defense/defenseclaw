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
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestRecordTagsAreSnakeCase(t *testing.T) {
	for _, v := range []any{Registration{}, Decision{}, DecisionActor{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if !snakeCase.MatchString(name) {
				t.Errorf("%s.%s json name %q is not snake_case", typ.Name(), f.Name, name)
			}
		}
	}
}

// A pending registration round-trips and leaves its unset times out.
func TestRegistrationJSON(t *testing.T) {
	r := Registration{
		V: RecordVersion, ID: IDPrefix + strings.Repeat("a", IDRandomChars), UID: 1001, UserName: "alice",
		SubjectKey: DigestPrefix + "00", FactsDigest: DigestPrefix + "11", ProfileMatch: MatchDefault,
		WorkdirMode: "copy", State: StatePending, CreatedAt: time.Unix(1_800_000_000, 0).UTC(),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"bound_at", "revoked_at", "sandbox_id", "binding_id", "revoked_reason"} {
		if _, ok := m[absent]; ok {
			t.Errorf("unset %q is serialized", absent)
		}
	}
	for _, present := range []string{"v", "subject_key", "facts_digest", "profile", "openshell_version", "workdir_mode"} {
		if _, ok := m[present]; !ok {
			t.Errorf("%q missing", present)
		}
	}
	var back Registration
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, r) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, r)
	}
}
