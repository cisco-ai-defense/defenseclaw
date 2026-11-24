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
	"net/http"
	"strings"
	"testing"
)

// GAP-0653: policy explain took only an agent name, so a person could not
// ask what profile they get. With no name it asks for the person's own
// answer (no actor in the query) and prints the default profile and the
// assignments that did not select them.
func TestSubstratePolicyExplainWithNoNameAsksForThePersonsProfileGAP0653(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET policy/explain": jsonReply(map[string]any{
			"profile": "eng", "default_profile": "eng", "profile_source": "default_profile",
			"unmatched_assignments": []any{map[string]any{"assignment": 1, "did_not_select_you": []any{"groups"}}},
		}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstratePolicyExplainCmd())
	if err != nil {
		t.Fatalf("policy explain with no name: %v", err)
	}
	for _, want := range []string{"default_profile: eng", "profile_source: default_profile", "groups"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
	if last := f.calls[len(f.calls)-1]; strings.Contains(last, "actor=") {
		t.Errorf("a no-name explain named an actor: %s", last)
	}
	if _, _, err := runSubstrate(t, newSubstratePolicyExplainCmd(), "a", "b"); err == nil {
		t.Error("two names must be refused")
	}
}
