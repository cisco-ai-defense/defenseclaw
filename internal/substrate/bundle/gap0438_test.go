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

package bundle

import (
	"context"
	"strings"
	"testing"

	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0438: a stage names only atespaces DefenseClaw manages. An atespace
// that is not a launcher atespace and that no assignment of config.yaml or
// of the bundle lists by name is refused with a receipt, and no stage is
// created for it (it would hold a slot of the stage cap and a receipt that
// says applied for a bundle no actor there can get).
func TestGAP0438ApplyRefusesUnmanagedAtespace(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.store.Base.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}}
	e.store.Base.Guardrail.ProfileAssignments = nil
	b := func(v uint64) []byte { return buildBundle(t, e.key, v, policyYAML("x.example.com")) }

	for name, ns := range map[string][]string{
		"no such atespace":     {"dc-evil"},
		"one of two unmanaged": {"team-a", "dc-default"},
		"listed nowhere":       {"team-zz"},
	} {
		rc, err := e.store.Apply(ctx, b(1), "s-"+strings.ReplaceAll(name, " ", "-"), ns, SourceAdmin)
		if eb.CodeOf(err) != CodeStageInvalid || rc == nil || rc.Result != ResultRefused || !strings.Contains(err.Error(), "not managed by DefenseClaw") {
			t.Errorf("%s: err %v receipt %+v, want a stage_invalid refusal", name, err, rc)
		}
	}
	st, err := e.store.Status(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Stages) != 0 {
		t.Fatalf("a refused apply created stages: %+v", st.Stages)
	}

	// Managed by the bundle's own assignment, by a launcher atespace, and the
	// all stage: each applies.
	if rc, err := e.store.Apply(ctx, b(1), "canary", []string{"team-a"}, SourceAdmin); err != nil || rc.Result != ResultApplied {
		t.Fatalf("bundle-listed atespace: %+v %v", rc, err)
	}
	if rc, err := e.store.Apply(ctx, b(2), "eng", []string{"dc-eng"}, SourceAdmin); err != nil || rc.Result != ResultApplied {
		t.Fatalf("launcher atespace: %+v %v", rc, err)
	}
	if rc, err := e.store.Apply(ctx, b(3), StageAll, nil, SourceAdmin); err != nil || rc.Result != ResultApplied {
		t.Fatalf("all stage: %+v %v", rc, err)
	}

	// The inbox path takes the same rule.
	e.cm.Put(&ConfigMap{Name: "defenseclaw-bundle-inbox",
		Data:       map[string]string{"wave2.atespaces": "dc-evil"},
		BinaryData: map[string][]byte{"wave2.dcbundle": b(4)}})
	rcs, err := e.store.SyncInbox(ctx, "defenseclaw-bundle-inbox")
	if err != nil || len(rcs) != 1 || rcs[0].Result != ResultRefused || rcs[0].Code != string(CodeStageInvalid) {
		t.Fatalf("inbox: %+v %v", rcs, err)
	}
}
