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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0494: the stage rule of GAP-0438 read the boot config, while the
// gateway and the controller follow launcher_atespaces live (GAP-0276). A
// launcher atespace added by a config change was refused (stage_invalid)
// until the gateway restarted. The store reads the live config when it has
// one; one removed live is refused again.
func TestGAP0494StageRuleFollowsTheLiveConfig(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.store.Base.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}}
	live := *e.store.Base
	live.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}, "ops": {"dc-ops"}}
	cur := &live
	e.store.Live = func() *config.Config { return cur }
	b := func(v uint64) []byte { return buildBundle(t, e.key, v, policyYAML("x.example.com")) }

	if rc, err := e.store.Apply(ctx, b(1), "ops", []string{"dc-ops"}, SourceAdmin); err != nil || rc.Result != ResultApplied {
		t.Fatalf("a launcher atespace added live was refused: %+v %v", rc, err)
	}
	removed := *e.store.Base
	cur = &removed
	if _, err := e.store.Apply(ctx, b(2), "ops2", []string{"dc-ops"}, SourceAdmin); eb.CodeOf(err) != CodeStageInvalid {
		t.Fatalf("an atespace removed live still applies: %v", err)
	}
	// No live config: the boot config decides.
	e.store.Live = nil
	if _, err := e.store.Apply(ctx, b(3), "eng", []string{"dc-eng"}, SourceAdmin); err != nil {
		t.Fatalf("boot launcher atespace: %v", err)
	}
}
