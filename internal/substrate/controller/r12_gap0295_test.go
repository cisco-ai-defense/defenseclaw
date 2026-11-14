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

package controller_test

// R12 review probe (not for commit).

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Scoped listing (no global viewer role): a launcher atespace removed from
// config.yaml must take DefenseClaw's policy off its running actors (the
// docs say so), not leave the old policy and report them deleted.
func TestGAP0295ScopedLauncherRemovalDropsPolicy(t *testing.T) {
	r := newLiveRig(t)
	r.api.Err = func(method, key string) error {
		if method == "ListActors" && key == "" {
			return status.Error(codes.PermissionDenied, "no global viewer")
		}
		return nil
	}
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if !r.policyHas(ref, j9Host) {
		t.Fatal("baseline: host not allowed")
	}
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-other"}} }))
	r.clk.Add(configwatch.DefaultInterval)
	r.pass()
	r.pass()
	del := len(r.sink.Events(controller.EventDeleted))
	if p := r.api.Policy(ref); p != nil {
		t.Fatalf("R12: scoped mode: running actor in a removed launcher atespace keeps DefenseClaw's old policy (allows %s=%v); %d 'actor deleted' events for a running actor",
			j9Host, r.policyHas(ref, j9Host), del)
	}
	if del != 0 {
		t.Fatalf("R12: %d actor deleted events for a running actor", del)
	}
}
