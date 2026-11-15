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

// R12 delta probe (not for commit): reloadConfig must never apply an older
// config after a newer one. Since 4f4e349a36 Refresh runs outside reloadMu,
// and a Refresh that returns at once (another one is reading) hands back the
// config in force at that moment. If that caller takes reloadMu after the
// reader applied the newer config, it sees digest != prev and stores the
// older one. The scripted source below replays exactly that interleaving.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

type scriptedSource struct {
	mu    sync.Mutex
	cur   *config.Config
	dig   string
	gen   uint64
	queue []configwatch.Change
}

func (s *scriptedSource) Current() (*config.Config, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur, s.dig
}

func (s *scriptedSource) Refresh(context.Context) configwatch.Change {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return configwatch.Change{Config: s.cur, Digest: s.dig, Gen: s.gen}
	}
	ch := s.queue[0]
	s.queue = s.queue[1:]
	if ch.Changed {
		s.cur, s.dig, s.gen = ch.Config, ch.Digest, ch.Gen
	}
	return ch
}

func TestGAP0305ReloadIsMonotonic(t *testing.T) {
	v1 := j9Config(nil)
	v2 := j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) })
	src := &scriptedSource{cur: v1, dig: "d1"}
	// Caller B's Refresh returned early (A was reading) with d1; A's
	// Refresh then committed d2. A takes reloadMu first, B second.
	src.queue = []configwatch.Change{
		{Config: v2, Digest: "d2", Previous: "d1", Changed: true, Gen: 1}, // A
		{Config: v1, Digest: "d1", Gen: 0},                                // B: stale snapshot
	}
	r := newRig(t, func(cfg *config.Config, o *controller.Options) {
		*cfg = *v1
		o.Resolver = &controller.ConfigResolver{Config: v1}
		o.Config = src
		o.Live = func(c *config.Config) controller.Live {
			return controller.Live{Settings: controller.SettingsFromConfig(c), Secrets: controller.SecretsFromConfig(c),
				LauncherAtespaces: controller.LauncherSet(c), RequireAttestation: true, Templates: c.Substrate.Templates,
				Attestor: o.Attestor, Resolver: &controller.ConfigResolver{Config: c}, IdleSuspendAfter: 30 * time.Minute}
		}
	})
	r.pass() // A
	if d := r.ctl.Digest(); d != "d2" {
		t.Fatalf("A did not apply d2: %s", d)
	}
	r.pass() // B
	if d := r.ctl.Digest(); d != "d2" {
		cur, _ := src.Current()
		t.Fatalf("R12 delta: a stale Refresh snapshot rolled the controller back from d2 to %s while the watcher holds %q (removed host allowed again: %v)",
			d, "d2", len(cur.Substrate.Egress.Allow) == 1 && d == "d1")
	}
}

// TestGAP0305ConcurrentCreatesNeverRollBack: many create-path reloads racing
// a stream of tightenings end on the newest config (run with -race).
func TestGAP0305ConcurrentCreatesNeverRollBack(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	for i := 2; i <= 6; i++ {
		raw := fmt.Sprintf("v%d", i)
		r.cm.set(raw, j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
		r.clk.Add(configwatch.DefaultInterval)
		var wg sync.WaitGroup
		for k := 0; k < 8; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
					t.Errorf("EnsurePolicy: %v", err)
				}
			}()
		}
		wg.Wait()
		if got, want := r.ctl.Digest(), configwatch.Digest([]byte(raw)); got != want {
			t.Fatalf("after %s the controller is on %s, not %s", raw, got, want)
		}
	}
}
