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

//go:build openshell_integration && (linux || darwin)

package openshelle2e

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestTwoDaemonsOneGateway runs two DefenseClaw daemons, with their own
// data dirs and ports (a dev daemon next to the usual one), against one
// OpenShell gateway. Each creates a Claude Code sandbox at the same time;
// both creates succeed, and each sandbox's hooks reach its own daemon (the
// other daemon never hears of it). This is the collision a single
// gateway-wide ingress provider profile, holding one daemon's port, caused.
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e \
//	DEFENSECLAW_E2E_PREFIX=pn-pair DEFENSECLAW_E2E_API_PORT=31970 DEFENSECLAW_E2E_MOCK_PORT=31921 \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestTwoDaemonsOneGateway -v -timeout 60m
//
// The daemons are <prefix>-a and <prefix>-b; b's ports are a's plus 20.
// DEFENSECLAW_E2E_TOKEN_DELIVERY=env runs both with token_delivery: env.
// Everything is cleaned up as in TestSandboxDaemon.
func TestTwoDaemonsOneGateway(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	if work == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR to run the live two-daemon sandbox test")
	}
	prefix := envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e-pair")
	apiPort := envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970)
	mock := envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921)
	delivery := e2eTokenDelivery(t)
	repo := repoRoot(t)
	var pair []*env
	for i, id := range []string{"a", "b"} {
		e := &env{
			t: t, root: t, prefix: prefix + "-" + id, repo: repo, tokenDelivery: delivery,
			apiPort: apiPort + 20*i, mock: mock + 20*i,
		}
		if !openshell.ValidSandboxName(e.prefix + stopSuffix) {
			t.Fatalf("DEFENSECLAW_E2E_PREFIX %q does not make valid sandbox names", prefix)
		}
		e.work = filepath.Join(work, e.prefix)
		pair = append(pair, e)
	}
	a, b := pair[0], pair[1]

	// Setup and daemon start one after the other (they share the build
	// cache); the sandboxes at the same time.
	for _, e := range pair {
		e.step("setup "+e.prefix, e.setup)
		e.step("start daemon "+e.prefix, e.startDaemon)
	}
	sbs := make([]*sandboxapi.Sandbox, len(pair))
	parallel(t, "create", pair, func(i int, e *env) { sbs[i] = e.create() })
	parallel(t, "hooks reach their own daemon", pair, func(i int, e *env) {
		e.hookReachesIngress(sbs[i])
		other := pair[1-i]
		if list, err := other.api.List(other.ctx(30 * time.Second)); err != nil ||
			slices.ContainsFunc(list, func(s sandboxapi.Sandbox) bool { return s.Name == sbs[i].Name }) {
			e.t.Fatalf("the other daemon lists %v (%v); it must not know %s", names(list), err, sbs[i].Name)
		}
		if got, err := other.api.Get(other.ctx(30*time.Second), sbs[i].Name); err == nil {
			e.t.Fatalf("the other daemon knows %s: %+v", sbs[i].Name, got.Hooks)
		}
	})
	a.t.Logf("ingress ports: %s %d, %s %d", a.prefix, a.ingressPort(), b.prefix, b.ingressPort())
	parallel(t, "delete", pair, func(i int, e *env) { e.deleteSandbox(sbs[i]) })
}

// parallel runs fn for every env at once, each as a subtest of t, and
// stops t when any failed (subtests may run concurrently; FailNow must not
// be called off the test's own goroutine).
func parallel(t *testing.T, name string, envs []*env, fn func(i int, e *env)) {
	t.Helper()
	ok := make([]bool, len(envs))
	var wg sync.WaitGroup
	for i, e := range envs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok[i] = t.Run(name+" "+e.prefix, func(st *testing.T) {
				prev := e.t
				e.t = st
				defer func() { e.t = prev }()
				fn(i, e)
			})
		}()
	}
	wg.Wait()
	if slices.Contains(ok, false) {
		t.FailNow()
	}
}
