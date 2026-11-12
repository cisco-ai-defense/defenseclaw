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

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Wiring of the Agent Substrate listeners into the sidecar (serve
// --substrate, role gateway). The sidecar runs as on a host, with no
// connector of its own; its API server also serves the actor and admin
// listeners, and the actor listener's /llm route uses the sidecar's
// guardrail proxy as it is at each call (the proxy restarts with the
// guardrail).

// SubstrateBuilder completes a SubstrateConfig for an API server (it is
// called each time the API server starts).
type SubstrateBuilder func(api *APIServer, llmProxy http.Handler) (SubstrateConfig, error)

// SetSubstrate makes the sidecar serve the Substrate listeners with the
// API server.
func (s *Sidecar) SetSubstrate(build SubstrateBuilder) {
	s.substrateBuild = build
}

// substrateLLMProxy is the guardrail proxy of /llm: the sidecar's live one
// when a connector runs it, else one the Substrate gateway keeps for actors
// alone. A cluster gateway has no host connector, so the sidecar's own
// guardrail boot stays idle; the actor proxy is built from the same
// guardrail config, rule pack, judge and stores, and binds no port (the
// actor listener is its only entry).
func (s *Sidecar) substrateLLMProxy() http.Handler {
	var (
		once  sync.Once
		own   *GuardrailProxy
		owner error
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := s.proxySnapshot()
		if p == nil {
			once.Do(func() { own, owner = s.newSubstrateGuardrailProxy() })
			p = own
		}
		if p == nil {
			if owner != nil {
				fmt.Fprintf(os.Stderr, "[substrate] guardrail proxy for actors: %v\n", owner)
			}
			writeSubstrateRefusal(w, http.StatusServiceUnavailable, "guardrail_proxy_unavailable")
			return
		}
		p.SubstrateHandler().ServeHTTP(w, r)
	})
}

func (s *Sidecar) newSubstrateGuardrailProxy() (*GuardrailProxy, error) {
	cfg := s.currentConfig()
	if cfg == nil {
		return nil, errors.New("no configuration")
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	// The token authenticates nothing here (actor calls are authenticated
	// by the actor listener); the proxy refuses to start without one.
	p, err := NewGuardrailProxy(&cfg.Guardrail, &cfg.CiscoAIDefense, s.logger, s.health, s.store, cfg.DataDir,
		hex.EncodeToString(token), s.notify, s.activeRulePack(), cfg.ResolveLLM("guardrail.judge"), nil)
	if err != nil {
		return nil, err
	}
	p.SetSecureClientIntegration(cfg.SecureClientIntegration())
	p.SetModelRouter(s.modelRouter)
	p.SetDefaultPolicyID(cfg.Guardrail.Mode)
	p.SetHILTApprovalManager(s.hilt)
	if webhooks := s.webhooksSnapshot(); webhooks != nil {
		p.SetWebhookDispatcher(webhooks)
	}
	if judge := s.sharedJudge(); judge != nil {
		p.SetJudge(judge)
	}
	return p, nil
}

// runWithSubstrate runs serveAPI and the Substrate listeners together;
// either ending ends both.
func (s *Sidecar) runWithSubstrate(ctx context.Context, api *APIServer, serveAPI func(context.Context) error) error {
	cfg, err := s.substrateBuild(api, s.substrateLLMProxy())
	if err != nil {
		return err
	}
	if err := api.SetSubstrate(cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, run := range []func(context.Context) error{serveAPI, api.RunSubstrate} {
		wg.Add(1)
		go func(run func(context.Context) error) {
			defer wg.Done()
			errs <- run(ctx)
		}(run)
	}
	first := <-errs
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(substrateShutdownTimeout + 5*time.Second):
	}
	return first
}
