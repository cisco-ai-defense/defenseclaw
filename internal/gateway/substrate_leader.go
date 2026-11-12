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
	"net/http"
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

// substrateLLMProxy is the sidecar's live guardrail proxy, for /llm.
func (s *Sidecar) substrateLLMProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := s.proxySnapshot()
		if p == nil {
			writeSubstrateRefusal(w, http.StatusServiceUnavailable, "guardrail_proxy_unavailable")
			return
		}
		p.SubstrateHandler().ServeHTTP(w, r)
	})
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
