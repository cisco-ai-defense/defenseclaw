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

package extproc

import (
	"context"
	"errors"
	"testing"
)

// TestChainFailureModeManaged is GAP-0090 per D8: on a managed install auto
// means closed for every actor and open is refused; on an OSS install auto
// alerts for an interactive actor.
func TestChainFailureModeManaged(t *testing.T) {
	ctx := context.Background()
	down := fakeChecker{err: errors.New("leader down")}

	// managed + auto: an interactive actor's unchecked step is refused.
	h := newHarness(t, func(c *Config, o *Options) { c.Managed = true; o.ChainChecker = down })
	if h.eng.cfg.Chain.FailureMode != ChainAuto {
		t.Fatalf("default chain.failure_mode %q", h.eng.cfg.Chain.FailureMode)
	}
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow || v.Category != CategoryChainUnchecked || !v.Retryable {
		t.Fatalf("managed/auto: %+v", v)
	}

	// managed + open: refused at load, from the file and in code.
	if _, err := ParseConfig([]byte("managed: true\nchain:\n  failure_mode: open\n")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("managed/open accepted: %v", err)
	}
	cfg := &Config{Managed: true, Chain: ChainConfig{FailureMode: FailureOpen}}
	if _, err := NewEngine(Options{Config: cfg}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("managed/open engine: %v", err)
	}
	if _, err := ParseConfig([]byte("managed: true\nchain:\n  failure_mode: closed\n")); err != nil {
		t.Fatalf("managed/closed refused: %v", err)
	}

	// OSS + auto: an interactive actor's unchecked step is an alert.
	h = newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = down })
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || !v.Alert {
		t.Fatalf("oss/auto: %+v", v)
	}
	// OSS + open stays allowed.
	if _, err := ParseConfig([]byte("chain:\n  failure_mode: open\n")); err != nil {
		t.Fatalf("oss/open refused: %v", err)
	}
}
