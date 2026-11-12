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

package controller

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// NoAttestor attests nothing. It stands in until the gateway carries the
// attestation verifier: with require_attested_templates on (the default)
// every actor is refused, which is the fail-closed answer.
type NoAttestor struct{}

func (NoAttestor) Attest(context.Context, *ateapi.ActorTemplate) (Attestation, error) {
	return Attestation{Reason: "this gateway has no template attestation verifier"}, nil
}

// NoActivity reports no activity source: with no CPU sample nothing is ever
// idle, so idle suspend never fires.
type NoActivity struct{}

func (NoActivity) LastActivity(string) (time.Time, bool) { return time.Time{}, false }
func (NoActivity) PendingAsk(string) bool                { return false }
func (NoActivity) CPU(string) (float64, time.Time, bool) { return 0, time.Time{}, false }

// JSONSink writes one JSON object per event (the pod log).
type JSONSink struct {
	mu sync.Mutex
	W  io.Writer
}

func (s *JSONSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = json.NewEncoder(s.W).Encode(e)
}
