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

// Package controllerfake holds test fakes for the controller's Attestor,
// ActivitySource and Sink.
package controllerfake

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// Attestor attests templates by "<atespace>/<name>".
type Attestor struct {
	mu    sync.Mutex
	byKey map[string]controller.Attestation
	// Default is returned for templates not set (zero: not attested).
	Default controller.Attestation
}

// Set records a template's attestation.
func (a *Attestor) Set(key string, att controller.Attestation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.byKey == nil {
		a.byKey = map[string]controller.Attestation{}
	}
	a.byKey[key] = att
}

// Attest implements controller.Attestor.
func (a *Attestor) Attest(_ context.Context, t *ateapi.ActorTemplate) (controller.Attestation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if att, ok := a.byKey[ateapi.Key(ateapi.RefOf(t.GetMetadata()))]; ok {
		return att, nil
	}
	return a.Default, nil
}

// Activity is a settable ActivitySource.
type Activity struct {
	mu    sync.Mutex
	last  map[string]time.Time
	asks  map[string]bool
	cpu   map[string]float64
	cpuAt map[string]time.Time
}

func (f *Activity) init() {
	if f.last == nil {
		f.last, f.asks, f.cpu, f.cpuAt = map[string]time.Time{}, map[string]bool{}, map[string]float64{}, map[string]time.Time{}
	}
}

// Touch records activity at t.
func (f *Activity) Touch(uid string, t time.Time) {
	f.mu.Lock()
	f.init()
	f.last[uid] = t
	f.mu.Unlock()
}

// SetAsk sets or clears a pending ask.
func (f *Activity) SetAsk(uid string, pending bool) {
	f.mu.Lock()
	f.init()
	f.asks[uid] = pending
	f.mu.Unlock()
}

// SetCPU records a CPU sample.
func (f *Activity) SetCPU(uid string, cores float64, at time.Time) {
	f.mu.Lock()
	f.init()
	f.cpu[uid], f.cpuAt[uid] = cores, at
	f.mu.Unlock()
}

func (f *Activity) LastActivity(uid string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.last[uid]
	return t, ok
}

func (f *Activity) PendingAsk(uid string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.asks[uid] }

func (f *Activity) CPU(uid string) (float64, time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.cpuAt[uid]
	return f.cpu[uid], at, ok
}

// Sink records events.
type Sink struct {
	mu     sync.Mutex
	events []controller.Event
}

func (s *Sink) Emit(e controller.Event) { s.mu.Lock(); s.events = append(s.events, e); s.mu.Unlock() }

// Events returns the events of the given types (all when none).
func (s *Sink) Events(types ...string) []controller.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []controller.Event
	for _, e := range s.events {
		if len(types) == 0 {
			out = append(out, e)
			continue
		}
		for _, t := range types {
			if e.Type == t {
				out = append(out, e)
			}
		}
	}
	return out
}
