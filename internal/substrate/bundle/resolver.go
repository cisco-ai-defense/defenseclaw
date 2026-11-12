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
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// LoadAnchorsFile reads bundle-anchors.json. A Secret volume serves the
// file through a symlink the kubelet swaps atomically, so the link is
// followed (the enterprise reader refuses links on a laptop, where the
// file's owner is what makes it trusted; here it is the Secret's RBAC).
func LoadAnchorsFile(path string) (*eb.Anchors, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, &eb.Error{Code: eb.CodeAnchorMissing, Path: eb.AnchorsName, Detail: "no trust anchor file at " + path + "; mount the admin bundle-anchors Secret"}
	}
	if err != nil {
		return nil, &eb.Error{Code: eb.CodeAnchorInsecure, Path: eb.AnchorsName, Detail: "cannot open the trust anchor file"}
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, eb.MaxAnchorsBytes+1))
	if err != nil {
		return nil, &eb.Error{Code: eb.CodeAnchorInvalid, Path: eb.AnchorsName, Detail: "cannot read the trust anchor file"}
	}
	return eb.DecodeAnchors(raw)
}

// Resolver is the controller's ProfileResolver in bundle mode: an actor in
// an atespace a stage covers resolves against config.yaml with the stage's
// active bundle layered over it; any other actor against config.yaml.
type Resolver struct {
	base *controller.ConfigResolver

	mu    sync.RWMutex
	snap  *Snapshot
	cache map[string]*controller.ConfigResolver // by manifest SHA-256
	baseC *config.Config
}

var (
	_ controller.ProfileResolver = (*Resolver)(nil)
	_ controller.AtespaceLister  = (*Resolver)(nil)
)

// NewResolver returns a resolver over config.yaml with no bundle yet.
func NewResolver(base *config.Config) *Resolver {
	return &Resolver{base: &controller.ConfigResolver{Config: base}, baseC: base, cache: map[string]*controller.ConfigResolver{}}
}

// Set installs a snapshot (Manager.Refresh calls it).
func (r *Resolver) Set(s *Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap = s
	keep := map[string]bool{}
	for _, ap := range r.applied() {
		keep[ap.Record.ManifestSHA256] = true
		if _, ok := r.cache[ap.Record.ManifestSHA256]; !ok {
			r.cache[ap.Record.ManifestSHA256] = &controller.ConfigResolver{Config: ap.Config}
		}
	}
	for k := range r.cache {
		if !keep[k] {
			delete(r.cache, k)
		}
	}
}

func (r *Resolver) applied() []*Applied {
	if r.snap == nil {
		return nil
	}
	var out []*Applied
	if r.snap.all != nil {
		out = append(out, r.snap.all)
	}
	for _, ap := range r.snap.byAtespace {
		out = append(out, ap)
	}
	return out
}

// For returns the bundle applied to atespace, nil for config.yaml alone.
func (r *Resolver) For(atespace string) *Applied {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snap.For(atespace)
}

// Resolve implements controller.ProfileResolver.
func (r *Resolver) Resolve(reg controller.Registration, launcher bool) (controller.Resolution, error) {
	r.mu.RLock()
	res := r.base
	if ap := r.snap.For(reg.Atespace); ap != nil {
		res = r.cache[ap.Record.ManifestSHA256]
	}
	r.mu.RUnlock()
	return res.Resolve(reg, launcher)
}

// ManagedAtespaces implements controller.AtespaceLister: config.yaml's and
// every atespace a stage names (and the exact names its bundles list).
func (r *Resolver) ManagedAtespaces() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := map[string]bool{}
	for _, ns := range r.base.ManagedAtespaces() {
		set[ns] = true
	}
	if r.snap != nil {
		for _, ns := range r.snap.Atespaces {
			set[ns] = true
		}
	}
	for _, ap := range r.applied() {
		for _, ns := range r.cache[ap.Record.ManifestSHA256].ManagedAtespaces() {
			set[ns] = true
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// Event types the manager emits.
const (
	EventApplied    = "sandbox.bundle.applied"
	EventRefused    = "sandbox.bundle.refused"
	EventUnverified = "sandbox.bundle.unverified"
	EventActive     = "sandbox.bundle.active"
)

// Manager keeps a Resolver current: it applies the GitOps inbox, then
// re-verifies every stage's active bundle against the current anchors.
type Manager struct {
	Store    *Store
	Resolver *Resolver
	// Inbox is the inbox ConfigMap name; empty skips the inbox.
	Inbox    string
	Interval time.Duration
	Sink     controller.Sink

	mu       sync.Mutex
	active   map[string]string // stage -> manifest SHA-256 last reported
	problems map[string]string // stage -> code last reported
}

func (m *Manager) emit(ev controller.Event) {
	if m.Sink != nil {
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}
		m.Sink.Emit(ev)
	}
}

// Refresh runs one pass. On a storage error the resolver keeps its last
// snapshot and the error is returned.
func (m *Manager) Refresh(ctx context.Context) error {
	var errs []error
	if m.Inbox != "" {
		rcs, err := m.Store.SyncInbox(ctx, m.Inbox)
		for _, rc := range rcs {
			ev := controller.Event{Type: EventApplied, Severity: controller.SeverityInfo,
				Message: fmt.Sprintf("inbox bundle %s version %d %s for stage %s", rc.BundleID, rc.Version, rc.Result, rc.Stage),
				Detail:  map[string]any{"stage": rc.Stage, "bundle_id": rc.BundleID, "version": rc.Version, "result": rc.Result, "manifest_sha256": rc.ManifestSHA256}}
			if rc.Result == ResultRefused {
				ev.Type, ev.Severity = EventRefused, controller.SeverityAlert
				ev.Message += ": " + rc.Error
				ev.Detail["code"] = rc.Code
			}
			m.emit(ev)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("bundle inbox: %w", err))
		}
	}
	snap, problems, err := m.Store.Load(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("bundle state: %w", err))...)
	}
	m.Resolver.Set(snap)
	m.report(snap, problems)
	return errors.Join(errs...)
}

func (m *Manager) report(snap *Snapshot, problems []Problem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.active, m.problems = map[string]string{}, map[string]string{}
	}
	now := map[string]*Applied{}
	if snap.all != nil {
		now[StageAll] = snap.all
	}
	for _, ap := range snap.byAtespace {
		now[ap.Stage] = ap
	}
	for stage, ap := range now {
		if m.active[stage] == ap.Record.ManifestSHA256 {
			continue
		}
		m.active[stage] = ap.Record.ManifestSHA256
		delete(m.problems, stage)
		m.emit(controller.Event{Type: EventActive, Severity: controller.SeverityInfo,
			Message: fmt.Sprintf("stage %s enforces bundle %s version %d", stage, ap.Record.BundleID, ap.Record.Version),
			Detail: map[string]any{"stage": stage, "bundle_id": ap.Record.BundleID, "version": ap.Record.Version,
				"manifest_sha256": ap.Record.ManifestSHA256, "key_id": ap.Record.KeyID, "profiles": ap.Policy.profileNames()}})
	}
	for _, p := range problems {
		delete(m.active, p.Stage)
		if m.problems[p.Stage] == p.Code {
			continue
		}
		m.problems[p.Stage] = p.Code
		m.emit(controller.Event{Type: EventUnverified, Severity: controller.SeverityAlert,
			Message: "stage " + p.Stage + " bundle no longer verifies; its atespaces fall back to config.yaml: " + p.Error,
			Detail:  map[string]any{"stage": p.Stage, "code": p.Code}})
	}
	for stage := range m.active {
		if _, ok := now[stage]; !ok && !slices.ContainsFunc(problems, func(p Problem) bool { return p.Stage == stage }) {
			delete(m.active, stage)
		}
	}
}

// Start runs the first refresh, retrying for up to a minute, so the
// controller never writes a policy from config.yaml alone for an atespace
// a bundle covers; then it refreshes every Interval until ctx ends.
func (m *Manager) Start(ctx context.Context) error {
	var err error
	for i := range 12 {
		if err = m.Refresh(ctx); err == nil {
			break
		}
		if i == 11 {
			return fmt.Errorf("bundle mode: the first refresh failed: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	go func() {
		interval := m.Interval
		if interval <= 0 {
			interval = config.DefaultSubstrateBundleRefresh
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.Refresh(ctx); err != nil && ctx.Err() == nil {
					m.emit(controller.Event{Type: controller.EventWarning, Severity: controller.SeverityWarn, Message: err.Error()})
				}
			}
		}
	}()
	return nil
}
