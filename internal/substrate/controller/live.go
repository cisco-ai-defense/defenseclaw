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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// Live is the part of the controller that config.yaml decides: the egress
// allow list and the other render settings, the secrets, the launcher
// atespaces, the profile resolver (assignments and profile sandbox
// sections), template admission and idle suspend. A config change replaces
// it whole at the start of the next pass, and that pass renders every
// actor's policy again from it (GAP-0276).
type Live struct {
	// Digest is the config.yaml source it came from ("" when the
	// controller has no ConfigSource); Gen its configwatch generation.
	Digest   string
	Gen      uint64
	Settings render.Settings
	Secrets  []render.Secret
	// Bindings returns the active self-service bindings of one person
	// (their OIDC subject) as secrets; nil when self_service_secrets.mode
	// is off. Only an actor bound to that person gets them.
	Bindings           func(person string) []render.Secret
	LauncherAtespaces  map[string]bool
	RequireAttestation bool
	Templates          config.SubstrateTemplatesConfig
	Attestor           Attestor
	Resolver           ProfileResolver
	IdleSuspendAfter   time.Duration
	// IdleSuspendWithoutCPU is Options.IdleSuspendWithoutCPU.
	IdleSuspendWithoutCPU bool
	// LoadedAt is when the controller put this config in force: a policy
	// write it causes measures its lag from here (GAP-0392).
	LoadedAt time.Time
	// CalloutMode is what a callout replacement does (CalloutFailClosed,
	// CalloutFailOpen or CalloutOff; "" is closed), from
	// CalloutFailModeFromConfig (GAP-0505).
	CalloutMode string
}

// ConfigSource is config.yaml as it is now (configwatch.Watcher).
type ConfigSource interface {
	Current() (*config.Config, string)
	Refresh(ctx context.Context) configwatch.Change
}

func (c *Controller) live() *Live { return c.cur.Load() }

// LiveAttestor is an Attestor that always runs the controller's attestor in
// force, for a caller that keeps it (the create path's template kit).
func (c *Controller) LiveAttestor() Attestor { return liveAttestor{c} }

type liveAttestor struct{ c *Controller }

func (a liveAttestor) Attest(ctx context.Context, tmpl *ateapi.ActorTemplate) (Attestation, error) {
	return a.c.live().Attestor.Attest(ctx, tmpl)
}

// Digest is the config.yaml digest the controller's policies come from.
func (c *Controller) Digest() string { return c.live().Digest }

// reloadConfig applies a config.yaml change before a pass (and before a
// create path's policy write): one read of the source at most every
// configwatch.DefaultInterval, so a change reaches every actor within that
// interval plus one pass. A source that does not load is reported and the
// config in force is kept.
func (c *Controller) reloadConfig(ctx context.Context) {
	if c.o.Config == nil || c.o.Live == nil {
		return
	}
	// The source is read without reloadMu: a create path waiting on a slow
	// API server read must not hold the others (GAP-0296).
	ch := c.o.Config.Refresh(ctx)
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	if ch.FetchWarning != "" {
		c.emit(Event{Type: EventWarning, Severity: SeverityWarn, Message: ch.FetchWarning})
	}
	if ch.Refused != nil {
		c.emit(Event{Type: EventConfigRefused, Severity: SeverityAlert,
			Message: "config.yaml change not applied: " + ch.Refused.Error() + "; actor policies keep the config in force",
			Detail:  map[string]any{"config_digest": c.live().Digest}})
	}
	prev := c.live().Digest
	// Only a newer generation applies: a Change read before another caller
	// applied a later one is stale, and putting it back would loosen the
	// policy again (GAP-0305).
	if ch.Config == nil || ch.Gen <= c.live().Gen || ch.Digest == prev {
		return
	}
	old := c.live()
	lv := c.o.Live(ch.Config)
	lv.Digest, lv.Gen, lv.LoadedAt = ch.Digest, ch.Gen, c.o.Now()
	c.cur.Store(&lv)
	// Atespaces the old config managed and the new one does not: a scoped
	// controller (no global viewer) lists them once more, so their actors
	// lose DefenseClaw's policy instead of dropping out of the listing with
	// it in force (GAP-0295).
	now := managedSet(&lv)
	c.mu.Lock()
	for ns := range managedSet(old) {
		if !now[ns] {
			c.retired[ns] = true
		}
	}
	// Template verdicts were reached with the old attestor, registries and
	// image lists: re-attest on the next use. Entries are expired, not
	// dropped, so a registry outage still rides out on the last good
	// verdict (GAP-0127).
	for k, ct := range c.templates {
		ct.at = time.Time{}
		c.templates[k] = ct
	}
	c.mu.Unlock()
	c.emit(Event{Type: EventConfigReloaded, Severity: SeverityInfo,
		Message: "config.yaml changed: every actor's egress policy is rendered again from it on this pass",
		Detail:  map[string]any{"config_digest": lv.Digest, "previous_digest": prev}})
}

// managedSet is the atespaces a config manages by name: the launcher ones
// and those its resolver lists.
func managedSet(lv *Live) map[string]bool {
	set := map[string]bool{}
	for ns := range lv.LauncherAtespaces {
		set[ns] = true
	}
	if l, ok := lv.Resolver.(AtespaceLister); ok {
		for _, ns := range l.ManagedAtespaces() {
			set[ns] = true
		}
	}
	return set
}

// UnattestedTemplates is how many templates of the actors the last pass
// listed carry no valid attestation now
// (defenseclaw.substrate.unattested_templates): their actors get no
// network. A template no listed actor uses no longer counts (GAP-0583).
func (c *Controller) UnattestedTemplates() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, ct := range c.templates {
		if len(c.inUse[k]) > 0 && !ct.att.Attested {
			n++
		}
	}
	return n
}
