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
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/exactvalue"
)

// The profile runtime keys the cluster gateway reads (PLAN §7.3): an
// actor's floor is substrate.admin tightened by its registration's profile,
// as the controller computes it (controller.ConfigResolver).

// substrateActorFloor is the sandbox floor of an actor of profile.
func substrateActorFloor(cfg *config.Config, profile string) (config.SandboxAdminConfig, error) {
	if cfg == nil {
		return config.SandboxAdminConfig{}, errors.New("no configuration")
	}
	var overlay *config.SandboxAdminConfig
	if p, ok := cfg.Guardrail.Profiles[strings.TrimSpace(profile)]; ok {
		overlay = p.Sandbox
	}
	return config.TightenSandboxAdmin(cfg.Substrate.Admin, overlay)
}

// SubstrateSandboxClassFor is the isolation class an actor of profile runs
// in: the floor's sandbox_class (substrate.admin tightened by the profile),
// never weaker than substrate.default_sandbox_class (D7). A floor that cannot
// be computed gives the cluster default; the controller refuses the actor.
func SubstrateSandboxClassFor(cfg *config.Config) func(profile string) string {
	if cfg == nil {
		return nil
	}
	return func(profile string) string {
		def := cfg.Substrate.EffectiveSandboxClass()
		floor, err := substrateActorFloor(cfg, profile)
		if err != nil {
			return def
		}
		return floor.EffectiveSandboxClass(def)
	}
}

// SubstrateUnattendedAsk is what an ask of an unattended (--task, --batch)
// actor does (D12): Queue false denies it at once; Queue true holds it for
// a person, and when Timeout passes the ask is denied.
type SubstrateUnattendedAsk struct {
	Queue   bool
	Timeout time.Duration
}

// SubstrateUnattendedAskFor is the ask rule of an unattended actor of
// profile: the floor's unattended_asks and ask_timeout, else
// substrate.unattended.asks and .ask_timeout. A floor that cannot be
// computed denies (unattended runs fail closed, D8).
func SubstrateUnattendedAskFor(cfg *config.Config, profile string) SubstrateUnattendedAsk {
	floor, err := substrateActorFloor(cfg, profile)
	if err != nil || floor.EffectiveUnattendedAsks(cfg.Substrate.EffectiveAsks()) != config.SubstrateAsksQueue {
		return SubstrateUnattendedAsk{}
	}
	return SubstrateUnattendedAsk{Queue: true, Timeout: floor.EffectiveAskTimeout(cfg.Substrate.EffectiveAskTimeout())}
}

var substrateExposedName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// SubstrateExposedValues returns, for a profile, the values of its
// actor_secrets (PLAN §7.2: values a program inside the actor may read,
// marked exposed), read from dir (one file per name, the callout's
// actor-secrets Secret mounted in the gateway too) on every call, so a
// rotation needs no restart. nil without dir. A name whose file is missing
// or shorter than 8 bytes is left out. Values never leave the gateway.
func SubstrateExposedValues(cfg *config.Config, dir string) func(profile string) map[string]string {
	if cfg == nil || strings.TrimSpace(dir) == "" {
		return nil
	}
	return func(profile string) map[string]string {
		floor, err := substrateActorFloor(cfg, profile)
		if err != nil || len(floor.ActorSecrets) == 0 {
			return nil
		}
		out := map[string]string{}
		for _, name := range floor.ActorSecrets {
			if !substrateExposedName.MatchString(name) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || len(data) > 64<<10 {
				continue
			}
			if v := strings.TrimSpace(string(data)); len(v) >= exactvalue.MinLen {
				out[name] = v
			}
		}
		return out
	}
}

// substrateExposedValueIn returns the name of the first exposed value found
// in body, in the forms the callout matches too (exactvalue.Forms: as is,
// JSON-escaped, base64, URL-encoded).
func substrateExposedValueIn(body []byte, values map[string]string) (string, bool) {
	text := string(body)
	for _, name := range slices.Sorted(maps.Keys(values)) {
		for _, form := range exactvalue.Forms(values[name]) {
			if strings.Contains(text, form) {
				return name, true
			}
		}
	}
	return "", false
}
