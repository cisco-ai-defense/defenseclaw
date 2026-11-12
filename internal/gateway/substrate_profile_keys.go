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
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

// substrateMinExposedValue keeps short values from matching everywhere (the
// callout's minExactValueLen).
const substrateMinExposedValue = 8

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
			if v := strings.TrimSpace(string(data)); len(v) >= substrateMinExposedValue {
				out[name] = v
			}
		}
		return out
	}
}

// substrateExposedValueIn returns the name of the first exposed value found
// in body: as is, JSON-escaped (a prompt is a JSON string), base64
// (standard and URL alphabets, padded or not) or URL-encoded, the callout's
// forms plus the JSON one.
func substrateExposedValueIn(body []byte, values map[string]string) (string, bool) {
	text := string(body)
	for _, name := range slices.Sorted(maps.Keys(values)) {
		for _, form := range substrateValueForms(values[name]) {
			if strings.Contains(text, form) {
				return name, true
			}
		}
	}
	return "", false
}

func substrateValueForms(v string) []string {
	b := []byte(v)
	escaped, _ := json.Marshal(v)
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{v, strings.Trim(string(escaped), `"`), base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b), base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(v), url.PathEscape(v)} {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
