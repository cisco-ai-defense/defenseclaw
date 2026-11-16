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

package packs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A managed computer's per-user sandbox daemon runs as the user, who cannot
// read the administrator's pack folder (0750 root:service, as ensure
// requires). The managed gateway resolves each run with the required pack's
// content and returns that content in its answer (the Effective wire form).
// The daemon installs that pack for the floor's required_pack reference
// (UseAuthorityPack). From then on, a trusted load of the reference in this
// process uses it and never reads the root-only file (GAP-0440). The floor's
// required_pack_digest pin still applies to it (fail closed).

var authorityPacks struct {
	mu    sync.RWMutex
	byRef map[string]*Pack
}

// AuthorityPack is the required pack of floor carried by a managed gateway's
// resolve answer: the pack of effective (the Effective wire form, whose
// digest it checks), or required (RequiredPackContent) when the run uses a
// stricter pack in its place (GAP-0563). It is nil when the floor requires
// no custom pack. An answer without the pack, or with a pack that does not
// match the floor's pin, fails.
func AuthorityPack(effective, required []byte, floor config.OpenShellAdminConfig) (*Pack, error) {
	ref := strings.TrimSpace(floor.RequiredPack)
	if ref == "" || IsBuiltin(ref) {
		return nil, nil
	}
	var pack Pack
	if len(required) > 0 {
		if err := json.Unmarshal(required, &pack); err != nil {
			return nil, fmt.Errorf("sandbox policy: the required pack in the managed gateway's answer: %w", err)
		}
		if pack.Builtin {
			return nil, errors.New("sandbox policy: the managed gateway's answer does not carry the required pack")
		}
	} else {
		var eff Effective
		if err := json.Unmarshal(effective, &eff); err != nil {
			return nil, err
		}
		if !eff.requiredPack || eff.Pack == nil || eff.Pack.Builtin {
			return nil, errors.New("sandbox policy: the managed gateway's answer does not carry the required pack")
		}
		pack = *eff.Pack
	}
	if err := checkAuthorityPack(&pack, floor); err != nil {
		return nil, err
	}
	return &pack, nil
}

// UseAuthorityPack makes pack (an AuthorityPack) stand in for floor's
// required pack in this process's trusted loads. A pack that does not match
// the floor's pin is refused.
func UseAuthorityPack(floor config.OpenShellAdminConfig, pack *Pack) error {
	ref := strings.TrimSpace(floor.RequiredPack)
	if ref == "" || IsBuiltin(ref) || pack == nil {
		return nil
	}
	p := *pack
	if err := checkAuthorityPack(&p, floor); err != nil {
		return err
	}
	authorityPacks.mu.Lock()
	defer authorityPacks.mu.Unlock()
	if authorityPacks.byRef == nil {
		authorityPacks.byRef = map[string]*Pack{}
	}
	authorityPacks.byRef[ref] = &p
	return nil
}

// generationPacks are the custom required packs the managed gateway loaded
// with its live configuration generation (UseGenerationPacks), by reference
// and pack folder.
var generationPacks struct {
	mu    sync.RWMutex
	byKey map[generationPackKey]*Pack
}

type generationPackKey struct{ ref, packDir string }

// UseGenerationPacks makes loaded (packs by their required_pack reference,
// read from packDir with LoadGenerationPack) the packs this process's
// trusted loads of those references use, in place of every earlier set.
// The managed gateway calls it when it publishes a configuration
// generation, so a sandbox pack is read once per generation: an edit of
// the file takes effect with the next generation (the restart ensure
// makes), and an edit that does not load, which fails that generation's
// build, never replaces the last good pack (GAP-0229).
func UseGenerationPacks(packDir string, loaded map[string]*Pack) {
	next := make(map[generationPackKey]*Pack, len(loaded))
	for ref, pack := range loaded {
		if pack != nil {
			p := *pack
			next[generationPackKey{ref: strings.TrimSpace(ref), packDir: packDir}] = &p
		}
	}
	generationPacks.mu.Lock()
	defer generationPacks.mu.Unlock()
	generationPacks.byKey = next
}

// generationPack is the pack UseGenerationPacks installed for ref in
// packDir, or nil.
func generationPack(ref, packDir string) *Pack {
	generationPacks.mu.RLock()
	defer generationPacks.mu.RUnlock()
	if p := generationPacks.byKey[generationPackKey{ref: strings.TrimSpace(ref), packDir: packDir}]; p != nil {
		c := *p
		return &c
	}
	return nil
}

// authorityPack is the pack UseAuthorityPack installed for ref, or nil.
func authorityPack(ref string) *Pack {
	authorityPacks.mu.RLock()
	defer authorityPacks.mu.RUnlock()
	if p := authorityPacks.byRef[strings.TrimSpace(ref)]; p != nil {
		c := *p
		return &c
	}
	return nil
}

// checkAuthorityPack holds pack to floor's pin and restores what its wire
// form leaves out: the egress.allow entries of a built-in ancestor
// (builtinAllow), which must be this build's built-in pack.
func checkAuthorityPack(pack *Pack, floor config.OpenShellAdminConfig) error {
	if pin := strings.TrimSpace(floor.RequiredPackDigest); pin != "" && pack.Digest != pin {
		return fmt.Errorf("sandbox policy: openshell.admin.required_pack %s has digest %s, not the pinned openshell.admin.required_pack_digest %s",
			pack.Name, pack.Digest, pin)
	}
	pack.builtinAllow = nil
	for _, link := range pack.Chain {
		if !link.Builtin {
			continue
		}
		base, err := Builtin(link.Name)
		if err != nil {
			return err
		}
		if base.Digest != link.Digest {
			return fmt.Errorf("sandbox policy: the required pack %s extends built-in pack %s %s, which this build does not have",
				pack.Name, link.Name, link.Digest)
		}
		pack.builtinAllow = base.Egress.Allow
		break
	}
	return nil
}
