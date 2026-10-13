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
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// maxConfigChangePaths bounds the paths one config.change.applied event
// lists; the event also carries the total.
const maxConfigChangePaths = 64

// unattributedConfigActor is the actor of a config.change.applied event that
// covers more than one generation (GAP-0318).
const unattributedConfigActor = "unattributed"

// configChangeActivity describes an applied config.yaml change for the audit
// trail (spec section 3, step 7): who wrote it (the actor
// config.generation.json recorded for exactly these bytes, such as
// cli:<os-user>; for a signed bundle, the local OS actor and bundle principal),
// the changed paths, the config generation, the sha256 of the
// applied file and the paths that still need a gateway restart. Values are
// never recorded. previous is the file the last generation was built from;
// without it the changed top-level sections stand in for the paths. ok is
// false when no writer recorded these bytes (a Secure Client host, a missing
// state file), and the caller keeps its plain config-update action.
//
// config.generation.json keeps only the last generation, so the event names
// its writer only when it is the one generation since last, the generation
// the gateway applied before (lastKnown). Generations coalesced by the reload
// debounce, or written while reloads were rejected, carry the paths of other
// writers too: that event says unattributed and gives the generation range
// and the last writer instead (GAP-0318). generation is the applied one.
func configChangeActivity(path string, previous, raw []byte, sections, effectiveRestart []string, last uint64, lastKnown bool) (in audit.ActivityInput, generation uint64, ok bool) {
	state, err := configwrite.ReadGenerationState(path)
	sum := configwrite.SHA256Hex(raw)
	if err != nil || strings.TrimSpace(state.Actor) == "" ||
		!strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), sum) {
		return audit.ActivityInput{}, 0, false
	}
	// A bundle can advance the signed policy generation with unchanged YAML
	// bytes (for example a changed custom pack). Ordinary asset rebuilds must
	// never inherit the previous config writer's identity.
	if len(previous) > 0 && bytes.Equal(previous, raw) &&
		(!lastKnown || state.Generation <= last || state.BundleID == "") {
		return audit.ActivityInput{}, 0, false
	}
	paths := sections
	if len(previous) > 0 {
		if changed, err := configwrite.ChangedPaths(previous, raw); err == nil && len(changed) > 0 {
			paths = changed
		}
	}
	// The raw YAML diff supplies precise audit paths, but its parent paths can
	// classify a whole section as restart-required. The gateway's effective
	// config diff is the authority on whether this apply needs a restart.
	restart := effectiveRestart
	if restart == nil {
		restart = []string{}
	}
	total := len(paths)
	if total > maxConfigChangePaths {
		paths = paths[:maxConfigChangePaths]
	}
	diff := make([]audit.ActivityDiffEntry, len(paths))
	for i, changed := range paths {
		diff[i] = audit.ActivityDiffEntry{Path: changed, Op: "replace"}
	}
	actor, bundleID, bundleVersion, signerKeyID, summary := state.Actor, state.BundleID, state.BundleVersion, state.SignerKeyID, configwrite.BundleChangeSummary(state)
	if state.TransactionBundleID != "" && configwrite.IsPrincipalActor(state.TransactionActor) {
		actor, bundleID, bundleVersion = state.TransactionActor, state.TransactionBundleID, state.TransactionBundleVersion
		signerKeyID, summary = state.TransactionSignerKeyID, state.TransactionSummary
	}
	bundlePrincipal := bundleID != "" && configwrite.IsPrincipalActor(actor)
	principal := ""
	if bundlePrincipal && state.LocalActor != "" {
		principal, actor = actor, state.LocalActor
	}
	in = audit.ActivityInput{
		Actor:      actor,
		Principal:  principal,
		Action:     audit.ActionConfigUpdate,
		TargetType: "config",
		TargetID:   filepath.Base(path),
		Reason:     state.Reason,
		After: map[string]any{
			"config_generation": state.Generation,
			"config_sha256":     sum,
			"changed_paths":     total,
			"restart_required":  restart,
		},
		Diff:     diff,
		Severity: "INFO",
	}
	if bundleID != "" {
		in.Bundle = &audit.PolicyBundle{ID: bundleID, Version: bundleVersion,
			SignerKeyID: signerKeyID, ChangeSummary: summary}
		in.After["bundle_id"], in.After["bundle_version"] = bundleID, bundleVersion
		in.After["signer_key_id"] = signerKeyID
		in.After["generation_before"] = last
		in.After["generation_after"] = state.Generation
		in.After["restart"] = len(restart) > 0
	}
	if lastKnown && (state.Generation > last+1 || state.Generation < last) {
		// A coalesced bundle is still the signed final policy. Its
		// principal and manifest identify that final apply, while the
		// aggregate path diff could include another writer's changes.
		// Keep the bundle identity but omit that diff. Other coalesced
		// writes retain their unattributed audit behavior.
		bundleFinal := state.Generation > last+1 && in.Bundle != nil && bundlePrincipal
		if bundleFinal {
			in.Diff = nil
			in.After["changed_paths"] = 0
			in.After["restart_required"] = []string{}
			in.After["coalesced"] = true
		} else {
			in.Bundle = nil
			in.Principal = ""
			delete(in.After, "bundle_id")
			delete(in.After, "bundle_version")
			delete(in.After, "signer_key_id")
			in.Actor = unattributedConfigActor
			in.After["last_actor"] = state.Actor
		}
		if state.Generation > last {
			in.After["first_generation"] = last + 1
			if !bundleFinal {
				in.Reason = fmt.Sprintf("generations %d-%d applied together; last writer %s", last+1, state.Generation, state.Actor)
			}
		} else {
			if !bundleFinal {
				in.Reason = fmt.Sprintf("generation %d follows %d (the generation record was reset); last writer %s", state.Generation, last, state.Actor)
			}
		}
	}
	return in, state.Generation, true
}

// awaitRecordedConfigBytes covers the small interval in a lifecycle write
// between the config.yaml rename and its config.generation.json rename. The
// gateway service may read the generation record but cannot open the
// root-owned writer lock. Only standalone managed reloads wait, and only
// when the record does not yet describe the YAML that was just applied.
func awaitRecordedConfigBytes(ctx context.Context, path string, raw []byte) {
	if _, ok := appliedGenerationOf(path, raw); ok {
		return
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
			if _, ok := appliedGenerationOf(path, raw); ok {
				return
			}
		}
	}
}

// appliedGenerationOf returns the generation config.generation.json records
// for raw, so the next applied change can tell whether it is the only
// generation since (GAP-0318).
func appliedGenerationOf(path string, raw []byte) (uint64, bool) {
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || !strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(raw)) {
		return 0, false
	}
	return state.Generation, true
}
