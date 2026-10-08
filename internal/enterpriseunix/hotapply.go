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

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// hotApplyTimeout bounds how long a gateway that kept running through a
// config change gets to report the policy the new config computes to. After
// it the lifecycle restarts the gateway, as it did for every change.
const hotApplyTimeout = 20 * time.Second

// hotConfigApply reports whether this ensure changes nothing but config.yaml
// keys that the running gateway applies as a generation swap (P0 spec
// section 4). Then the gateway keeps running through the change: it reloads
// the file itself, its policy generation advances, and
// defenseclaw.policy.generation on decisions orders the two configs. A
// restart starts the in-process counter over at 1 every time.
//
// The change is hot when the version, channel, binaries, unit files,
// drop-ins, descriptor, secrets and machine policy all stay as they are, no
// changed key is restart-required, and the gateway is up and publishes its
// effective policy digest. Anything else, and every repair, upgrade and
// install, stops and starts the services. A rule pack switch (rule_pack, a
// custom_packs entry added, replaced or removed) is hot: the gateway builds
// the packs into each generation (GAP-0550).
func (l *lifecycle) hotConfigApply(ctx context.Context, record *Deployment, p *plan, adopting *adoption) bool {
	env := l.env
	if record == nil || adopting != nil || l.opts.Action != ActionEnsure || l.opts.NoStart || len(p.stale) > 0 ||
		p.config.Migration != nil || p.config.SHA == record.ConfigSHA256 ||
		p.version != record.ProductVersion || p.channel != record.Channel || p.secretsSHA != record.SecretsSHA256 ||
		!slices.Equal(p.machinePolicy, record.MachinePolicyConnectors) {
		return false
	}
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		if file.Path == env.Layout.ConfigPath {
			continue
		}
		if current, _ := sha256File(env.P(file.Path)); current != file.SHA {
			return false
		}
	}
	if p.channel == ChannelPackage {
		for name, digest := range p.payload.Digests {
			if record.Files[filepath.Join(env.Layout.BinDir, name)] != digest {
				return false
			}
		}
		for path, digest := range p.packageUnits {
			if record.Files[path] != digest {
				return false
			}
		}
	}
	previous, err := readBounded(env.committedConfigPath(), maxInputBytes)
	if err != nil || sha256Bytes(previous) != record.ConfigSHA256 {
		return false
	}
	// A file that differs only in bytes (a comment, CRLF, a BOM, quoting)
	// changes no key: it is applied hot like any reloadable change, so the
	// gateway is not restarted for a policy that stays the same (GAP-0545).
	changed, err := configwrite.ChangedPaths(previous, p.config.Raw)
	if err != nil || len(configwrite.ManagedRestartRequired(changed)) > 0 {
		return false
	}
	gateway, ok := gatewayUnitOf(env.Services.Units())
	if !ok || !env.Services.Active(ctx, gateway) {
		return false
	}
	body, err := l.gatewayHealth(ctx, gateway, l.serviceUID)
	return err == nil && gatewayPolicyDigest(body) != ""
}

func gatewayUnitOf(units []Unit) (Unit, bool) {
	for _, unit := range units {
		if unit.Kind == "gateway" {
			return unit, true
		}
	}
	return Unit{}, false
}

// settleHotGateway waits for the gateway that kept running through a config
// change to report the effective policy the installed config computes to,
// which is the generation swap. A gateway that does not (it keeps a key at
// its running value, refused the change, or cannot be asked) is restarted,
// which loads the config whole.
func (l *lifecycle) settleHotGateway(ctx context.Context, gateway Unit) error {
	env := l.env
	if want, _, ok := l.computePolicy(ctx); ok {
		deadline := env.Now().Add(min(hotApplyTimeout, env.ReadyTimeout))
		for {
			if body, err := l.gatewayHealth(ctx, gateway, l.serviceUID); err == nil && gatewayPolicyDigest(body) == want {
				l.gatewayKeptRunning = true
				l.noteChange("applied the config change in the running %s; it was not restarted", gateway.Name)
				return nil
			}
			if !env.Now().Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(env.PollInterval):
			}
		}
	}
	if err := restartUnit(ctx, env.Services, gateway); err != nil {
		return fmt.Errorf("restart %s: %w", gateway.Name, err)
	}
	return l.waitGatewayReady(ctx, gateway)
}
