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
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
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
	restart, err := configwrite.ManagedConfigRestartRequired(previous, p.config.Raw, configwrite.ManagedDefaultsFor(env.Layout))
	if err != nil || len(restart) > 0 {
		return false
	}
	// Loading the SELinux module replaces the hook socket, which a gateway
	// that keeps running would no longer listen on.
	if env.selinuxModuleStale() {
		return false
	}
	// A hot change keeps the sensor helper running; one that runs another
	// Tetragon mode than the config renders must restart.
	if l.helperModeDrift(ctx, p) {
		l.helperModeRestart = true
		return false
	}
	gateway, ok := gatewayUnitOf(env.Services.Units())
	if !ok || !env.Services.Active(ctx, gateway) {
		return false
	}
	body, err := l.gatewayHealth(ctx, gateway, l.serviceUID)
	return err == nil && gatewayPolicyDigest(body) != ""
}

// installedConfigReplaced reports an in-place config.yaml that changed after
// this transaction planned it. A bundle or --config run brings its own
// config and is never superseded this way.
func (l *lifecycle) installedConfigReplaced() bool {
	if l.bundle != nil || l.planned == nil || !l.planned.configFromInstalled {
		return false
	}
	current, err := sha256File(l.env.P(l.env.Layout.ConfigPath))
	return err == nil && current != l.planned.configSHA
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
	var receipt *enterprisebundle.Receipt
	if l.bundle != nil {
		receipt = l.bundle.receipt
	}
	want, ok := l.bundlePolicyWant(ctx, receipt)
	if !ok {
		if receipt != nil {
			if err := restartUnit(ctx, env.Services, gateway); err != nil {
				return fmt.Errorf("restart %s: %w", gateway.Name, err)
			}
			return l.waitGatewayReady(ctx, gateway)
		}
		return errors.New("the installed config's effective policy digest could not be computed, so the running gateway cannot confirm the change")
	}
	var state configwrite.GenerationState
	if receipt == nil {
		var err error
		state, err = configwrite.ReadGenerationState(env.P(env.Layout.ConfigPath))
		if err != nil {
			return fmt.Errorf("read the installed config generation before confirming the gateway: %w", err)
		}
	}
	probe := func() (bool, string) {
		body, err := l.gatewayHealth(ctx, gateway, l.serviceUID)
		if err != nil {
			return false, "read gateway health: " + err.Error()
		}
		health := parseBundleHealth(body)
		// Signed bundles have their own confirmation step, which assigns the
		// bundle-specific refusal code and rolls back if a reload was rejected.
		if receipt != nil {
			if health.digest == want {
				return true, ""
			}
			return false, fmt.Sprintf("gateway reports effective policy %s, not %s of the bundle", shortDigest(health.digest), shortDigest(want))
		}
		switch {
		case health.reloadError != "":
			return false, "gateway rejected the config reload: " + health.reloadError
		case health.configState == "error":
			return false, "gateway config.state=error: " + health.configError
		case health.configGeneration != state.Generation:
			return false, fmt.Sprintf("gateway reports config generation %d, not lifecycle generation %d", health.configGeneration, state.Generation)
		case health.bundleID != state.BundleID || health.bundleVersion != state.BundleVersion:
			return false, fmt.Sprintf("gateway reports bundle %q version %d, not lifecycle bundle %q version %d", health.bundleID, health.bundleVersion, state.BundleID, state.BundleVersion)
		case health.digest != want:
			return false, fmt.Sprintf("gateway reports effective policy %s, not %s of the installed config", shortDigest(health.digest), shortDigest(want))
		default:
			return true, ""
		}
	}
	wait := func() (bool, string, error) {
		deadline := env.Now().Add(min(hotApplyTimeout, env.ReadyTimeout))
		var cause string
		for {
			if applied, reason := probe(); applied {
				return true, "", nil
			} else {
				cause = reason
			}
			if l.installedConfigReplaced() {
				// A follow-up transaction applies a newer config push.
				return false, "replaced", nil
			}
			if !env.Now().Before(deadline) {
				return false, cause, nil
			}
			select {
			case <-ctx.Done():
				return false, cause, ctx.Err()
			case <-time.After(env.PollInterval):
			}
		}
	}
	applied, cause, err := wait()
	if err != nil {
		return err
	}
	if applied {
		l.gatewayKeptRunning = true
		l.noteChange("applied the config change in the running %s; it was not restarted", gateway.Name)
		return nil
	}
	if cause == "replaced" {
		// Restarting here would apply the newer push cold (GAP-0738).
		l.gatewayKeptRunning = true
		l.noteChange("left %s running: config.yaml was replaced while it applied the previous version, and the follow-up applies the new one", gateway.Name)
		return nil
	}
	if err := restartUnit(ctx, env.Services, gateway); err != nil {
		return fmt.Errorf("restart %s: %w", gateway.Name, err)
	}
	if err := l.waitGatewayReady(ctx, gateway); err != nil {
		return err
	}
	if receipt != nil {
		return nil
	}
	applied, cause, err = wait()
	if err != nil {
		return err
	}
	if !applied && cause != "replaced" {
		return fmt.Errorf("%s restarted but did not confirm lifecycle generation %d: %s", gateway.Name, state.Generation, cause)
	}
	return nil
}

// bundlePolicyWant reuses the digest already computed while verifying a
// same-build signed bundle. Starting another gateway CLI to rebuild the same
// generation during a hot apply competes with the serving gateway for CPU and
// disk precisely while hooks must keep their deadlines. Other config changes
// and bundles whose digest could not be compared still compute it locally.
func (l *lifecycle) bundlePolicyWant(ctx context.Context, receipt *enterprisebundle.Receipt) (string, bool) {
	if receipt != nil && receipt.DigestComparable && receipt.ExpectedDigest != "" {
		wantSHA := receipt.ConfigSHA256
		if wantSHA == "" && l.bundle != nil && l.bundle.receipt == receipt {
			wantSHA = l.bundle.configSHA
		}
		if wantSHA != "" && l.env != nil {
			if installedSHA, err := sha256File(l.env.P(l.env.Layout.ConfigPath)); err == nil && installedSHA == wantSHA {
				return receipt.ExpectedDigest, true
			}
		}
	}
	digest, _, err := l.computePolicy(ctx)
	return digest, err == nil
}
