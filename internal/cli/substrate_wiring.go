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

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// newSubstrateController builds the controller the controller deployment
// runs and the gateway's create path uses for EnsurePolicy: the same
// admission, profiles and render in both. With src, a config.yaml change
// replaces the config-decided options (substrateControllerLive) before the
// next pass or create (GAP-0276).
func newSubstrateController(cfg *config.Config, client ateapi.Client, reg controller.Registry,
	act controller.ActivitySource, cpu controller.CPUSource, sink controller.Sink, idleAfter bool,
	resets controller.ResetStore, namespace string, resolver controller.ProfileResolver, src controller.ConfigSource) (*controller.Controller, error) {
	if act == nil {
		act = controller.NoActivity{}
	}
	// Without a CPU source (the chart wires no usage receiver) idle suspend
	// rests on the activity feed (GAP-0465): an attached actor is not idle
	// unless substrate.idle_suspend_without_cpu says so (GAP-0534).
	live := substrateControllerLiveFunc(cfg, idleAfter, resolver, sink)
	lv := live(cfg)
	o := controller.Options{
		Client: client, Attestor: lv.Attestor, Activity: act, CPU: cpu,
		Registry: reg, Resolver: lv.Resolver,
		Sink:     sink,
		Settings: lv.Settings, Secrets: lv.Secrets, Bindings: lv.Bindings,
		LauncherAtespaces: lv.LauncherAtespaces, RequireAttestation: lv.RequireAttestation, Templates: lv.Templates,
		KitVersion: appVersion, IdleSuspendAfter: lv.IdleSuspendAfter, IdleSuspendWithoutCPU: lv.IdleSuspendWithoutCPU,
		Resets: resets, Namespace: namespace, CalloutMode: lv.CalloutMode,
	}
	if src != nil {
		o.Config, o.Live = src, live
	}
	return controller.New(o)
}

// substrateControllerLive is the part of the controller config.yaml
// decides (controller.Live), built the same way at start and on every
// config change. resolver, when set (bundle mode), is kept as it is.
func substrateControllerLive(cfg *config.Config, idle bool, resolver controller.ProfileResolver, sink controller.Sink) controller.Live {
	sub := cfg.Substrate
	if resolver == nil {
		resolver = &controller.ConfigResolver{Config: cfg}
	}
	var after time.Duration
	if idle {
		after = sub.EffectiveIdleSuspendAfter()
	}
	// Both the controller and the create path admit only attested,
	// digest-pinned templates (GAP-0053): the anchors come from the
	// admin-only Secret mount and are re-read on change; a missing file
	// refuses every template (fail closed).
	attestor := controller.Attestor(controller.NoAttestor{})
	if sub.AttestationRequired() {
		ver, anchors := controller.VerifierFromConfig(sub.Templates)
		if _, err := anchors.Get(); err != nil {
			sink.Emit(controller.Event{Type: controller.EventWarning, Severity: controller.SeverityAlert,
				Message: err.Error() + ": every template is refused until the trust anchors are mounted"})
		}
		attestor = &controller.TemplateAttestor{Verifier: ver, VolumeImages: sub.Templates.VolumeImages, Registries: controller.AllowedRegistries(sub.Templates)}
	}
	return controller.Live{
		Settings: controller.SettingsFromConfig(cfg), Secrets: controller.SecretsFromConfig(cfg),
		Bindings:          controller.BindingsFrom(substrateBindingStore(cfg), cfg, time.Now),
		LauncherAtespaces: controller.LauncherSet(cfg), RequireAttestation: sub.AttestationRequired(), Templates: sub.Templates,
		Attestor: attestor, Resolver: resolver, IdleSuspendAfter: after, IdleSuspendWithoutCPU: sub.IdleSuspendWithoutCPU,
		CalloutMode: controller.CalloutFailModeFromConfig(cfg),
	}
}

// substrateTemplateKit reads what a template was built with from its
// attestation (the signed statement): the connector, the agent version and
// the hook contract. An unattested template names none, and the controller
// refuses it at resume.
func substrateTemplateKit(a controller.Attestor) func(context.Context, *ateapi.ActorTemplate) (gateway.SubstrateTemplateKit, error) {
	return func(ctx context.Context, tmpl *ateapi.ActorTemplate) (gateway.SubstrateTemplateKit, error) {
		if a == nil {
			return gateway.SubstrateTemplateKit{}, nil
		}
		att, err := a.Attest(ctx, tmpl)
		if err != nil {
			// Not "no label": the create route decides by mode (GAP-0181).
			return gateway.SubstrateTemplateKit{}, fmt.Errorf("%w: %v", gateway.ErrSubstrateTemplateAttestation, err)
		}
		if !att.Attested {
			// controller.TemplateAttestor reports every refusal here, a
			// verifier outage too (Retryable), never as an error: it is not
			// "no label" (GAP-0181, R4).
			return gateway.SubstrateTemplateKit{}, &gateway.SubstrateTemplateAttestation{Reason: att.Reason, Retryable: att.Retryable}
		}
		if strings.TrimSpace(att.Connector) == "" {
			return gateway.SubstrateTemplateKit{}, &gateway.SubstrateTemplateAttestation{Reason: "the attestation carries no connector label", Unlabeled: true}
		}
		return gateway.SubstrateTemplateKit{Connector: att.Connector, AgentVersion: att.AgentVersion,
			HookContract: att.HookContract, KitVersion: att.KitVersion, Digest: att.Digest, RelayStreams: att.RelayStreams}, nil
	}
}

// substrateEnsurer is the create path's policy writer over a controller.
func substrateEnsurer(ctl *controller.Controller) gateway.SubstratePolicyEnsurer {
	return func(ctx context.Context, atespace, name string) error {
		err := ctl.EnsurePolicy(ctx, ateapi.Ref(atespace, name))
		if errors.Is(err, controller.ErrRefused) {
			// Keep the controller's *RefusedError in the chain: the create
			// path answers with its code, reason and actor UID (GAP-0182).
			return fmt.Errorf("%w: %w", gateway.ErrSubstrateActorRefused, err)
		}
		return err
	}
}

// runtimeSkillScanner is the gateway's skill folder scan (GAP-0039): A9's
// runtime scanner with the host admission rules (attest.RuntimeScanner).
type runtimeSkillScanner struct {
	rt *attest.RuntimeScanner
	// remote is the scanner sidecar client, nil without the sidecar folder.
	remote *scanner.RemoteScanner
	// enabled is substrate.skills.scan.enabled, read on each scan (hot).
	enabled func() bool
}

func newRuntimeSkillScanner(cfg *config.Config) runtimeSkillScanner {
	rt := attest.NewRuntimeScanner(cfg)
	var remote *scanner.RemoteScanner
	// GAP-0477: the gateway image has no Python, so skill-scanner runs in the
	// chart's scanner sidecar. Its shared folder exists only when the chart
	// renders the sidecar; without it the scan is unavailable as in rel and
	// the fail mode decides.
	if fi, err := os.Stat(substrateScanDir); err == nil && fi.IsDir() {
		// The client waits skills.scan.timeout, as the chart's worker
		// --timeout does (GAP-0934: with 0 it waited 20s and cut at 25s
		// whatever the key said). The gateway's own deadline is the live
		// value, so a lower reload applies at once.
		if rs, err := scanner.NewRemoteSkillScanner(cfg.Scanners.SkillScanner, cfg.Substrate.EffectiveSkillScanTimeout()); err == nil {
			rs.Dir = substrateScanDir
			rt.Skill = rs
			remote = rs
		}
	}
	return runtimeSkillScanner{rt: rt, remote: remote}
}

// checkSidecar is the missing-tool check (GAP-0477): with the chart's
// scanner sidecar, serve start asks it whether skill-scanner is ready and
// says so once. The sidecar can start after the gateway, so it asks tries
// times, every apart, before it reports the scanner missing; new skills then
// follow the fail mode (the doctor row substrate.skill_scan shows the same).
func (s runtimeSkillScanner) checkSidecar(ctx context.Context, w io.Writer, tries int, every time.Duration) scanner.RemoteHealth {
	if s.remote == nil {
		return scanner.RemoteHealth{}
	}
	var h scanner.RemoteHealth
	for i := 0; i < tries; i++ {
		if h = s.remote.Health(ctx); h.Ready {
			fmt.Fprintf(w, "substrate: skill scanner ready (skill-scanner %s)\n", h.Version)
			return h
		}
		if i+1 < tries {
			select {
			case <-ctx.Done():
				i = tries
			case <-time.After(every):
			}
		}
	}
	fmt.Fprintf(w, "substrate: skill scanner is not running (%s); new skills follow the hook fail mode. Check: kubectl logs deploy/defenseclaw-gateway -c skill-scanner\n", h.Error)
	return h
}

// substrateScanDir is the scanner sidecar's shared folder (a var for tests).
var substrateScanDir = scanner.DefaultScanDir

// ScanSkillFolder implements gateway.SubstrateSkillScanner.
func (s runtimeSkillScanner) ScanSkillFolder(ctx context.Context, name, dir string, files []gateway.SubstrateAttachedFile) (bool, string, error) {
	asset := attest.RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: name, Path: dir}
	for _, f := range files {
		asset.Files = append(asset.Files, attest.AttachedFile{Role: attest.RoleSkillFile, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
	}
	if s.enabled != nil && !s.enabled() {
		// The admin-off switch (substrate.skills.scan.enabled: false): no
		// scan, the fail mode decides (managed installs refuse new skills).
		return false, "", fmt.Errorf("%w: skill scanning is turned off (substrate.skills.scan.enabled: false)", gateway.ErrSubstrateSkillScannerUnavailable)
	}
	d, err := s.rt.Scan(ctx, asset)
	if errors.Is(err, scanner.ErrScanTimeout) {
		return false, "", fmt.Errorf("%w: %v", gateway.ErrSubstrateSkillScanTimeout, err)
	}
	if err != nil {
		return false, "", err
	}
	if d.Unavailable {
		// No scanner can run in this pod: the gateway's fail mode decides
		// (GAP-0164), never a quarantine on a scan that did not run.
		return false, "", fmt.Errorf("%w: %s", gateway.ErrSubstrateSkillScannerUnavailable, d.Reason)
	}
	return d.Action == "block", d.Reason, nil
}

// substrateTemplateSkills reads an actor template's admitted skill folder
// digests through the create path's controller (the same attestation check
// and cache that admitted the template; GAP-0164).
func substrateTemplateSkills(ctl *controller.Controller) func(ctx context.Context, template string) ([]string, error) {
	return func(ctx context.Context, template string) ([]string, error) {
		atespace, name, ok := strings.Cut(template, "/")
		if !ok || atespace == "" || name == "" {
			return nil, fmt.Errorf("template %q is not atespace/name", template)
		}
		digests, attested, err := ctl.TemplateSkillDigests(ctx, ateapi.Ref(atespace, name))
		if err != nil || !attested {
			return nil, err
		}
		return digests, nil
	}
}

// substrateControllerLiveFunc builds controller.Live for each config.yaml in
// force. The restart-only render inputs (substrate.identity: audience and
// token lifetime; substrate.services; substrate.extproc mcp_hosts and the
// llm_providers hosts) keep their boot values, as the gateway and the
// callout keep them (GAP-0297, GAP-0306). In bundle mode the stage bundles keep the boot profiles.
func substrateControllerLiveFunc(boot *config.Config, idle bool, resolver controller.ProfileResolver, sink controller.Sink) func(*config.Config) controller.Live {
	bootSettings := controller.SettingsFromConfig(boot)
	return func(c *config.Config) controller.Live {
		if c != boot && resolver != nil {
			sink.Emit(controller.Event{Type: controller.EventWarning, Severity: controller.SeverityWarn,
				Message: "substrate.bundles: the stage bundles are layered over the profiles config.yaml had when the controller started; " +
					"a profile change in config.yaml applies when the controller restarts (the egress allow list, secrets, launcher atespaces and template rules apply now)"})
		}
		lv := substrateControllerLive(c, idle, resolver, sink)
		if c == boot {
			return lv
		}
		if keys := substrateControllerRestartOnly(boot, c); len(keys) > 0 {
			sink.Emit(controller.Event{Type: controller.EventWarning, Severity: controller.SeverityWarn,
				Message: "config.yaml changed " + strings.Join(keys, ", ") + ": applies when the pods restart (helm upgrade, or " +
					substrateRestartAll + "); until then the values the pods started with stay"})
		}
		lv.Settings.ActorService, lv.Settings.AdminService = bootSettings.ActorService, bootSettings.AdminService
		lv.Settings.Audience, lv.Settings.TokenLifetimeSeconds = bootSettings.Audience, bootSettings.TokenLifetimeSeconds
		// The callout reads substrate.extproc (mcp_hosts) and the gateway the
		// LLM providers only at helm upgrade or restart (its config reload
		// holds llm_providers on Substrate, GAP-0589): rendering their hosts
		// live would open egress before the callout inspects it (GAP-0306).
		lv.Settings.MCPHosts, lv.Settings.ProviderHosts = bootSettings.MCPHosts, bootSettings.ProviderHosts
		// substrate.extproc is restart-only: a callout replacement follows
		// the fail mode the pods started with (GAP-0505).
		lv.CalloutMode = controller.CalloutFailModeFromConfig(boot)
		return lv
	}
}

// substrateControllerRestartOnly names the render inputs that changed from
// boot to cur and that the controller keeps at their boot values.
func substrateControllerRestartOnly(boot, cur *config.Config) []string {
	var out []string
	if !reflect.DeepEqual(boot.Substrate.Identity, cur.Substrate.Identity) {
		out = append(out, "substrate.identity")
	}
	if !reflect.DeepEqual(boot.Substrate.Services, cur.Substrate.Services) {
		out = append(out, "substrate.services")
	}
	if !reflect.DeepEqual(boot.Substrate.API, cur.Substrate.API) {
		out = append(out, "substrate.api")
	}
	if !reflect.DeepEqual(boot.Substrate.Extproc, cur.Substrate.Extproc) {
		out = append(out, "substrate.extproc (helm upgrade only: it renders the callout's ConfigMap)")
	}
	if !reflect.DeepEqual(boot.LLMProviders, cur.LLMProviders) {
		out = append(out, "llm_providers")
	}
	return out
}
