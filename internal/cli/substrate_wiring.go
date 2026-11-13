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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// newSubstrateController builds the controller the controller deployment
// runs and the gateway's create path uses for EnsurePolicy: the same
// admission, profiles and render in both.
func newSubstrateController(cfg *config.Config, client ateapi.Client, reg controller.Registry,
	act controller.ActivitySource, cpu controller.CPUSource, sink controller.Sink, idleAfter bool,
	resets controller.ResetStore, namespace string, resolver controller.ProfileResolver) (*controller.Controller, error) {
	sub := cfg.Substrate
	if resolver == nil {
		resolver = &controller.ConfigResolver{Config: cfg}
	}

	if act == nil {
		act = controller.NoActivity{}
	}
	idle := sub.EffectiveIdleSuspendAfter()
	if !idleAfter || cpu == nil {
		idle = 0 // no CPU source: never suspend on silence alone (E4)
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
	return controller.New(controller.Options{
		Client: client, Attestor: attestor, Activity: act, CPU: cpu,
		Registry: reg, Resolver: resolver,
		Sink:     sink,
		Settings: controller.SettingsFromConfig(cfg), Secrets: controller.SecretsFromConfig(cfg),
		LauncherAtespaces: controller.LauncherSet(cfg), RequireAttestation: sub.AttestationRequired(), Templates: sub.Templates,
		KitVersion: appVersion, IdleSuspendAfter: idle, Resets: resets, Namespace: namespace,
	})
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
			return gateway.SubstrateTemplateKit{}, nil
		}
		return gateway.SubstrateTemplateKit{Connector: att.Connector, AgentVersion: att.AgentVersion,
			HookContract: att.HookContract, KitVersion: att.KitVersion, Digest: att.Digest}, nil
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
type runtimeSkillScanner struct{ rt *attest.RuntimeScanner }

func newRuntimeSkillScanner(cfg *config.Config) runtimeSkillScanner {
	return runtimeSkillScanner{rt: &attest.RuntimeScanner{
		Skill:     scanner.NewSkillScannerFromLLM(cfg.Scanners.SkillScanner, cfg.ResolveLLM("scanners.skill"), cfg.CiscoAIDefense),
		MCPStatic: &attest.MCPStaticScanner{},
		Compiled:  policy.CompileAdmission(cfg),
	}}
}

// ScanSkillFolder implements gateway.SubstrateSkillScanner.
func (s runtimeSkillScanner) ScanSkillFolder(ctx context.Context, name, dir string, files []gateway.SubstrateAttachedFile) (bool, string, error) {
	asset := attest.RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: name, Path: dir}
	for _, f := range files {
		asset.Files = append(asset.Files, attest.AttachedFile{Role: attest.RoleSkillFile, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
	}
	d, err := s.rt.Scan(ctx, asset)
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
