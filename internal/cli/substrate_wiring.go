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
	act controller.ActivitySource, cpu controller.CPUSource, events io.Writer, idleAfter bool,
	resets controller.ResetStore, namespace string) (*controller.Controller, error) {
	sub := cfg.Substrate
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
			fmt.Fprintf(events, "{\"type\":%q,\"severity\":\"warning\",\"message\":%q}\n", controller.EventWarning,
				err.Error()+": every template is refused until the trust anchors are mounted")
		}
		attestor = &controller.TemplateAttestor{Verifier: ver, VolumeImages: sub.Templates.VolumeImages}
	}
	return controller.New(controller.Options{
		Client: client, Attestor: attestor, Activity: act, CPU: cpu,
		Registry: reg, Resolver: &controller.ConfigResolver{Config: cfg},
		Sink:     &controller.JSONSink{W: events},
		Settings: controller.SettingsFromConfig(cfg), Secrets: controller.SecretsFromConfig(cfg),
		LauncherAtespaces: controller.LauncherSet(cfg), RequireAttestation: sub.AttestationRequired(), Templates: sub.Templates,
		KitVersion: appVersion, IdleSuspendAfter: idle, Resets: resets, Namespace: namespace,
	})
}

// substrateEnsurer is the create path's policy writer over a controller.
func substrateEnsurer(ctl *controller.Controller) gateway.SubstratePolicyEnsurer {
	return func(ctx context.Context, atespace, name string) error {
		err := ctl.EnsurePolicy(ctx, ateapi.Ref(atespace, name))
		if errors.Is(err, controller.ErrRefused) {
			return fmt.Errorf("%w: %v", gateway.ErrSubstrateActorRefused, err)
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
	return d.Action == "block", d.Reason, nil
}
