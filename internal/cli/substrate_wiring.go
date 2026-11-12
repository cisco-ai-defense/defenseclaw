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
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// controllerRegistry is controller.Registry over the leader's
// registrations (registry.Store), so the controller and the gateway share
// one record per actor UID: the launcher's registration is what the
// controller attributes a launcher actor to, and the controller's
// attributed and fork records reach the gateway.
type controllerRegistry struct {
	store registry.Store
}

func (c controllerRegistry) Get(ctx context.Context, atespace, uid string) (controller.Registration, bool, error) {
	r, ok, err := c.store.Get(ctx, atespace, uid)
	if err != nil || !ok || r.Deleted {
		return controller.Registration{}, false, err
	}
	out := controller.Registration{
		Atespace: r.Atespace, Name: r.Name, UID: r.UID, Template: r.Template, Profile: r.Profile,
		Task: r.Unattended, BatchID: r.BatchID, ParentUID: r.ParentUID, ForkedBy: r.ForkedBy,
		Approved: slices.Clone(r.Approved), Source: controller.SourceLauncher,
	}
	switch {
	case r.Attributed:
		out.Source = controller.SourceAtespace
	case r.ParentUID != "":
		out.Source = controller.SourceFork
	}
	switch r.Person.Kind {
	case identity.PersonWorkload:
		out.Workload = r.Person.Subject
	default:
		out.Person = r.Person.Subject
	}
	return out, true, nil
}

// Put writes the controller's records: an attributed actor, an adopted
// fork (with its parent's person), or a change to one it already has.
func (c controllerRegistry) Put(ctx context.Context, in controller.Registration) error {
	cur, ok, err := c.store.Get(ctx, in.Atespace, in.UID)
	if err != nil {
		return err
	}
	if ok {
		cur.Approved, cur.ForkedBy = slices.Clone(in.Approved), in.ForkedBy
		if cur.Template == "" {
			cur.Template = in.Template
		}
		return c.store.Put(ctx, cur)
	}
	reg := registry.Registration{
		Atespace: in.Atespace, Name: in.Name, UID: in.UID, Template: in.Template, Profile: in.Profile,
		Unattended: in.Task, BatchID: in.BatchID, ParentUID: in.ParentUID, ForkedBy: in.ForkedBy,
		Approved: slices.Clone(in.Approved),
	}
	if in.Source == controller.SourceFork && in.ParentUID != "" {
		parent, pok, perr := c.store.Get(ctx, in.Atespace, in.ParentUID)
		if perr != nil {
			return perr
		}
		if pok && !parent.Attributed {
			reg.Person, reg.Connector, reg.KitVersion, reg.HookContract = parent.Person, parent.Connector, parent.KitVersion, parent.HookContract
			reg.HarnessVersion, reg.TemplateDigest, reg.Secrets = parent.HarnessVersion, parent.TemplateDigest, parent.Secrets
		} else {
			reg.Attributed = true
		}
	} else {
		reg.Attributed = true
	}
	return c.store.Put(ctx, reg)
}

// newSubstrateController builds the controller the controller deployment
// runs and the gateway's create path uses for EnsurePolicy: the same
// admission, profiles and render in both.
func newSubstrateController(cfg *config.Config, client ateapi.Client, reg controller.Registry,
	act controller.ActivitySource, cpu controller.CPUSource, events io.Writer, idleAfter bool) (*controller.Controller, error) {
	sub := cfg.Substrate
	if act == nil {
		act = controller.NoActivity{}
	}
	idle := sub.EffectiveIdleSuspendAfter()
	if !idleAfter || cpu == nil {
		idle = 0 // no CPU source: never suspend on silence alone (E4)
	}
	return controller.New(controller.Options{
		Client: client, Attestor: controller.NoAttestor{}, Activity: act, CPU: cpu,
		Registry: reg, Resolver: &controller.ConfigResolver{Config: cfg},
		Sink:     &controller.JSONSink{W: events},
		Settings: controller.SettingsFromConfig(cfg), Secrets: controller.SecretsFromConfig(cfg),
		LauncherAtespaces: controller.LauncherSet(cfg), RequireAttestation: sub.AttestationRequired(),
		KitVersion: appVersion, IdleSuspendAfter: idle,
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
