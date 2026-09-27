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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

// TeardownOptions are the `sandbox teardown` flags.
type TeardownOptions struct {
	Yes        bool
	DryRun     bool
	KeepImages bool
}

// teardownPlan is what teardown found to remove.
type teardownPlan struct {
	daemon    bool
	sandboxes []string
	providers []string
	profiles  []string
	// ownIngress are this data dir's ingress profiles, found before its
	// providers are deleted.
	ownIngress map[string]bool
	images     []string
	gateway    []receiptFile
	changed    []receiptFile
	wrappers   []wrapper.Installed
	gwErr      error
	client     openshell.Client
}

// Teardown removes everything DefenseClaw created for sandboxes: its
// sandboxes, providers and provider profiles, its images, the gateway
// configuration it changed (restored from the backup when nobody changed
// it since) and the shell wrappers. OpenShell itself stays installed.
func (a *App) Teardown(ctx context.Context, o TeardownOptions) error {
	a.defaults()
	if err := openshell.CheckPlatform(a.GOOS); err != nil {
		return fmt.Errorf("%w: OpenShell sandboxes run on Linux and macOS only", ErrUnsupported)
	}
	if a.Cfg != nil && managed.IsManagedEnterprise(a.Cfg.DeploymentMode) {
		return fmt.Errorf("%w: sandboxes are not supported in managed_enterprise deployments", ErrUnsupported)
	}
	p, err := a.planTeardown(ctx, o)
	if err != nil {
		return err
	}
	if p.client != nil {
		defer p.client.Close()
	}
	a.printTeardown(p, o)
	if p.empty() {
		a.ok("nothing to tear down")
		return nil
	}
	if o.DryRun {
		return nil
	}
	yes, err := a.confirm("Remove all of it? (OpenShell itself stays installed)", o.Yes)
	if err != nil {
		return err
	}
	if !yes {
		a.note("nothing changed")
		return nil
	}
	return a.runTeardown(ctx, p, o)
}

func (p *teardownPlan) empty() bool {
	return len(p.sandboxes) == 0 && len(p.providers) == 0 && len(p.profiles) == 0 && len(p.images) == 0 &&
		len(p.gateway) == 0 && len(p.changed) == 0 && len(p.wrappers) == 0
}

// owner is this data dir's sandbox owner label, "" when it never had one
// (reading it must not create the image store).
func (a *App) owner() string {
	store := image.NewStore(a.dataDir())
	if _, err := os.Stat(store.Path()); err != nil {
		return ""
	}
	owner, err := store.Owner()
	if err != nil {
		return ""
	}
	return owner
}

func (a *App) planTeardown(ctx context.Context, o TeardownOptions) (*teardownPlan, error) {
	p := &teardownPlan{}
	owner := a.owner()
	if api, err := a.api(); err == nil {
		if list, err := api.List(ctx); err == nil {
			p.daemon = true
			for _, sb := range list {
				p.sandboxes = append(p.sandboxes, sb.Name)
			}
		}
	}
	// The gateway directly: sandboxes and providers the daemon does not
	// know (it is stopped, or they were orphaned), and the profiles.
	c, _, err := a.OpenShell(ctx)
	if err != nil {
		p.gwErr = err
	} else {
		p.client = c
		if owner != "" {
			sel := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: owner}
			if sbs, err := c.ListSandboxes(ctx, sel); err == nil {
				for _, sb := range sbs {
					if !slices.Contains(p.sandboxes, sb.Name) {
						p.sandboxes = append(p.sandboxes, sb.Name)
					}
				}
			}
			if list, err := c.ListProviders(ctx); err == nil {
				for _, pr := range list {
					if pr.Labels[manager.LabelManaged] == "true" && pr.Labels[manager.LabelOwner] == owner {
						p.providers = append(p.providers, pr.Name)
					}
				}
			}
		}
		p.ownIngress = a.ownIngressProfiles(ctx, c, p.providers)
		p.profiles = a.unusedProfiles(ctx, c, p.providers, p.ownIngress)
	}
	sort.Strings(p.sandboxes)
	if !o.KeepImages {
		if tags, err := a.Images.Remove(ctx, true); err == nil {
			p.images = tags
		}
	}
	if r, err := a.loadReceipt(); err == nil {
		for _, f := range r.GatewayFiles {
			if sum, err := fileSHA256(f.Path); err == nil && sum == f.SHA256 {
				p.gateway = append(p.gateway, f)
			} else if err == nil || !errors.Is(err, os.ErrNotExist) {
				p.changed = append(p.changed, f)
			}
		}
	}
	if home, err := a.Home(); err == nil {
		p.wrappers = wrapper.Scan(home, a.Getenv)
	}
	return p, nil
}

// ownIngressProfiles are the ingress provider profiles this data dir uses:
// its configured listener's and the ones its providers (ours) were created
// from, which an earlier ingress port leaves behind.
func (a *App) ownIngressProfiles(ctx context.Context, c openshell.Client, ours []string) map[string]bool {
	own := map[string]bool{}
	if a.Cfg != nil {
		own[profiles.IngressProfileID(a.Cfg.OpenShellIngressPort())] = true
	}
	if list, err := c.ListProviders(ctx); err == nil {
		for _, pr := range list {
			if _, ok := profiles.IngressPort(pr.Type); ok && slices.Contains(ours, pr.Name) {
				own[pr.Type] = true
			}
		}
	}
	return own
}

// unusedProfiles are the provider profiles teardown removes, each only when
// no provider outside this teardown (ours) uses it: profiles are
// gateway-global, shared with every DefenseClaw data dir on the gateway.
// Those are this data dir's own ingress profiles (ownIngress), the legacy
// gateway-wide one, and the shared LLM and credential profiles, which the
// daemons re-import when they need them. Another daemon's ingress profile
// (another listener's) is never removed, used or not, and OpenShell itself
// refuses to delete a profile a provider still uses.
func (a *App) unusedProfiles(ctx context.Context, c openshell.Client, ours []string, ownIngress map[string]bool) []string {
	list, err := c.ListProfiles(ctx)
	if err != nil {
		return nil
	}
	providers, err := c.ListProviders(ctx)
	if err != nil {
		return nil
	}
	used := map[string]bool{}
	for _, pr := range providers {
		if !slices.Contains(ours, pr.Name) {
			used[pr.Type] = true
		}
	}
	var out []string
	for _, pf := range list {
		dc := profiles.IsDefenseClaw(pf.ID) || strings.HasPrefix(pf.ID, "dc-cred-")
		if _, ingress := profiles.IngressPort(pf.ID); ingress && !ownIngress[pf.ID] {
			dc = false
		}
		if dc && !used[pf.ID] {
			out = append(out, pf.ID)
		}
	}
	sort.Strings(out)
	return out
}

func (a *App) printTeardown(p *teardownPlan, o TeardownOptions) {
	list := func(label string, items []string) {
		if len(items) > 0 {
			a.line(fmt.Sprintf("%-18s%s", label, strings.Join(items, ", ")))
		}
	}
	a.println(a.bold("Sandbox teardown"))
	list("sandboxes", p.sandboxes)
	list("providers", p.providers)
	list("provider profiles", p.profiles)
	list("images", p.images)
	for _, f := range p.gateway {
		how := "restore the backup " + f.Backup
		if f.Backup == "" {
			how = "remove it (DefenseClaw created it)"
		}
		a.line(fmt.Sprintf("%-18s%s: %s", "gateway config", f.Path, how))
	}
	for _, f := range p.changed {
		a.warn(f.Path + " changed after DefenseClaw edited it; it is left alone (DefenseClaw's backup: " + firstNonEmpty(f.Backup, "none") + ")")
	}
	for _, w := range p.wrappers {
		a.line(fmt.Sprintf("%-18s%s in %s", "shell wrappers", strings.Join(w.Block.Commands(), ", "), a.tildePath(w.Path)))
	}
	if p.gwErr != nil {
		a.warn("the OpenShell gateway is not reachable (" + truncate(p.gwErr.Error(), 120) + "); only what DefenseClaw can see locally is removed")
	}
	if o.KeepImages {
		a.note("images are kept (--keep-images)")
	}
}

func (a *App) runTeardown(ctx context.Context, p *teardownPlan, o TeardownOptions) error {
	var errs []error
	fail := func(what string, err error) {
		a.bad(what + ": " + err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", what, err))
	}
	api, _ := a.api()
	for _, name := range p.sandboxes {
		deleted := false
		if p.daemon && api != nil {
			if _, err := api.Delete(ctx, name, sandboxapi.DeleteRequest{}); err == nil {
				deleted = true
			} else if !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) && p.client == nil {
				fail("delete sandbox "+name, apiError(err))
				continue
			}
		}
		if !deleted && p.client != nil {
			if _, err := p.client.DeleteSandbox(ctx, name); err != nil {
				fail("delete sandbox "+name, err)
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			err := p.client.WaitDeleted(wctx, name)
			cancel()
			if err != nil {
				fail("wait for "+name+" to go", err)
				continue
			}
		}
		a.ok("deleted sandbox " + name)
	}
	if p.client != nil {
		// The daemon deletes a sandbox's providers with it; what is left
		// belonged to sandboxes it no longer knew.
		left := map[string]bool{}
		if list, err := p.client.ListProviders(ctx); err == nil {
			for _, pr := range list {
				left[pr.Name] = true
			}
		}
		for _, name := range p.providers {
			if !left[name] {
				continue
			}
			if _, err := p.client.DeleteProvider(ctx, name); err != nil && !openshell.IsNotFound(err) {
				fail("delete provider "+name, err)
				continue
			}
			a.ok("deleted provider " + name)
		}
		for _, id := range a.unusedProfiles(ctx, p.client, p.providers, p.ownIngress) {
			if _, err := p.client.DeleteProfile(ctx, id); err != nil && !openshell.IsNotFound(err) {
				fail("delete provider profile "+id, err)
				continue
			}
			a.ok("deleted provider profile " + id)
		}
	}
	if !o.KeepImages && len(p.images) > 0 {
		removed, err := a.Images.Remove(ctx, false)
		for _, t := range removed {
			a.ok("removed image " + t)
		}
		if err != nil {
			fail("remove images", err)
		}
	}
	if len(p.gateway) > 0 {
		res := &openshell.GatewayApplyResult{}
		for _, f := range p.gateway {
			res.Files = append(res.Files, openshell.AppliedFile{Path: f.Path, Backup: f.Backup})
		}
		if err := a.Gateway.Rollback(ctx, res); err != nil {
			fail("restore the gateway configuration", err)
		} else {
			a.ok("restored the OpenShell gateway configuration and restarted it")
			if r, err := a.loadReceipt(); err == nil {
				r.GatewayFiles = nil
				_ = a.saveReceipt(r)
			}
		}
	}
	for _, w := range p.wrappers {
		if _, err := wrapper.RemoveAll(w.Shell, w.Path); err != nil {
			fail("remove the wrappers from "+w.Path, err)
			continue
		}
		a.ok("removed the shell wrappers from " + a.tildePath(w.Path))
	}
	if a.Cfg != nil && a.Cfg.OpenShell.Enabled {
		if _, err := os.Stat(a.ConfigPath); err == nil {
			if err := a.patchConfig(map[string]any{"openshell.enabled": false, "openshell.wrappers": []string{}}); err != nil {
				a.warn("could not turn openshell.enabled off: " + err.Error())
			} else {
				a.ok("openshell.enabled is off")
			}
		}
	}
	if len(errs) > 0 {
		return &Silent{Err: errors.Join(errs...)}
	}
	a.ok("teardown complete; OpenShell itself is still installed")
	return nil
}
