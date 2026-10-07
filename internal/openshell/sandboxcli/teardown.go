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
	"path/filepath"
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
	// imageIDs are the image IDs of those images, and vmDisks the disks the
	// MicroVM driver prepared from them, which teardown removes once the
	// images are gone and no sandbox is left that boots one.
	imageIDs []string
	vmDisks  vmDiskSet
	// listed is set when the gateway listed this data dir's sandboxes.
	listed bool
	// orphans are sandboxes whose data under <data_dir>/sandboxes the
	// daemon has no record of.
	orphans []string
	// offline is set when no daemon manages the data dir (it is stopped,
	// or sandboxes are off): teardown then removes the local state of the
	// recorded sandboxes it deletes on the gateway itself, and of those
	// already gone from it (stale), which no daemon reconciles once
	// openshell.enabled is off (manager.RemoveSandboxState).
	offline bool
	// recorded are the sandboxes the daemon keeps records of, by name.
	recorded map[string]manager.RecordedSandbox
	// stale are recorded sandboxes the gateway no longer has: a kept
	// snapshot, or a delete the daemon never saw.
	stale   []string
	gateway []receiptFile
	// manualRestart is set when no gateway service runs the gateway those
	// files are for: its user restarts it on them, and this says what that
	// restart stops (manualRestartStops).
	manualRestart string
	changed       []receiptFile
	wrappers      []wrapper.Installed
	gwErr         error
	client        openshell.Client
	// disable is set when config.yaml turns sandboxes on
	// (openshell.enabled), which teardown turns off last.
	disable bool
	// unhanded says, per copy-mode sandbox, the work it holds that never
	// came back to the folder (see unhandedWork).
	unhanded []string
}

// gatewayBackups are the backups DefenseClaw made of the gateway file path
// before it edited it (openshell.GatewayConfigurator: one per edit, named
// path.defenseclaw-<UTC>.bak), regular files only.
func gatewayBackups(path string) []string {
	matches, _ := filepath.Glob(path + ".defenseclaw-*.bak")
	var out []string
	for _, m := range matches {
		if info, err := os.Lstat(m); err == nil && info.Mode().IsRegular() {
			out = append(out, m)
		}
	}
	return out
}

// Teardown removes everything DefenseClaw created for sandboxes: its
// sandboxes, providers and provider profiles, the data sandboxes it no
// longer knows left under the data dir, its images, the gateway
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
		a.println()
		a.note("dry run: nothing was changed")
		return nil
	}
	question := "Remove all of it? (OpenShell itself stays installed)"
	if len(p.unhanded) > 0 {
		question = "Remove all of it, and discard the work the sandboxes above hold? (OpenShell itself stays installed)"
	}
	yes, err := a.confirm(question, o.Yes)
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
		len(p.orphans) == 0 && len(p.stale) == 0 && len(p.gateway) == 0 && len(p.changed) == 0 && len(p.wrappers) == 0 &&
		!p.disable
}

// sandboxesOn reports whether config.yaml turns sandboxes on, which the
// teardown's last step turns off.
func (a *App) sandboxesOn() bool {
	if a.Cfg == nil || !a.Cfg.OpenShell.Enabled {
		return false
	}
	_, err := os.Stat(a.ConfigPath)
	return err == nil
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
	// No daemon manages the data dir when none answers, or when the one
	// that does has sandboxes off; one that has them on but could not list
	// them may still be running its manager, so nothing local is touched.
	p.offline = true
	if api, err := a.api(); err == nil {
		if list, err := api.List(ctx); err == nil {
			p.daemon = true
			for _, sb := range list {
				p.sandboxes = append(p.sandboxes, sb.Name)
				if lost := a.unhandedWork(ctx, &sb); lost != "" {
					p.unhanded = append(p.unhanded, "sandbox "+sb.Name+" "+lost)
				}
			}
			sort.Strings(p.unhanded)
		}
		if p.daemon {
			p.offline = false
		} else if st, err := api.Status(ctx); err == nil && st.Enabled {
			p.offline = false
		}
	}
	// The gateway directly: sandboxes and providers the daemon does not
	// know (it is stopped, or they were orphaned), and the profiles.
	listed := false
	c, _, err := a.OpenShell(ctx)
	if err != nil {
		p.gwErr = err
	} else {
		p.client = c
		if owner != "" {
			sel := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: owner}
			if sbs, err := c.ListSandboxes(ctx, sel); err == nil {
				listed, p.listed = true, true
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
	if p.offline {
		p.recorded = map[string]manager.RecordedSandbox{}
		for _, r := range manager.RecordedSandboxes(a.dataDir()) {
			p.recorded[r.Name] = r
			// Only a gateway that listed its sandboxes tells a gone one
			// from a live one.
			if listed && !slices.Contains(p.sandboxes, r.Name) {
				p.stale = append(p.stale, r.Name)
			}
		}
	}
	p.orphans = manager.OrphanedSandboxData(a.dataDir())
	if !o.KeepImages {
		if tags, err := a.Images.Remove(ctx, nil, true); err == nil {
			p.images = tags
		}
		if len(p.images) > 0 {
			p.imageIDs = a.storeImageIDs()
			p.vmDisks = a.vmDisksOf(p.imageIDs, nil)
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
	if len(p.gateway) > 0 && a.Gateway.NoService(ctx) {
		// Teardown deletes this install's sandboxes before it restores the
		// files: the restart stops the others.
		p.manualRestart = a.manualRestartStops(ctx, !a.gatewayDriverNow(ctx).StopFlushes, p.sandboxes)
	}
	p.wrappers = a.wrapperFiles()
	p.disable = a.sandboxesOn()
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

// printTeardown prints the plan, one step per line. A plan with something
// to remove lists every step, "none" included, so a dry run shows all of
// what a teardown does.
func (a *App) printTeardown(p *teardownPlan, o TeardownOptions) {
	full := !p.empty()
	row := func(label, text string) { a.line(fmt.Sprintf("%-18s%s", label, text)) }
	list := func(label string, items []string) {
		switch {
		case len(items) > 0:
			row(label, strings.Join(items, ", "))
		case full:
			row(label, "none")
		}
	}
	a.println(a.bold("Sandbox teardown"))
	list("sandboxes", p.sandboxes)
	list("providers", p.providers)
	for i, r := range a.profileRows(p) {
		if i == 0 {
			row("provider profiles", r)
		} else {
			row("", r)
		}
	}
	if o.KeepImages {
		row("images", "kept (--keep-images)")
	} else {
		list("images", p.images)
		if n := len(p.vmDisks.disks); n > 0 {
			row("", fmt.Sprintf("and the %s OpenShell prepared from them (%s in %s)",
				plural(int64(n), "MicroVM disk", "MicroVM disks"), humanBytes(p.vmDisks.size), a.tildePath(p.vmDisks.dir)))
		}
	}
	if len(p.orphans) > 0 {
		list("leftover data", p.orphans)
	}
	var stale []string
	for _, name := range p.stale {
		if p.recorded[name].Retained {
			name += " (kept snapshot)"
		}
		stale = append(stale, name)
	}
	if len(stale) > 0 {
		list("gone sandboxes", stale)
	}
	for _, f := range p.gateway {
		how := "restore the backup " + a.tildePath(f.Backup)
		if f.Backup == "" {
			how = "remove it (DefenseClaw created it)"
		}
		if n := len(gatewayBackups(f.Path)); n > 0 {
			how += ", then remove the " + plural(int64(n), "backup", "backups") + " DefenseClaw made of it"
		}
		row("gateway config", a.tildePath(f.Path)+": "+how)
	}
	switch {
	case len(p.gateway) > 0 && p.manualRestart != "":
		// A gateway run another way, which DefenseClaw cannot restart.
		row("", "then you restart the OpenShell gateway yourself, the way you started it, so it loads them (DefenseClaw cannot restart it); "+p.manualRestart)
	case len(p.gateway) > 0:
		row("", "then restart the OpenShell gateway, which drops the connections of every sandbox on it")
	case len(p.changed) == 0 && full:
		row("gateway config", "nothing to restore (setup recorded no change to it)")
	}
	for _, f := range p.changed {
		a.warn(f.Path + " changed after DefenseClaw edited it; it is left alone (DefenseClaw's backup: " + firstNonEmpty(f.Backup, "none") + ")")
	}
	for _, u := range p.unhanded {
		a.warn(u + "; teardown deletes it")
	}
	for _, w := range p.wrappers {
		row("shell wrappers", strings.Join(w.Block.Commands(), ", ")+" in "+a.tildePath(w.Path))
	}
	if len(p.wrappers) == 0 && full {
		row("shell wrappers", "none")
	}
	switch {
	case p.disable:
		row("config", "turn openshell.enabled off in "+a.tildePath(a.ConfigPath))
	case full && a.Cfg != nil:
		row("config", "openshell.enabled is already off")
	}
	if p.gwErr != nil {
		a.warn("the OpenShell gateway is not reachable (" + truncate(p.gwErr.Error(), 120) + "); only what DefenseClaw can see locally is removed")
	}
}

// profileRows labels the provider profiles teardown removes: this install's
// own ingress profiles, and the model and credential profiles every install
// on the gateway shares, which no provider uses now (an install that needs
// one imports it again).
func (a *App) profileRows(p *teardownPlan) []string {
	var own, shared, creds []string
	for _, id := range p.profiles {
		switch {
		case p.ownIngress[id]:
			own = append(own, id)
		case strings.HasPrefix(id, "dc-cred-"):
			creds = append(creds, id)
		default:
			shared = append(shared, id)
		}
	}
	// Credential profile names are hashes: past a few, a count says more.
	if len(creds) > 3 {
		shared = append(shared, fmt.Sprintf("%d --credential profiles (dc-cred-…)", len(creds)))
	} else {
		shared = append(shared, creds...)
	}
	var rows []string
	if len(own) > 0 {
		rows = append(rows, strings.Join(own, ", ")+" (this install's hook ingress)")
	}
	if len(shared) > 0 {
		rows = append(rows, strings.Join(shared, ", ")+" (shared by every DefenseClaw install on this gateway and unused now; an install that needs one imports it again)")
	}
	if len(rows) == 0 && !p.empty() {
		rows = append(rows, "none")
	}
	return rows
}

// sandboxImageRefs are the images the sandboxes left after the teardown's
// deletes are recorded with, by tag and ID: the daemon's, and the records
// under the data dir. why says, instead, why they cannot be known, and the
// MicroVM disks stay: a sandbox teardown could not delete, or no daemon or
// gateway that lists them.
func (a *App) sandboxImageRefs(ctx context.Context, p *teardownPlan, undeleted int) (map[string]bool, string) {
	switch {
	case undeleted > 0:
		return nil, plural(int64(undeleted), "sandbox", "sandboxes") + " that may boot them could not be deleted"
	case !p.daemon && !p.listed:
		return nil, "neither the DefenseClaw daemon nor the OpenShell gateway listed the sandboxes that may boot them"
	}
	refs := map[string]bool{}
	if p.daemon {
		api, err := a.api()
		if err != nil {
			return nil, "the DefenseClaw daemon did not list its sandboxes: " + err.Error()
		}
		list, err := api.List(ctx)
		if err != nil {
			return nil, "the DefenseClaw daemon did not list its sandboxes: " + apiError(err).Error()
		}
		for _, sb := range list {
			for _, ref := range []string{sb.Image, sb.ImageID, sb.RunImage, sb.RunImageID} {
				refs[ref] = true
			}
		}
	}
	if p.listed && p.client != nil {
		sel := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: a.owner()}
		sbs, err := p.client.ListSandboxes(ctx, sel)
		switch {
		case err != nil:
			return nil, "the OpenShell gateway did not list its sandboxes: " + err.Error()
		case len(sbs) > 0:
			return nil, plural(int64(len(sbs)), "sandbox", "sandboxes") + " of this install are still on the OpenShell gateway"
		}
	}
	for _, r := range manager.RecordedSandboxes(a.dataDir()) {
		for _, ref := range r.Images {
			refs[ref] = true
		}
	}
	delete(refs, "")
	return refs, ""
}

// removeSandboxState removes what a recorded sandbox left on this machine
// once it is gone from the gateway (manager.RemoveSandboxState): its mount
// pins and masks, snapshot, copy, run files, binding and record, and the
// CLI's own state of it.
func (a *App) removeSandboxState(ctx context.Context, name string) error {
	if err := manager.RemoveSandboxState(ctx, a.dataDir(), name); err != nil {
		return err
	}
	a.forgetCLIState(name)
	return nil
}

func (a *App) runTeardown(ctx context.Context, p *teardownPlan, o TeardownOptions) error {
	var errs []error
	fail := func(what string, err error) {
		a.bad(what + ": " + err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", what, err))
	}
	api, _ := a.api()
	undeleted := 0
	for _, name := range p.sandboxes {
		deleted := false
		if p.daemon && api != nil {
			if _, err := api.Delete(ctx, name, sandboxapi.DeleteRequest{}); err == nil {
				deleted = true
			} else if !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) && p.client == nil {
				fail("delete sandbox "+name, apiError(err))
				undeleted++
				continue
			}
		}
		if !deleted && p.client != nil {
			if _, err := p.client.DeleteSandbox(ctx, name); err != nil {
				fail("delete sandbox "+name, err)
				undeleted++
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			err := p.client.WaitDeleted(wctx, name)
			cancel()
			if err != nil {
				fail("wait for "+name+" to go", err)
				undeleted++
				continue
			}
			// No daemon cleans up after a delete it did not make.
			if _, ok := p.recorded[name]; ok && p.offline {
				if err := a.removeSandboxState(ctx, name); err != nil {
					fail("remove what "+name+" left on this machine", err)
					continue
				}
			}
		}
		// What the CLI kept of it (the run's options, a copy's hand-over), as
		// `sandbox delete` removes it: the daemon's delete leaves it.
		a.forgetCLIState(name)
		a.ok("deleted sandbox " + name)
	}
	for _, name := range p.stale {
		if err := a.removeSandboxState(ctx, name); err != nil {
			fail("remove what "+name+" left on this machine", err)
			continue
		}
		a.ok("removed what the gone sandbox " + name + " left on this machine")
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
	// Data of sandboxes the daemon no longer knew: mount pins and masks,
	// copy-mode state and run files an interrupted create or delete left.
	for _, name := range p.orphans {
		a.forgetCLIState(name)
		if err := manager.RemoveOrphanedSandboxData(a.dataDir(), name); err != nil {
			fail("remove the leftover data of "+name, err)
			continue
		}
		a.ok("removed the leftover data of " + name)
	}
	if !o.KeepImages && len(p.images) > 0 {
		removed, err := a.Images.Remove(ctx, nil, false)
		for _, t := range removed {
			a.ok("removed image " + t)
		}
		if err != nil {
			fail("remove images", err)
		}
		if n := len(p.vmDisks.disks); n > 0 {
			if refs, why := a.sandboxImageRefs(ctx, p, undeleted); why != "" {
				a.note(fmt.Sprintf("kept the %s OpenShell prepared from them (%s in %s): %s",
					plural(int64(n), "MicroVM disk", "MicroVM disks"), humanBytes(p.vmDisks.size), a.tildePath(p.vmDisks.dir), why))
			} else {
				a.removeVMDisks(ctx, a.vmDisksOf(p.imageIDs, refs), false, "them")
			}
		}
	}
	if len(p.gateway) > 0 {
		res := &openshell.GatewayApplyResult{}
		for _, f := range p.gateway {
			res.Files = append(res.Files, openshell.AppliedFile{Path: f.Path, Backup: f.Backup})
		}
		err := a.Gateway.Rollback(ctx, res)
		switch {
		case errors.Is(err, openshell.ErrNoGatewayService):
			// A gateway run another way, which DefenseClaw cannot restart.
			a.ok("restored the OpenShell gateway configuration; restart the gateway yourself, the way you started it, so it runs on it")
		case err != nil:
			fail("restore the gateway configuration", err)
		default:
			a.ok("restored the OpenShell gateway configuration and restarted it")
		}
		if err == nil || errors.Is(err, openshell.ErrNoGatewayService) {
			if r, err := a.loadReceipt(); err == nil {
				r.GatewayFiles = nil
				_ = a.saveReceipt(r)
			}
			// Every edit of a gateway file (setup, doctor --fix, the TUI)
			// kept a backup; restored, the files need none of them.
			removed := 0
			for _, f := range p.gateway {
				for _, b := range gatewayBackups(f.Path) {
					if err := os.Remove(b); err == nil {
						removed++
					} else {
						fail("remove the backup "+b, err)
					}
				}
			}
			if removed > 0 {
				a.ok("removed the " + plural(int64(removed), "backup", "backups") + " DefenseClaw made of the gateway configuration")
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
	a.pruneWrapperFiles()
	if p.disable {
		if err := a.patchConfig(map[string]any{"openshell.enabled": false, "openshell.wrappers": []string{}}); err != nil {
			a.warn("could not turn openshell.enabled off: " + err.Error())
		} else {
			a.ok("openshell.enabled is off")
		}
	}
	if len(errs) > 0 {
		return &Silent{Err: errors.Join(errs...)}
	}
	a.ok("teardown complete; OpenShell itself is still installed")
	return nil
}
