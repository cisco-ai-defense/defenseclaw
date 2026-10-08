// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// IDE inventory: every IDE installation in each scanned home and every
// extension or plugin it has, AI or not, with its enabled state and the
// account that owns the home. The parsers live in ideplugins; this file
// attributes, hashes and classifies their output and tracks its lifecycle.

const (
	// MaxIDEPluginsPerUser bounds one home's plugin list.
	MaxIDEPluginsPerUser = ideplugins.DefaultMaxPlugins
	// maxIDEInstallationsPerUser bounds one home's installation list in a
	// per-user report.
	maxIDEInstallationsPerUser = 1024
)

// IDEInventory is the IDE installation and plugin list of one full scan.
// A published inventory is shared read-only; never mutate one returned by
// ContinuousDiscoveryService.IDEInventory.
type IDEInventory struct {
	Scope         string            `json:"scope"`
	ScannedAt     time.Time         `json:"scanned_at"`
	Installations []IDEInstallation `json:"installations"`
	Plugins       []IDEPlugin       `json:"plugins"`
	Partial       bool              `json:"partial,omitempty"`
	// Removed lists the previous scan's plugins this scan no longer found.
	// It feeds lifecycle telemetry only.
	Removed []IDEPlugin `json:"-"`
	// Carried is set on a process-only scan, which reuses the last full
	// scan's list without reading the IDEs again.
	Carried bool `json:"-"`
	// persist asks RecordScan to write the lists: when they changed, and
	// at least every ideRecordInterval so retention pruning never drops
	// the last recorded inventory.
	persist bool
	// savedPlugins includes baseline rows retained from partial installations.
	savedPlugins []IDEPlugin
}

// ideRecordInterval is how long an unchanged IDE inventory goes without
// being written to the history store again.
const ideRecordInterval = 12 * time.Hour

// IDEInstallation is one IDE installation (or remote server) in a home.
type IDEInstallation struct {
	InstallID  string    `json:"install_id"`
	UserID     string    `json:"user_id,omitempty"`
	UserName   string    `json:"user,omitempty"`
	Family     string    `json:"ide_family"`
	Product    string    `json:"ide_product"`
	Channel    string    `json:"channel,omitempty"`
	RemoteKind string    `json:"remote_kind,omitempty"`
	Version    string    `json:"version,omitempty"`
	PathHash   string    `json:"path_hash"`
	Partial    bool      `json:"partial,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
}

// IDEPlugin is one extension or plugin of an installation.
type IDEPlugin struct {
	Fingerprint   string     `json:"fingerprint"`
	UserID        string     `json:"user_id,omitempty"`
	UserName      string     `json:"user,omitempty"`
	InstallID     string     `json:"install_id"`
	Family        string     `json:"ide_family"`
	Product       string     `json:"ide_product"`
	PluginID      string     `json:"plugin_id"`
	DisplayName   string     `json:"display_name,omitempty"`
	Publisher     string     `json:"publisher,omitempty"`
	Version       string     `json:"version,omitempty"`
	Enabled       string     `json:"enabled"`
	EnabledSource string     `json:"enabled_source,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	IsAI          bool       `json:"is_ai"`
	AISignatureID string     `json:"ai_signature_id,omitempty"`
	PathHash      string     `json:"path_hash,omitempty"`
	InstalledAt   *time.Time `json:"installed_at,omitempty"`
	LastSeen      time.Time  `json:"last_seen"`
	// State is the lifecycle state against the previous full scan (new,
	// changed or seen); it feeds telemetry only.
	State string `json:"-"`
}

// IDEInventoryCounts summarizes an inventory for /api/v1/ai-usage.
type IDEInventoryCounts struct {
	Total         int            `json:"total"`
	AI            int            `json:"ai"`
	Disabled      int            `json:"disabled"`
	Users         int            `json:"users"`
	Installations int            `json:"installations"`
	ByIDE         map[string]int `json:"by_ide"`
}

// Counts summarizes the inventory; a nil inventory has zero counts.
func (inv *IDEInventory) Counts() IDEInventoryCounts {
	out := IDEInventoryCounts{ByIDE: map[string]int{}}
	if inv == nil {
		return out
	}
	users := map[string]bool{}
	for _, p := range inv.Plugins {
		out.Total++
		if p.IsAI {
			out.AI++
		}
		if p.Enabled == ideplugins.EnabledOff {
			out.Disabled++
		}
		out.ByIDE[p.Product]++
		if key := ideUserKey(p.UserID, p.UserName); key != "" {
			users[key] = true
		}
	}
	for _, inst := range inv.Installations {
		if key := ideUserKey(inst.UserID, inst.UserName); key != "" {
			users[key] = true
		}
	}
	out.Users = len(users)
	out.Installations = len(inv.Installations)
	return out
}

func ideUserKey(id, name string) string {
	if id != "" {
		return "id:" + id
	}
	if name != "" {
		return "name:" + strings.ToLower(name)
	}
	return ""
}

// ideOwner is the account a home's rows are attributed to.
type ideOwner struct{ id, name string }

// ideAIIndex maps each family's plugin ids to the catalog signature that
// names them.
type ideAIIndex map[string]map[string]AISignature

func newIDEAIIndex(catalog []AISignature) ideAIIndex {
	idx := ideAIIndex{}
	put := func(family string, ids []string, sig AISignature) {
		if idx[family] == nil {
			idx[family] = map[string]AISignature{}
		}
		for _, id := range ids {
			if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
				if _, taken := idx[family][id]; !taken {
					idx[family][id] = sig
				}
			}
		}
	}
	for _, sig := range catalog {
		put(ideplugins.FamilyVSCode, sig.ExtensionIDs, sig)
		put(ideplugins.FamilyVisualStudio, sig.ExtensionIDs, sig)
		put(ideplugins.FamilyJetBrains, sig.JetBrainsPluginIDs, sig)
		put(ideplugins.FamilyZed, sig.ZedExtensionIDs, sig)
		put(ideplugins.FamilyVim, sig.VimPlugins, sig)
		// The Devin vendor's plugins keep their pre-rename ids, which the
		// catalog does not spell; legacyconnector owns them.
		if sig.ID == legacyconnector.Replacement {
			put(ideplugins.FamilyVSCode, legacyconnector.VSCodeExtensionIDs, sig)
			put(ideplugins.FamilyJetBrains, legacyconnector.JetBrainsPluginIDs, sig)
			put(ideplugins.FamilyVim, legacyconnector.VimPlugins, sig)
		}
	}
	return idx
}

func (idx ideAIIndex) match(family, id string) (AISignature, bool) {
	sig, ok := idx[family][strings.ToLower(strings.TrimSpace(id))]
	return sig, ok
}

// Some marketplace AI extensions are newer than the curated signature catalog.
// Exact IDs cover established products; the narrow description rule covers
// new publishers that describe their own extension as an AI coding tool.
var marketplaceAIExtensions = map[string]bool{
	"augment.vscode-augment":                 true,
	"kilocode.kilo-code":                     true,
	"rjmacarthy.twinny":                      true,
	"genieai.chatgpt-vscode":                 true,
	"gitlab.gitlab-workflow":                 true,
	"google.gemini-cli-vscode-ide-companion": true,
	"sst-dev.opencode":                       true,
	"visualstudioexptteam.vscodeintellicode": true,
}

func (idx ideAIIndex) matchPlugin(family string, p ideplugins.Plugin) (AISignature, bool) {
	if sig, ok := idx.match(family, p.ID); ok {
		return sig, true
	}
	if family != ideplugins.FamilyVSCode {
		return AISignature{}, false
	}
	description := strings.ToLower(p.Description)
	aiDescription := strings.Contains(description, "ai coding") ||
		strings.Contains(description, "ai code completion") ||
		strings.Contains(description, "ai-powered code") ||
		strings.Contains(description, "llm coding") ||
		strings.Contains(description, "chatgpt")
	if !marketplaceAIExtensions[strings.ToLower(p.ID)] && !aiDescription {
		return AISignature{}, false
	}
	return AISignature{
		ID: "ide-" + strings.ToLower(p.ID), Name: p.DisplayName,
		Vendor: p.Publisher, Category: "editor_extension", Confidence: 0.9,
	}, true
}

// detectEditorExtensions reads every scanned home's IDEs. It returns the
// AI editor-extension signals (one per signature, IDE installation and
// account, attributed through the home's owner) and the full IDE
// inventory. The Secure Client profile keeps the historical detector and
// no inventory.
func (s *ContinuousDiscoveryService) detectEditorExtensions() ([]AISignal, *IDEInventory) {
	if s.opts.SecureClient {
		return s.detectEditorExtensionsLegacy(), nil
	}
	homes := s.homesToScan()
	serviceContext := len(s.opts.homeOwners) > 0 || len(homes) > 1
	index := newIDEAIIndex(s.catalog)
	now := time.Now().UTC()
	inv := &IDEInventory{Scope: s.ideInventoryScope(), ScannedAt: now}
	var signals []AISignal
	for _, home := range homes {
		// Only a user's own gateway follows links: a link a user planted
		// toward another readable home must not put that account's
		// plugins in a managed inventory (GAP-0396).
		limits := ideplugins.Limits{FollowSymlinks: !serviceContext && !s.userHomeScan}
		if !serviceContext {
			limits.RoamingAppData, limits.LocalAppData = platformIDEAppData(home)
		}
		installs := ideplugins.Scan(home, runtime.GOOS, limits)
		signals = append(signals, s.ideSignals(installs, index)...)
		inv.add(installs, s.ideOwnerForHome(home, serviceContext), index, now)
	}
	if runtime.GOOS == "windows" {
		machine := ideplugins.ScanMachine(runtime.GOOS, ideplugins.Limits{ProgramFiles: programFilesDirs()})
		signals = append(signals, s.ideSignals(machine, index)...)
		inv.add(machine, ideOwner{}, index, now)
	}
	if inv.Scope == config.IDEInventoryOff {
		return signals, nil
	}
	inv.applyScope()
	return signals, inv
}

func (s *ContinuousDiscoveryService) ideInventoryScope() string {
	return config.AIDiscoveryConfig{IDEInventory: s.opts.IDEInventory}.EffectiveIDEInventory()
}

// ideSignals turns AI plugins into editor_extension signals. The evidence
// is the installation's extensions directory, so a version update keeps
// the signal's fingerprint and its owner is the home that holds it.
func (s *ContinuousDiscoveryService) ideSignals(installs []ideplugins.Install, index ideAIIndex) []AISignal {
	var out []AISignal
	for _, inst := range installs {
		seen := map[string]bool{}
		for _, p := range inst.Plugins {
			sig, ok := index.matchPlugin(inst.Family, p)
			if !ok || seen[sig.ID] || inst.Root == "" {
				continue
			}
			seen[sig.ID] = true
			out = append(out, s.signalFromPath(sig, SignalEditorExtension, "editor_extension", inst.Root))
		}
	}
	return out
}

// legacyEditorExtensionRows matches the editor-extension rows of 0.8.x and
// 1.0.0 to the signals that replace them. Those builds keyed a signal on the
// matched extension id (signalFromValue, as detectEditorExtensionsLegacy
// still does for Secure Client); ideSignals keys it on the installation. A
// full scan's editor-extension signal with no stored row takes the oldest
// stored row of its signature's extension ids as its predecessor, and those
// rows are replaced rather than gone: an upgrade keeps first-seen times and
// reports no removal of a tool that is still installed. Remove once
// upgrades from 0.8.x state files are no longer supported.
func (s *ContinuousDiscoveryService) legacyEditorExtensionRows(prevMap map[string]aiStoredSignal, signals []AISignal, full bool) (map[string]aiStoredSignal, map[string]bool) {
	if !full || s.opts.SecureClient || len(prevMap) == 0 {
		return nil, nil
	}
	emitted := make(map[string]bool, len(signals))
	for _, sig := range signals {
		emitted[sig.Fingerprint] = true
	}
	catalog := make(map[string]AISignature, len(s.catalog))
	for _, sig := range s.catalog {
		catalog[sig.ID] = sig
	}
	predecessors, replaced := map[string]aiStoredSignal{}, map[string]bool{}
	for _, sig := range signals {
		if _, stored := prevMap[sig.Fingerprint]; stored || sig.Detector != "editor_extension" {
			continue
		}
		signature := catalog[sig.SignatureID]
		for _, ext := range signature.ExtensionIDs {
			fp := s.signalFromValue(signature, SignalEditorExtension, "editor_extension", strings.ToLower(ext)).Fingerprint
			old, ok := prevMap[fp]
			if !ok || emitted[fp] || old.Detector != "editor_extension" {
				continue
			}
			replaced[fp] = true
			if first, have := predecessors[sig.Fingerprint]; !have || old.FirstSeen.Before(first.FirstSeen) {
				predecessors[sig.Fingerprint] = old
			}
		}
	}
	return predecessors, replaced
}

// ideOwnerForHome names the account of a home: the profile owner on a
// service-context scan, otherwise the account this process runs as.
func (s *ContinuousDiscoveryService) ideOwnerForHome(home string, serviceContext bool) ideOwner {
	if owner, ok := s.homeOwnerForPath(home); ok {
		return ideOwner{id: owner.UserID, name: owner.UserName}
	}
	if serviceContext || s.opts.UserScanDir != "" {
		return ideOwner{}
	}
	return currentIDEOwner()
}

// currentIDEOwner is the account this process runs as; replaceable in tests.
var currentIDEOwner = func() ideOwner {
	u, err := user.Current()
	if err != nil {
		return ideOwner{}
	}
	// The bare account name, as agent identities and hook records spell it
	// (DOMAIN\name and user@realm are the principal, reported separately).
	return ideOwner{id: u.Uid, name: useridentity.BareAccountName(u.Username)}
}

// programFilesDirs lists the Program Files roots of the machine-wide IDE
// scan; replaceable in tests, which must not read the host's real
// Visual Studio installations.
var programFilesDirs = func() []string {
	var out []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if dir := strings.TrimSpace(os.Getenv(env)); dir != "" {
			out = append(out, dir)
		}
	}
	return out
}

// add converts one home's installations into hashed, attributed rows.
func (inv *IDEInventory) add(installs []ideplugins.Install, owner ideOwner, index ideAIIndex, now time.Time) {
	for _, inst := range installs {
		row := IDEInstallation{
			UserID: owner.id, UserName: owner.name,
			Family: inst.Family, Product: inst.Product, Channel: inst.Channel,
			RemoteKind: inst.RemoteKind, Version: inst.Version,
			PathHash: hashPath(inst.Root), Partial: inst.Partial, LastSeen: now,
		}
		row.InstallID = ideInstallID(row)
		if inst.Partial {
			inv.Partial = true
		}
		inv.Installations = append(inv.Installations, row)
		for _, p := range inst.Plugins {
			plugin := IDEPlugin{
				UserID: owner.id, UserName: owner.name,
				Family: inst.Family, Product: inst.Product,
				PluginID: p.ID, DisplayName: p.DisplayName, Publisher: p.Publisher,
				Version: p.Version, Enabled: p.Enabled, EnabledSource: p.EnabledSource,
				Scope: p.Scope, PathHash: hashPath(p.Path), InstalledAt: p.InstalledAt, LastSeen: now,
				InstallID: row.InstallID,
			}
			plugin.Fingerprint = idePluginFingerprint(plugin)
			if sig, ok := index.matchPlugin(inst.Family, p); ok {
				plugin.IsAI, plugin.AISignatureID = true, sig.ID
			}
			inv.Plugins = append(inv.Plugins, plugin)
		}
	}
}

func idePluginFingerprint(p IDEPlugin) string {
	return hashValue("ide-plugin/v1\x00" + p.InstallID + "\x00" + strings.ToLower(p.PluginID) + "\x00" + p.Scope)
}

func ideInstallID(inst IDEInstallation) string {
	key := strings.Join([]string{"ide-install/v1", inst.UserID, inst.Family, inst.Product, inst.Channel, inst.RemoteKind, inst.PathHash}, "\x00")
	return "ide-" + hashHex(key)[:16]
}

// applyScope keeps only AI plugins under ai_only, and sorts the lists.
func (inv *IDEInventory) applyScope() {
	if inv.Scope == config.IDEInventoryAIOnly {
		kept := inv.Plugins[:0]
		for _, p := range inv.Plugins {
			if p.IsAI {
				kept = append(kept, p)
			}
		}
		inv.Plugins = kept
	}
	inv.sort()
}

func (inv *IDEInventory) sort() {
	seen := map[string]bool{}
	plugins := inv.Plugins[:0]
	for _, p := range inv.Plugins {
		if !seen[p.Fingerprint] {
			seen[p.Fingerprint] = true
			plugins = append(plugins, p)
		}
	}
	inv.Plugins = plugins
	sort.SliceStable(inv.Installations, func(i, j int) bool {
		a, b := inv.Installations[i], inv.Installations[j]
		return a.UserName+"\x00"+a.UserID+"\x00"+a.Product+"\x00"+a.InstallID < b.UserName+"\x00"+b.UserID+"\x00"+b.Product+"\x00"+b.InstallID
	})
	sort.SliceStable(inv.Plugins, func(i, j int) bool {
		a, b := inv.Plugins[i], inv.Plugins[j]
		ka := a.UserName + "\x00" + a.UserID + "\x00" + a.Product + "\x00" + strings.ToLower(a.PluginID) + "\x00" + a.Fingerprint
		kb := b.UserName + "\x00" + b.UserID + "\x00" + b.Product + "\x00" + strings.ToLower(b.PluginID) + "\x00" + b.Fingerprint
		return ka < kb
	})
}

// mergeIDEInventory folds b into a; either may be nil.
func mergeIDEInventory(a, b *IDEInventory) *IDEInventory {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	a.Installations = append(a.Installations, b.Installations...)
	a.Plugins = append(a.Plugins, b.Plugins...)
	a.Partial = a.Partial || b.Partial
	a.sort()
	return a
}

// IDEInventory returns the last full scan's IDE inventory, or nil when the
// inventory is off or no full scan has finished. It is shared: read it,
// never change it.
func (s *ContinuousDiscoveryService) IDEInventory() *IDEInventory {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastIDE
}

// finishIDEInventory classifies a full scan's inventory against the
// previous one (new, changed, seen, and the removed rows), or carries the
// previous one forward on a process-only scan.
func (s *ContinuousDiscoveryService) finishIDEInventory(inv *IDEInventory, full bool, now time.Time) *IDEInventory {
	if s.opts.SecureClient {
		return nil
	}
	if !full {
		s.mu.RLock()
		prev := s.lastIDE
		s.mu.RUnlock()
		if prev == nil {
			return nil
		}
		carried := *prev
		carried.Removed, carried.Carried, carried.persist = nil, true, false
		return &carried
	}
	if inv == nil {
		s.ideBaseline = nil
		return nil
	}
	if s.ideBaseline == nil {
		s.ideBaseline = s.loadIDEBaseline()
	}
	if inv.Scope == config.IDEInventoryAIOnly {
		// A row ai_only no longer collects leaves the baseline silently: a
		// removal record would export the very plugin ai_only withholds.
		for fp, prev := range s.ideBaseline {
			if !prev.IsAI {
				delete(s.ideBaseline, fp)
			}
		}
	}
	partial := map[string]bool{}
	for _, inst := range inv.Installations {
		if inst.Partial {
			partial[inst.InstallID] = true
		}
	}
	for i := range inv.Installations {
		inv.Installations[i].LastSeen = now
	}
	current := make(map[string]IDEPlugin, len(inv.Plugins))
	for i := range inv.Plugins {
		p := &inv.Plugins[i]
		p.LastSeen = now
		prev, ok := s.ideBaseline[p.Fingerprint]
		switch {
		case !ok:
			p.State = AIStateNew
		case prev.Version != p.Version || prev.Enabled != p.Enabled || prev.IsAI != p.IsAI:
			p.State = AIStateChanged
		default:
			p.State = AIStateSeen
		}
		current[p.Fingerprint] = *p
	}
	for fp, prev := range s.ideBaseline {
		if _, ok := current[fp]; ok {
			continue
		}
		if partial[prev.InstallID] {
			// A limit cut this installation short; keep the row rather
			// than report a removal the scan cannot prove.
			current[fp] = prev
			continue
		}
		prev.State = AIStateGone
		inv.Removed = append(inv.Removed, prev)
	}
	sort.Slice(inv.Removed, func(i, j int) bool { return inv.Removed[i].Fingerprint < inv.Removed[j].Fingerprint })
	inv.ScannedAt = now
	changed := len(inv.Removed) > 0
	for _, p := range inv.Plugins {
		changed = changed || p.State != AIStateSeen
	}
	if changed || now.Sub(s.ideRecordedAt) >= ideRecordInterval {
		inv.persist = true
		inv.savedPlugins = make([]IDEPlugin, 0, len(current))
		for _, p := range current {
			inv.savedPlugins = append(inv.savedPlugins, p)
		}
		sort.Slice(inv.savedPlugins, func(i, j int) bool {
			return inv.savedPlugins[i].Fingerprint < inv.savedPlugins[j].Fingerprint
		})
	}
	s.ideBaseline = current
	return inv
}

// loadIDEBaseline reads the last recorded plugin list so a restart does not
// report every plugin as newly discovered.
func (s *ContinuousDiscoveryService) loadIDEBaseline() map[string]IDEPlugin {
	out := map[string]IDEPlugin{}
	if s.invStore == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if at, err := s.invStore.LatestIDEInventoryRecordedAt(ctx); err == nil {
		s.ideRecordedAt = at
	}
	plugins, err := s.invStore.LatestIDEPlugins(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ai-discovery] ide inventory baseline: %v\n", err)
		return out
	}
	for _, p := range plugins {
		out[p.Fingerprint] = p
		if p.LastSeen.After(s.ideRecordedAt) {
			s.ideRecordedAt = p.LastSeen
		}
	}
	return out
}

// attributeUserScanIDE binds a spooled IDE inventory to its account,
// re-deriving every hash in the account's namespace (see
// attributeUserScanSignal).
func attributeUserScanIDE(inv *IDEInventory, namespace func(string) string, uid, user string) *IDEInventory {
	if inv == nil {
		return nil
	}
	out := &IDEInventory{Scope: inv.Scope, ScannedAt: inv.ScannedAt, Partial: inv.Partial}
	out.Installations = make([]IDEInstallation, len(inv.Installations))
	installIDs := map[string]string{}
	for i, inst := range inv.Installations {
		old := inst.InstallID
		inst.UserID, inst.UserName = uid, user
		inst.PathHash = namespace(inst.PathHash)
		inst.InstallID = ideInstallID(inst)
		installIDs[old] = inst.InstallID
		out.Installations[i] = inst
	}
	out.Plugins = make([]IDEPlugin, 0, len(inv.Plugins))
	for _, p := range inv.Plugins {
		installID, ok := installIDs[p.InstallID]
		if !ok {
			continue
		}
		p.UserID, p.UserName = uid, user
		p.PathHash = namespace(p.PathHash)
		p.InstallID = installID
		p.Fingerprint = idePluginFingerprint(p)
		out.Plugins = append(out.Plugins, p)
	}
	return out
}

var (
	ideTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	ideFamilies     = map[string]bool{
		ideplugins.FamilyVSCode: true, ideplugins.FamilyJetBrains: true, ideplugins.FamilyVisualStudio: true,
		ideplugins.FamilyZed: true, ideplugins.FamilyEclipse: true, ideplugins.FamilyVim: true,
	}
	ideEnabledStates = map[string]bool{
		ideplugins.EnabledOn: true, ideplugins.EnabledOff: true,
		ideplugins.EnabledClientSideUnknown: true, ideplugins.EnabledUnknown: true,
	}
)

// validateUserScanIDE bounds a per-user report's IDE inventory.
func validateUserScanIDE(inv *IDEInventory) error {
	if inv == nil {
		return nil
	}
	if len(inv.Installations) > maxIDEInstallationsPerUser || len(inv.Plugins) > MaxIDEPluginsPerUser {
		return errors.New("ide inventory exceeds the per-user limit")
	}
	switch inv.Scope {
	case config.IDEInventoryAll, config.IDEInventoryAIOnly:
	default:
		return errors.New("ide inventory scope is invalid")
	}
	installs := map[string]bool{}
	for _, inst := range inv.Installations {
		if err := ideInstallationError(inst); err != nil {
			return err
		}
		installs[inst.InstallID] = true
	}
	for _, p := range inv.Plugins {
		if err := idePluginError(p, installs); err != nil {
			return err
		}
	}
	return nil
}

func ideInstallationError(inst IDEInstallation) error {
	if !ideFamilies[inst.Family] || !ideTokenPattern.MatchString(inst.Product) || !isSHA256Hash(inst.PathHash) {
		return errors.New("ide installation fields are invalid")
	}
	for _, value := range []string{inst.InstallID, inst.Channel, inst.RemoteKind, inst.Version} {
		if !userScanText(value, maxUserScanField) {
			return errors.New("ide installation fields must be short printable text")
		}
	}
	return nil
}

func idePluginError(p IDEPlugin, installs map[string]bool) error {
	if !installs[p.InstallID] || !ideFamilies[p.Family] || !ideTokenPattern.MatchString(p.Product) ||
		!ideEnabledStates[p.Enabled] || strings.TrimSpace(p.PluginID) == "" ||
		(p.PathHash != "" && !isSHA256Hash(p.PathHash)) {
		return errors.New("ide plugin fields are invalid")
	}
	for _, value := range []string{p.PluginID, p.DisplayName, p.Publisher, p.Version, p.EnabledSource, p.Scope, p.AISignatureID} {
		if !userScanText(value, maxUserScanField) {
			return errors.New("ide plugin fields must be short printable text")
		}
	}
	return nil
}

// boundUserScanIDE keeps a worker's IDE inventory within
// validateUserScanIDE. A row it would refuse, or one past the per-user
// limits, is dropped and the inventory marked partial, so one odd folder in
// a home costs that row, never the user's whole report.
func boundUserScanIDE(inv *IDEInventory) {
	installs := map[string]bool{}
	kept := inv.Installations[:0]
	for _, inst := range inv.Installations {
		if len(kept) < maxIDEInstallationsPerUser && ideInstallationError(inst) == nil {
			kept = append(kept, inst)
			installs[inst.InstallID] = true
		} else {
			inv.Partial = true
		}
	}
	inv.Installations = kept
	plugins := inv.Plugins[:0]
	for _, p := range inv.Plugins {
		if len(plugins) < MaxIDEPluginsPerUser && idePluginError(p, installs) == nil {
			plugins = append(plugins, p)
		} else {
			inv.Partial = true
		}
	}
	inv.Plugins = plugins
}

// sanitizeUserScanIDE strips the account a worker may have stamped; the
// gateway attributes rows from the guardian's record.
func sanitizeUserScanIDE(inv *IDEInventory) {
	if inv == nil {
		return
	}
	for i := range inv.Installations {
		inv.Installations[i].UserID, inv.Installations[i].UserName = "", ""
	}
	for i := range inv.Plugins {
		inv.Plugins[i].UserID, inv.Plugins[i].UserName = "", ""
	}
}
