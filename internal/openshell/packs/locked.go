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

package packs

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const lockedConstraint = "openshell.admin.locked"

// dropLockedFlags applies openshell.admin.locked to the run flags. A locked
// key keeps its configured value (what the run gets from the selected pack
// and the user's openshell keys without flags) against every flag that would
// loosen it, and each dropped flag is a Violation. Flags that only tighten a
// locked key still apply: --safe, --copy and --no-mcp; a --pack at least as
// strict as the configured pack in every setting (looserPackKey) when "pack"
// is locked, and otherwise in every setting of a locked key the pack decides
// (lockedPackKeys); a --profile at least as strict as the configured
// profile; --cpu and --memory at or below the configured request; and
// --unmask and --host-port entries the configuration already has.
func (r *resolver) dropLockedFlags(o config.OpenShellConfig, flags Flags) Flags {
	if len(r.admin.Locked) == 0 {
		return flags
	}
	// The pack the run uses without --pack. When it does not load, nothing
	// can be compared with it, and selectPack reports the error.
	baseline, err := r.configuredPack(o)
	if err != nil {
		baseline = nil
	}
	refuse := func(key, attempted, reason string) {
		detail := "your organization locked " + key
		if reason != "" {
			detail += "; " + reason
		}
		r.violate(Violation{
			Key: key, Source: SourceFlag, Attempted: attempted, Constraint: lockedConstraint,
			Detail: detail + "; the run uses the configured value",
		})
	}
	locked := r.admin.IsLocked

	// The profile goes first: the pack comparison needs the profile the run
	// ends up with.
	if profile := strings.TrimSpace(flags.Profile); profile != "" && locked("profile") {
		configured := strings.TrimSpace(o.Profile)
		if configured == "" && baseline != nil {
			configured = baseline.Profile()
		}
		if configured == "" || config.OpenShellProfileRank(profile) < config.OpenShellProfileRank(configured) {
			reason := ""
			if configured != "" {
				reason = "the configured profile is " + configured + " and a run may only pick a stricter one"
			}
			refuse("profile", "--profile "+flags.Profile, reason)
			flags.Profile = ""
		}
	}
	if ref := strings.TrimSpace(flags.Pack); ref != "" {
		if key, reason, ok := r.packFlagAllowed(o, flags, ref, baseline); !ok {
			refuse(key, "--pack "+flags.Pack, reason)
			flags.Pack = ""
		}
	}
	if flags.Yolo && !flags.Safe && locked("yolo") {
		configured := baseline != nil && baseline.Harness.Yolo
		if o.Yolo != nil {
			configured = *o.Yolo
		}
		if !configured {
			refuse("yolo", "--yolo", "the configured posture keeps the harness permission prompts")
			flags.Yolo = false
		}
	}
	// --copy (workdir.mode) and --no-mcp (mcp.import) only ever tighten.
	if len(flags.Unmask) > 0 && locked("workdir.unmask") {
		var configured []string
		if baseline != nil {
			configured = baseline.Workspace.Unmask
		}
		configured = mergeLists(configured, o.Workdir.Unmask)
		var kept, dropped []string
		for _, glob := range flags.Unmask {
			if containsString(configured, strings.TrimSpace(glob)) {
				kept = append(kept, glob)
			} else {
				dropped = append(dropped, glob)
			}
		}
		if len(dropped) > 0 {
			refuse("workdir.unmask", "--unmask "+strings.Join(dropped, ", "),
				"only files the configuration already shares stay visible")
			flags.Unmask = kept
		}
	}
	if len(flags.HostPorts) > 0 && locked("mcp.host_ports") {
		var kept, dropped []int
		for _, port := range flags.HostPorts {
			if containsInt(o.MCP.HostPorts, port) {
				kept = append(kept, port)
			} else {
				dropped = append(dropped, port)
			}
		}
		if len(dropped) > 0 {
			refuse("mcp.host_ports", "--host-port "+joinInts(dropped), "only the configured host ports can be opened")
			flags.HostPorts = kept
		}
	}
	if locked("resources") {
		var dropped []string
		if flags.CPU != "" && !quantityWithin(flags.CPU, o.Resources.CPU, config.ParseOpenShellCPU) {
			dropped, flags.CPU = append(dropped, "--cpu "+flags.CPU), ""
		}
		if flags.Memory != "" && !quantityWithin(flags.Memory, o.Resources.Memory, config.ParseOpenShellMemory) {
			dropped, flags.Memory = append(dropped, "--memory "+flags.Memory), ""
		}
		if len(dropped) > 0 {
			refuse("resources", strings.Join(dropped, " "), "a run may only ask for less than the configured resources")
		}
	}
	return flags
}

// configuredPack loads the pack a run uses without --pack: the required pack
// when openshell.admin sets one, else openshell.pack.
func (r *resolver) configuredPack(o config.OpenShellConfig) (*Pack, error) {
	if required := strings.TrimSpace(r.admin.RequiredPack); required != "" {
		return r.loadPack(required, o.PackDir, r.managed)
	}
	return r.loadPack(o.Pack, o.PackDir, false)
}

// loadPack loads a pack reference at most once per Resolve (LoadTrusted when
// trusted). dropLockedFlags compares the configured pack with a --pack, and
// selectPack must run exactly the pack that was compared, not a second read
// of a file the user can rewrite in between.
func (r *resolver) loadPack(ref, packDir string, trusted bool) (*Pack, error) {
	key := packCacheKey{ref: strings.TrimSpace(ref), trusted: trusted}
	if pack, ok := r.loaded[key]; ok {
		return pack, nil
	}
	load := Load
	if trusted {
		load = LoadTrusted
	}
	pack, err := load(key.ref, packDir)
	if err != nil {
		return nil, err
	}
	if r.loaded == nil {
		r.loaded = make(map[packCacheKey]*Pack)
	}
	r.loaded[key] = pack
	return pack, nil
}

type packCacheKey struct {
	ref     string
	trusted bool
}

// lockedPackKeys returns the locked keys whose configured value the pack
// decides for this run: "pack" itself, and "profile", "yolo",
// "workdir.mode" and "mcp.import" while neither the user's openshell key nor
// a tightening flag sets them. The pack always decides what
// "workdir.unmask" and "mcp.host_ports" protect (its masks and its host-port
// access); "resources" is never the pack's.
func (r *resolver) lockedPackKeys(o config.OpenShellConfig, flags Flags) []string {
	candidates := []struct {
		key     string
		decides bool
	}{
		{"pack", true},
		{"profile", strings.TrimSpace(o.Profile) == "" && strings.TrimSpace(flags.Profile) == ""},
		{"yolo", o.Yolo == nil && !flags.Safe},
		{"workdir.mode", o.Workdir.Mode == "" && !flags.Copy},
		{"workdir.unmask", true},
		{"mcp.import", o.MCP.Import == nil && !flags.NoMCP},
		{"mcp.host_ports", true},
	}
	var keys []string
	for _, c := range candidates {
		if c.decides && r.admin.IsLocked(c.key) {
			keys = append(keys, c.key)
		}
	}
	return keys
}

// packFlagAllowed reports whether --pack ref may replace the configured
// pack, and otherwise the locked key it would loosen and why. With "pack"
// locked the candidate must be at least as strict in every setting; with
// other keys locked, in the settings behind those keys. The candidate is
// loaded once, and selectPack runs that load.
func (r *resolver) packFlagAllowed(o config.OpenShellConfig, flags Flags, ref string, baseline *Pack) (string, string, bool) {
	keys := r.lockedPackKeys(o, flags)
	if len(keys) == 0 || (keys[0] != "pack" && strings.TrimSpace(r.admin.RequiredPack) != "") {
		// Nothing locked depends on the pack, or a required pack runs
		// whatever --pack says (selectPack reports that).
		return "", "", true
	}
	if baseline == nil {
		return keys[0], "", false
	}
	candidate, err := r.loadPack(ref, o.PackDir, false)
	if err != nil {
		return keys[0], "the pack could not be loaded to compare it with the configured " + baseline.Name + " pack", false
	}
	if candidate.Digest == baseline.Digest {
		return "", "", true
	}
	looser := func(key, setting string) (string, string, bool) {
		return key, fmt.Sprintf("the %s pack is looser than the configured %s pack in %s", candidate.Name, baseline.Name, setting), false
	}
	c, b := candidate, baseline
	for _, key := range keys {
		switch key {
		case "pack":
			profile := candidate.Profile()
			for _, chosen := range []string{o.Profile, flags.Profile} {
				if chosen = strings.TrimSpace(chosen); chosen != "" {
					profile = chosen
				}
			}
			if setting := looserPackKey(c, b, networkForProfile(profile)); setting != "" {
				return looser(key, setting)
			}
			// Every other locked key is covered.
			return "", "", true
		case "profile":
			if networkRank(c.Network.Mode) < networkRank(b.Network.Mode) {
				return looser(key, "network.mode")
			}
		case "yolo":
			if c.Harness.Yolo && !b.Harness.Yolo {
				return looser(key, "harness.yolo")
			}
		case "workdir.mode":
			if c.Workspace.Mode == config.OpenShellWorkdirMount && b.Workspace.Mode == config.OpenShellWorkdirCopy {
				return looser(key, "workspace.mode")
			}
		case "workdir.unmask":
			// The user's own masks and unmask entries apply over either pack.
			if !containsAll(mergeLists(c.Workspace.Masks, o.Workdir.Masks), b.Workspace.Masks) {
				return looser(key, "workspace.masks")
			}
			if len(b.Workspace.Masks) > 0 && !containsAll(mergeLists(b.Workspace.Unmask, o.Workdir.Unmask), c.Workspace.Unmask) {
				return looser(key, "workspace.unmask")
			}
		case "mcp.import":
			if c.MCP.Import && !b.MCP.Import {
				return looser(key, "mcp.import")
			}
		case "mcp.host_ports":
			if c.MCP.HostPorts && !b.MCP.HostPorts {
				return looser(key, "mcp.host_ports")
			}
		}
	}
	return "", "", true
}

// looserPackKey returns the first pack key in which candidate is looser than
// baseline, or "" when candidate is at least as strict in every setting.
// mode is the network mode the run would have with candidate: with the
// egress proxy off (deny) the egress lists and thresholds do not apply.
// Entries of DefenseClaw's curated allowlist (the balanced pack's) never
// count as a loosening; Resolve adds them itself whenever the profile asks
// for an allowlist.
func looserPackKey(candidate, baseline *Pack, mode string) string {
	c, b := candidate, baseline
	type check struct {
		key    string
		looser bool
	}
	checks := []check{
		{"network.mode", networkRank(c.Network.Mode) < networkRank(b.Network.Mode)},
		{"approvals.mode", approvalsRank(c.Approvals.Mode) < approvalsRank(b.Approvals.Mode)},
		{"harness.yolo", c.Harness.Yolo && !b.Harness.Yolo},
		{"harness.allowed", len(b.Harness.Allowed) > 0 &&
			(len(c.Harness.Allowed) == 0 || !containsAll(b.Harness.Allowed, c.Harness.Allowed))},
		{"workspace.mode", c.Workspace.Mode == config.OpenShellWorkdirMount && b.Workspace.Mode == config.OpenShellWorkdirCopy},
		{"workspace.masks", !containsAll(c.Workspace.Masks, b.Workspace.Masks)},
		// An unmask entry can only reveal what the baseline masks.
		{"workspace.unmask", len(b.Workspace.Masks) > 0 && !containsAll(b.Workspace.Unmask, c.Workspace.Unmask)},
		{"workspace.review", !containsAll(c.Workspace.Review, b.Workspace.Review)},
		{"workspace.max_upload_mb", c.Workspace.MaxUploadMB > b.Workspace.MaxUploadMB},
		{"mcp.import", c.MCP.Import && !b.MCP.Import},
		{"mcp.host_ports", c.MCP.HostPorts && !b.MCP.HostPorts},
		{"mcp.blocked_tools", !containsAll(c.MCP.BlockedTools, b.MCP.BlockedTools)},
		{"mcp.project_servers", c.MCP.ProjectServers == MCPProjectServersAllow && b.MCP.ProjectServers != MCPProjectServersAllow},
		{"hooks.fail_mode", c.Hooks.FailMode != b.Hooks.FailMode},
		// on_tamper: alert is looser than stop.
		{"hooks.on_tamper", c.Hooks.OnTamper == OnTamperAlert && b.Hooks.OnTamper == OnTamperStop},
		// on_silence: alert is looser than stop, and a longer wait looser
		// than a shorter one.
		{"hooks.on_silence", c.Hooks.OnSilence == OnSilenceAlert && b.Hooks.OnSilence == OnSilenceStop},
		{"hooks.silence_after", c.Hooks.SilenceAfterDuration() > b.Hooks.SilenceAfterDuration()},
	}
	if mode != NetworkDeny {
		allowed := append(append([]string{}, b.Egress.Allow...), curatedAllowlist()...)
		checks = append(checks,
			check{"egress.feeds", !containsAll(c.Egress.Feeds, b.Egress.Feeds)},
			check{"egress.block", !globsCovered(b.Egress.Block, c.Egress.Block)},
			check{"egress.allow", !globsCovered(c.Egress.Allow, allowed)},
			check{"egress.ports", !containsAllInts(b.Egress.Ports, c.Egress.Ports)},
			check{"egress.large_upload_mb", b.Egress.LargeUploadMB > 0 &&
				(c.Egress.LargeUploadMB == 0 || c.Egress.LargeUploadMB > b.Egress.LargeUploadMB)},
			check{"egress.block_large_uploads", b.Egress.BlockLargeUploads && !c.Egress.BlockLargeUploads},
		)
	}
	for _, ch := range checks {
		if ch.looser {
			return ch.key
		}
	}
	return ""
}

func networkRank(mode string) int {
	return config.OpenShellProfileRank(profileForNetwork(mode))
}

func curatedAllowlist() []string {
	curated, err := Builtin(config.OpenShellProfileBalanced)
	if err != nil {
		return nil
	}
	return curated.Egress.Allow
}

// quantityWithin reports whether a requested resource quantity is at most
// the configured request ("" is unlimited). A malformed request passes, so
// resolveResources reports it; a malformed configured value never does.
func quantityWithin(requested, configured string, parse func(string) (int64, error)) bool {
	want, err := parse(requested)
	if err != nil || strings.TrimSpace(configured) == "" {
		return true
	}
	have, err := parse(configured)
	return err == nil && want <= have
}

// containsAll reports whether list holds every item.
func containsAll(list, items []string) bool {
	for _, item := range items {
		if !containsString(list, item) {
			return false
		}
	}
	return true
}

func containsAllInts(list, items []int) bool {
	for _, item := range items {
		if !containsInt(list, item) {
			return false
		}
	}
	return true
}

// globsCovered reports whether every host glob in inner is covered by one in
// outer (hostGlobCovers).
func globsCovered(inner, outer []string) bool {
	for _, glob := range inner {
		covered := false
		for _, candidate := range outer {
			if hostGlobCovers(candidate, glob) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// hostGlobCovers reports whether every host inner matches (see MatchHost)
// also matches outer. A pattern that does not parse covers only its own
// spelling.
func hostGlobCovers(outer, inner string) bool {
	switch {
	case strings.TrimSpace(outer) == "*":
		return true
	case strings.TrimSpace(inner) == "*":
		return false
	}
	o, errOuter := config.ParseOpenShellEgressPattern(outer)
	i, errInner := config.ParseOpenShellEgressPattern(inner)
	if errOuter != nil || errInner != nil {
		return config.NormalizeOpenShellEgressPattern(outer) == config.NormalizeOpenShellEgressPattern(inner)
	}
	return o.Covers(i)
}
