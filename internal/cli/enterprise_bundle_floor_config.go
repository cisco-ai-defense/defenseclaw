// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// An older release refuses a config.yaml that sets a key it does not have
// (its v8 schema has additionalProperties false, so a key set to null counts
// too), and its package finds that out only in postinstall, after its files
// replaced this release's. A managed macOS rollback to 1.0.10 over
// ai_discovery.include_skill_manifests failed config_invalid and left 1.0.10
// binaries over 1.0.11 state (rel-1-0-10 GAP-2035). floor-check is the only
// code of this release such a rollback runs, before any file is replaced
// (see enterprise_bundle_floor_route.go), so it refuses the downgrade there
// and names the keys. The managed config is the administrator's, so it is
// never edited here; the OSS rollback (upgrade_shim) sets the same keys
// aside instead.
//
// newerConfigKeys is upgrade_shim's NEWER_CONFIG_KEYS, NEWER_CONFIG_SUBTREES
// and NEWER_ITEM_KEYS, with the first release that has each key: [] is
// every item of a list and * every entry of a map.
// cli/tests/test_upgrade_shim.py keeps the two lists equal.
var newerConfigKeys = []struct {
	path  string
	since [3]int
}{
	{"openshell.trusted_ca_bundle", [3]int{1, 0, 3}},
	{"guardrail.internal_domains", [3]int{1, 0, 6}},
	{"guardrail.chains", [3]int{1, 0, 6}},
	{"connectors", [3]int{1, 0, 6}},
	{"connectors.openclaw", [3]int{1, 0, 10}},
	{"guardrail.cascade", [3]int{1, 0, 10}},
	{"guardrail.secret_flow", [3]int{1, 0, 10}},
	{"guardrail.effects_rules_tier", [3]int{1, 0, 10}},
	{"guardrail.judge.intent_scope", [3]int{1, 0, 10}},
	{"decision_model.block_risk_score", [3]int{1, 0, 10}},
	{"decision_model.escalate_rule_flagged", [3]int{1, 0, 10}},
	{"decision_model.flow_guard", [3]int{1, 0, 10}},
	{"decision_model.history_tool_results", [3]int{1, 0, 10}},
	{"decision_model.history_turns", [3]int{1, 0, 10}},
	{"decision_model.protocol", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.routing", [3]int{1, 0, 10}},
	{"observability.local.keep_rejected_records", [3]int{1, 0, 10}},
	{"observability.local.rejected_records_max_rows", [3]int{1, 0, 10}},
	{"observability.pricing", [3]int{1, 0, 10}},
	{"observability.tokenomics", [3]int{1, 0, 10}},
	{"routing.admin", [3]int{1, 0, 10}},
	{"routing.allow_user_override", [3]int{1, 0, 10}},
	{"routing.categories", [3]int{1, 0, 10}},
	{"routing.classifier", [3]int{1, 0, 10}},
	{"routing.context", [3]int{1, 0, 10}},
	{"routing.default_alias", [3]int{1, 0, 10}},
	{"routing.min_confidence", [3]int{1, 0, 10}},
	{"routing.models[].apis", [3]int{1, 0, 10}},
	{"routing.models[].bedrock", [3]int{1, 0, 10}},
	{"routing.models[].credential", [3]int{1, 0, 10}},
	{"routing.on_classifier_error", [3]int{1, 0, 10}},
	{"routing.route_only", [3]int{1, 0, 10}},
	{"routing.sensitive", [3]int{1, 0, 10}},
	{"routing.systemone", [3]int{1, 0, 10}},
	{"guardrail.history_seen_max", [3]int{1, 0, 10}},
	{"guardrail.max_body_values", [3]int{1, 0, 10}},
	{"openshell.admin.actor_secrets", [3]int{1, 0, 10}},
	{"openshell.admin.ask_hosts", [3]int{1, 0, 10}},
	{"openshell.admin.ask_timeout", [3]int{1, 0, 10}},
	{"openshell.admin.idle_suspend_after", [3]int{1, 0, 10}},
	{"openshell.admin.idle_suspend_tasks", [3]int{1, 0, 10}},
	{"openshell.admin.runtimes", [3]int{1, 0, 10}},
	{"openshell.admin.sandbox_class", [3]int{1, 0, 10}},
	{"openshell.admin.unattended_asks", [3]int{1, 0, 10}},
	{"openshell.admin.git_push", [3]int{1, 0, 11}},
	{"openshell.admin.url_rules", [3]int{1, 0, 10}},
	{"openshell.vault", [3]int{1, 0, 11}},
	{"substrate", [3]int{1, 0, 10}},
	{"substrate.bundles.oci", [3]int{1, 0, 11}},
	{"substrate.identity.kube_sign_in", [3]int{1, 0, 11}},
	{"substrate.skills", [3]int{1, 0, 11}},
	{"substrate.usage", [3]int{1, 0, 11}},
	{"substrate.activity", [3]int{1, 0, 11}},
	{"substrate.admin.git_push", [3]int{1, 0, 11}},
	{"substrate.egress.no_swap_hosts", [3]int{1, 0, 11}},
	{"substrate.files", [3]int{1, 0, 11}},
	{"substrate.git", [3]int{1, 0, 11}},
	{"substrate.identity.revocation", [3]int{1, 0, 11}},
	{"substrate.interactive", [3]int{1, 0, 11}},
	{"substrate.launcher", [3]int{1, 0, 11}},
	{"substrate.relay_cert_reissue", [3]int{1, 0, 11}},
	{"substrate.relay_tls", [3]int{1, 0, 11}},
	{"substrate.secret_templates", [3]int{1, 0, 11}},
	{"substrate.self_service_secrets", [3]int{1, 0, 11}},
	{"enterprise.openshell.allow_downgrade", [3]int{1, 0, 11}},
	{"ai_discovery.include_skill_content_hashes", [3]int{1, 0, 11}},
	{"ai_discovery.include_skill_manifests", [3]int{1, 0, 11}},
	{"guardrail.include_hook_event_content", [3]int{1, 0, 11}},
	{"notifications.substrate", [3]int{1, 0, 11}},
	{"guardrail.connectors.*.cascade", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.cascade", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.connectors.*.cascade", [3]int{1, 0, 10}},
	{"application_protection.guardrail.cascade", [3]int{1, 0, 10}},
	{"application_protection.connectors.*.guardrail.cascade", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.actor_secrets", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.ask_hosts", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.ask_timeout", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.git_push", [3]int{1, 0, 11}},
	{"guardrail.profiles.*.sandbox.idle_suspend_after", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.idle_suspend_tasks", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.runtimes", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.sandbox_class", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.unattended_asks", [3]int{1, 0, 10}},
	{"guardrail.profiles.*.sandbox.url_rules", [3]int{1, 0, 10}},
	{"guardrail.profile_assignments[].match.substrate", [3]int{1, 0, 10}},
}

// floorCheckInstalledConfigBytes reads the deployed config.yaml as written
// (tests replace it). fs.ErrNotExist: no deployed config.
var floorCheckInstalledConfigBytes = func(env *enterpriseunix.Env) ([]byte, error) {
	return env.InstalledConfigBytes()
}

// newerConfigDowngradeRefusal refuses installing version while the deployed
// config.yaml sets a key that release does not have. A same or later
// release, and a target that lacks none of the keys, pass without reading
// the config; so does a host with no deployed config.yaml.
func newerConfigDowngradeRefusal(env *enterpriseunix.Env, version string) error {
	target, known := releaseNumber(version)
	lacking := make([]string, 0, len(newerConfigKeys))
	for _, key := range newerConfigKeys {
		// An unknown or unreadable target counts as older, the safe direction.
		if !known || releaseBefore(target, key.since) {
			lacking = append(lacking, key.path)
		}
	}
	if len(lacking) == 0 {
		return nil
	}
	gateway := filepath.Join(env.Layout.BinDir, "defenseclaw-gateway") + " enterprise " + floorCheckOSName(env.GOOS)
	raw, err := floorCheckInstalledConfigBytes(env)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var doc any
	if err == nil {
		err = yaml.Unmarshal(raw, &doc)
	}
	if err != nil {
		return fmt.Errorf("config_newer_than_release: the managed config of this deployment could not be read (%v), so DefenseClaw cannot tell whether it sets a setting DefenseClaw %s does not have. "+
			"Fix or restore the managed config (%s ensure --config <file>), then install the older package again", err, version, gateway)
	}
	set := setConfigKeys(doc, lacking)
	if len(set) == 0 {
		return nil
	}
	list := strings.Join(set, ", ")
	return fmt.Errorf("config_newer_than_release: the managed config sets %s, which DefenseClaw %s does not have: its package would refuse that config only after its files replaced this release's, "+
		"and leave this device between the two releases. Remove %s from the managed config (or the signed bundle) and apply it (%s ensure --config <file>, or enterprise bundle apply), "+
		"then install the older package again", list, version, list, gateway)
}

// setConfigKeys lists the concrete keys of doc (a decoded config.yaml) that
// the patterns name, each present with any value, sorted, without a key
// that sits inside another listed one.
func setConfigKeys(doc any, patterns []string) []string {
	var found []string
	for _, pattern := range patterns {
		walkConfigKey(doc, configKeySegments(pattern), "", func(key string) { found = append(found, key) })
	}
	slices.Sort(found)
	found = slices.Compact(found)
	out := found[:0]
	for _, key := range found {
		if n := len(out); n > 0 && (strings.HasPrefix(key, out[n-1]+".") || strings.HasPrefix(key, out[n-1]+"[")) {
			continue
		}
		out = append(out, key)
	}
	return out
}

// configKeySegments splits a.b[].c into a, b, [], c.
func configKeySegments(pattern string) []string {
	var segments []string
	for _, part := range strings.Split(pattern, ".") {
		if name, ok := strings.CutSuffix(part, "[]"); ok {
			segments = append(segments, name, "[]")
			continue
		}
		segments = append(segments, part)
	}
	return segments
}

func walkConfigKey(node any, segments []string, path string, found func(string)) {
	if len(segments) == 0 {
		found(path)
		return
	}
	head, rest := segments[0], segments[1:]
	if head == "[]" {
		items, _ := node.([]any)
		for i, item := range items {
			walkConfigKey(item, rest, fmt.Sprintf("%s[%d]", path, i), found)
		}
		return
	}
	entries, _ := node.(map[string]any)
	join := func(name string) string {
		if path == "" {
			return name
		}
		return path + "." + name
	}
	if head == "*" {
		for name, child := range entries {
			walkConfigKey(child, rest, join(name), found)
		}
		return
	}
	if child, ok := entries[head]; ok {
		walkConfigKey(child, rest, join(head), found)
	}
}
