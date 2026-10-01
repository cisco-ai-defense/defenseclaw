// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// ConnectorHermes is the Hermes Agent connector. Hermes has no machine
// policy source: DefenseClaw registers its hooks in each enrolled user's
// own config (the per-user route).
const ConnectorHermes = "hermes"

// Hermes reads its shell hooks from the top-level hooks mapping of
// <HERMES_HOME>/config.yaml (~/.hermes by default, %LOCALAPPDATA%\hermes on
// Windows; a named profile sets HERMES_HOME for the process): each event
// maps to a list of {command, matcher, timeout} entries, and Hermes runs
// every entry of an event in order. A pre_tool_call entry may block the call
// or rewrite its input, so an entry after DefenseClaw's can change what
// DefenseClaw checked. Hermes also merges a managed-scope config.yaml
// (HERMES_MANAGED_DIR, else /etc/hermes) over the user's. Hermes reads no
// project hook file and has no managed-only lock: the shell-hook allowlist
// is the user's consent record and `hermes --accept-hooks` skips it.
const formatHermesYAML = "hermes-yaml"

// hermesUserConfig adds the Hermes config.yaml files a Hermes process
// started with req's environment reads: <HERMES_HOME>/config.yaml, and the
// managed-scope config.yaml in the directory HERMES_MANAGED_DIR names.
func hermesUserConfig(req GuardRequest, home string, envPath func(string) string, user func(format string, parts ...string)) {
	for _, dir := range hermesHomeDirs(req, home, envPath) {
		user(formatHermesYAML, dir, "config.yaml")
	}
	if dir := hermesManagedDir(req, envPath); dir != "" {
		user(formatHermesYAML, dir, "config.yaml")
	}
}

// hermesDefaultManagedDir is the managed scope Hermes reads when
// HERMES_MANAGED_DIR is not set. Only an administrator can write it.
const hermesDefaultManagedDir = "/etc/hermes"

// hermesManagedDir returns the managed-scope directory HERMES_MANAGED_DIR
// names, or "" when the variable is unset or names the administrator's
// default. Hermes merges <managed dir>/config.yaml over the user's
// config.yaml, and an event's list there replaces the user's list, so hooks
// in that file run like the user's own. Any user can set the variable, so
// the file is user scope: the guard reads it, the hook records the location
// for the guardian's cleanup (ObservedEnvRedirect), and the cleanup removes
// unapproved entries from it. Hermes itself honors the variable only when it
// names an existing directory; a missing file has no entries.
func hermesManagedDir(req GuardRequest, envPath func(string) string) string {
	if strings.TrimSpace(req.getenv("HERMES_MANAGED_DIR")) == "" {
		return ""
	}
	dir := envPath("HERMES_MANAGED_DIR")
	if dir == "" || filepath.Clean(dir) == hermesDefaultManagedDir {
		return ""
	}
	return dir
}

// hermesReservedHookSections are the keys of the Hermes hooks mapping that
// hold settings rather than events. Hermes registers no shell hook from them
// (output_spill sets tool-output size and spill directory; outbound lists
// notify-only webhooks, which cannot block or change a tool call), so the
// guard neither reports them nor changes them.
var hermesReservedHookSections = map[string]bool{
	"output_spill": true,
	"outbound":     true,
}

// hermesHomeDirs resolves HERMES_HOME as Hermes does: an explicit value
// wins (a relative one is relative to the agent's working directory; a
// leading ~ is also read as the home, since DefenseClaw cannot tell whether
// the Hermes build expands it), otherwise the platform default.
func hermesHomeDirs(req GuardRequest, home string, envPath func(string) string) []string {
	if configured := req.getenv("HERMES_HOME"); configured != "" {
		var dirs []string
		if dir := envPath("HERMES_HOME"); dir != "" {
			dirs = append(dirs, dir)
		}
		if rest, ok := strings.CutPrefix(configured, "~"); ok && home != "" && (rest == "" || strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, `\`)) {
			dirs = append(dirs, filepath.Join(home, rest))
		}
		return dirs
	}
	if home == "" {
		return nil
	}
	if req.goos() == "windows" {
		if localAppData := req.getenv("LOCALAPPDATA"); localAppData != "" {
			return []string{filepath.Join(localAppData, "hermes"), filepath.Join(home, "AppData", "Local", "hermes")}
		}
		return []string{filepath.Join(home, "AppData", "Local", "hermes")}
	}
	return []string{filepath.Join(home, ".hermes")}
}

// hermesHookEvents decodes the hooks mapping of a Hermes config.yaml, with
// every value in JSON form (string keys). A file without hooks has none; a
// document or hooks value Hermes could not read as a mapping cannot be
// verified.
func hermesHookEvents(data []byte) (map[string]any, error) {
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse Hermes config: %w", err)
	}
	document = hermesJSONValue(document)
	if document == nil {
		return nil, nil
	}
	root, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("the Hermes config is not a YAML mapping")
	}
	value, present := root["hooks"]
	if !present || value == nil {
		return nil, nil
	}
	hooks, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("the Hermes hooks setting is not a YAML mapping")
	}
	return hooks, nil
}

// hermesEventHandlers lists the entries of one Hermes event. Hermes expects
// a list; a single entry, or a value of another shape, is still checked, so
// nothing Hermes might run is skipped.
func hermesEventHandlers(value any) []any {
	switch v := value.(type) {
	case nil:
		return nil
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			if item != nil {
				out = append(out, item)
			}
		}
		return out
	default:
		return []any{v}
	}
}

// hermesJSONValue converts a decoded YAML value into the JSON shapes the
// scanner and the canonical digest use: string-keyed maps, lists and
// scalars.
func hermesJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = hermesJSONValue(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[fmt.Sprint(key)] = hermesJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = hermesJSONValue(item)
		}
		return out
	default:
		return v
	}
}

func sortedEventNames(hooks map[string]any) []string {
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	return events
}

// scanHermesYAML returns a finding for every entry of a Hermes config.yaml
// that is not exactly DefenseClaw's own registration.
func (s *guardScan) scanHermesYAML(source hookSource, data []byte) []Finding {
	hooks, err := hermesHookEvents(data)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	var findings []Finding
	for _, event := range sortedEventNames(hooks) {
		if hermesReservedHookSections[event] {
			continue
		}
		for _, handler := range hermesEventHandlers(hooks[event]) {
			if s.req.ownedHandler(handler) {
				continue
			}
			findings = append(findings, s.handlerFinding(source, event, handler))
		}
	}
	return findings
}

// cleanHermesYAMLSource removes the user's unapproved Hermes hook entries
// from one config.yaml. Only the top-level hooks mapping is rewritten, the
// way Setup writes it; every other byte of the file is kept, and the
// original is backed up first. An unverifiable file is reported and left
// alone (the hook keeps denying until the user fixes it).
func cleanHermesYAMLSource(scan *guardScan, source hookSource, backupDir string, result *CleanupResult) error {
	req := scan.req
	data, exists, err := scan.readSource(source)
	if err != nil {
		result.Reported = append(result.Reported, unreadableFinding(req, source, err))
		return nil
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	remove := map[string]bool{}
	var removed []Finding
	for _, finding := range scan.scanHermesYAML(source, data) {
		if finding.Allowed {
			continue
		}
		if strings.HasPrefix(finding.Reason, "cannot verify") || scan.exceeded != nil || source.reportOnly || source.inline != nil {
			result.Reported = append(result.Reported, finding)
			continue
		}
		remove[finding.key] = true
		removed = append(removed, finding)
	}
	if len(remove) == 0 {
		return nil
	}
	hooks, err := hermesHookEvents(data)
	if err != nil {
		return err
	}
	kept := make(map[string]any, len(hooks))
	for event, value := range hooks {
		if hermesReservedHookSections[event] {
			kept[event] = value
			continue
		}
		handlers := hermesEventHandlers(value)
		if len(handlers) == 0 {
			kept[event] = value
			continue
		}
		keptHandlers := make([]any, 0, len(handlers))
		for _, handler := range handlers {
			if !remove[sha256Hex(canonicalJSON(handler))] {
				keptHandlers = append(keptHandlers, handler)
			}
		}
		if len(keptHandlers) == 0 {
			continue
		}
		if _, list := value.([]any); !list && len(keptHandlers) == 1 {
			kept[event] = keptHandlers[0]
			continue
		}
		kept[event] = keptHandlers
	}
	rendered, err := connector.ReplaceTopLevelYAMLField(source.path, data, "hooks", kept)
	if err != nil {
		return err
	}
	if err := backupUserFile(source.path, data, backupDir); err != nil {
		return err
	}
	result.BackupDir = backupDir
	info, err := os.Lstat(source.path)
	if err != nil {
		return err
	}
	if err := rewriteUserFile(source.path, rendered, info.Mode().Perm()); err != nil {
		return err
	}
	result.Removed = append(result.Removed, removed...)
	result.FilesTouch = appendUnique(result.FilesTouch, source.path)
	return nil
}
