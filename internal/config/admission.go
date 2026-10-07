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

package config

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Admission action shorthands (schema $defs.admissionAction).
const (
	AdmissionActionBlock      = "block"
	AdmissionActionQuarantine = "quarantine"
	AdmissionActionWarn       = "warn"
	AdmissionActionAllow      = "allow"
)

// Admission asset types: the keys of admission: besides defaults.
// AdmissionTypeTool names the asset_policy.tool lists; tool definitions have
// no admission: block, since no enforcement path admits a tool.
const (
	AdmissionTypeSkill  = "skill"
	AdmissionTypeMCP    = "mcp"
	AdmissionTypePlugin = "plugin"
	AdmissionTypeTool   = "tool"
)

// AdmissionConfig is the admission: section (config_version 9). It is the
// only source of install-time admission policy: policies/rego/data.json and
// the skill_actions/mcp_actions/plugin_actions keys are v8 migration input.
// Every asset type inherits Defaults field by field. When Skill.Actions is
// unset, the action map is derived from the scanner gate
// (scanners.skill_scanner.fail_on_severity / review_queue_min) at generation
// build; only skills have a scanner gate, so the other asset types take their
// actions from their own block or Defaults. The gateway compiles this into
// policy.CompiledAdmission per type.
type AdmissionConfig struct {
	Defaults AdmissionAssetType `yaml:"defaults,omitempty"`
	Skill    AdmissionAssetType `yaml:"skill,omitempty"`
	MCP      AdmissionAssetType `yaml:"mcp,omitempty"`
	Plugin   AdmissionAssetType `yaml:"plugin,omitempty"`
}

// AdmissionAssetType is one asset type's admission policy. Nil pointers and
// empty collections inherit from admission.defaults.
type AdmissionAssetType struct {
	ScanOnInstall       *bool              `yaml:"scan_on_install,omitempty"`
	AllowListBypassScan *bool              `yaml:"allow_list_bypass_scan,omitempty"`
	Actions             AdmissionActionMap `yaml:"actions,omitempty"`
	// ScannerOverrides is keyed by scan_result.scanner_name (for example
	// skill-scanner; analyzers such as VirusTotal run inside it) and wins over
	// Actions for that scanner's findings.
	ScannerOverrides    map[string]AdmissionActionMap `yaml:"scanner_overrides,omitempty"`
	FirstPartyAllowList []AdmissionFirstParty         `yaml:"first_party_allow_list,omitempty"`
}

// AdmissionActionMap maps a finding severity to an action. A nil entry is
// unset (inherits, or fails closed when nothing defines it).
type AdmissionActionMap struct {
	Critical *AdmissionAction `yaml:"critical,omitempty"`
	High     *AdmissionAction `yaml:"high,omitempty"`
	Medium   *AdmissionAction `yaml:"medium,omitempty"`
	Low      *AdmissionAction `yaml:"low,omitempty"`
	Info     *AdmissionAction `yaml:"info,omitempty"`
}

// IsZero reports whether no severity is set.
func (m AdmissionActionMap) IsZero() bool {
	return m.Critical == nil && m.High == nil && m.Medium == nil && m.Low == nil && m.Info == nil
}

// AdmissionFirstParty marks an asset as first party when its name matches and
// its path contains one of SourcePathContains as whole path components.
type AdmissionFirstParty struct {
	Name               string   `yaml:"name"`
	SourcePathContains []string `yaml:"source_path_contains"`
	Reason             string   `yaml:"reason,omitempty"`
}

// AdmissionAction is a shorthand (block, quarantine, warn, allow) or the
// exact install/file/runtime triple. Exactly one form is set.
type AdmissionAction struct {
	// Shorthand is one of the AdmissionAction* constants, or "" when the
	// triple form is used.
	Shorthand string
	// Triple is the explicit form; ignored when Shorthand is set.
	Triple SeverityAction
}

// Expand returns the install/file/runtime triple the action stands for:
//
//	block      -> {install: block, file: none,       runtime: disable}
//	quarantine -> {install: block, file: quarantine, runtime: disable}
//	warn       -> {install: none,  file: none,       runtime: enable}
//	allow      -> {install: none,  file: none,       runtime: enable}
//
// warn and allow differ only in the verdict (warning vs allowed).
func (a AdmissionAction) Expand() SeverityAction {
	switch a.Shorthand {
	case AdmissionActionBlock:
		return SeverityAction{Install: InstallBlock, File: FileActionNone, Runtime: RuntimeDisable}
	case AdmissionActionQuarantine:
		return SeverityAction{Install: InstallBlock, File: FileActionQuarantine, Runtime: RuntimeDisable}
	case AdmissionActionWarn, AdmissionActionAllow:
		return SeverityAction{Install: InstallNone, File: FileActionNone, Runtime: RuntimeEnable}
	default:
		return a.Triple
	}
}

func validAdmissionShorthand(value string) bool {
	switch value {
	case AdmissionActionBlock, AdmissionActionQuarantine, AdmissionActionWarn, AdmissionActionAllow:
		return true
	}
	return false
}

// UnmarshalYAML accepts a shorthand scalar or a triple mapping.
func (a *AdmissionAction) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if !validAdmissionShorthand(node.Value) {
			return fmt.Errorf("config: admission action must be block, quarantine, warn, allow or an install/file/runtime mapping")
		}
		*a = AdmissionAction{Shorthand: node.Value}
		return nil
	case yaml.MappingNode:
		var triple SeverityAction
		if err := node.Decode(&triple); err != nil {
			return err
		}
		*a = AdmissionAction{Triple: triple}
		return nil
	default:
		return fmt.Errorf("config: admission action must be a string or a mapping")
	}
}

// MarshalYAML writes the form the action was declared in.
func (a AdmissionAction) MarshalYAML() (any, error) {
	if a.Shorthand != "" {
		return a.Shorthand, nil
	}
	return a.Triple, nil
}

// UnmarshalJSON reads what MarshalJSON writes (the gateway clones a config
// through JSON): a shorthand string or an install/file/runtime object.
func (a *AdmissionAction) UnmarshalJSON(data []byte) error {
	var shorthand string
	if json.Unmarshal(data, &shorthand) == nil {
		if !validAdmissionShorthand(shorthand) {
			return fmt.Errorf("config: admission action must be block, quarantine, warn, allow or an install/file/runtime mapping")
		}
		*a = AdmissionAction{Shorthand: shorthand}
		return nil
	}
	var triple struct {
		Install string `json:"install"`
		File    string `json:"file"`
		Runtime string `json:"runtime"`
	}
	if err := json.Unmarshal(data, &triple); err != nil {
		return fmt.Errorf("config: admission action must be a string or a mapping: %w", err)
	}
	*a = AdmissionAction{Triple: SeverityAction{
		Install: InstallAction(triple.Install), File: FileAction(triple.File), Runtime: RuntimeAction(triple.Runtime),
	}}
	return nil
}

// MarshalJSON writes the form the action was declared in.
func (a AdmissionAction) MarshalJSON() ([]byte, error) {
	if a.Shorthand != "" {
		return json.Marshal(a.Shorthand)
	}
	return json.Marshal(map[string]string{
		"install": string(a.Triple.Install),
		"file":    string(a.Triple.File),
		"runtime": string(a.Triple.Runtime),
	})
}
