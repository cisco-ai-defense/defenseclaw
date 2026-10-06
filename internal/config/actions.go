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

import "fmt"

func DefaultSkillActions() SkillActionsConfig {
	return SkillActionsConfig{
		Critical: SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		High:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Medium:   SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Low:      SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Info:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}
}

func (a *SkillActionsConfig) Validate() error {
	return validateActions("skill_actions", []struct {
		label  string
		action SeverityAction
	}{
		{"critical", a.Critical},
		{"high", a.High},
		{"medium", a.Medium},
		{"low", a.Low},
		{"info", a.Info},
	})
}

func DefaultMCPActions() MCPActionsConfig {
	return MCPActionsConfig{
		Critical: SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallBlock},
		High:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallBlock},
		Medium:   SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Low:      SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Info:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}
}

func (a *MCPActionsConfig) Validate() error {
	return validateActions("mcp_actions", []struct {
		label  string
		action SeverityAction
	}{
		{"critical", a.Critical},
		{"high", a.High},
		{"medium", a.Medium},
		{"low", a.Low},
		{"info", a.Info},
	})
}

func DefaultPluginActions() PluginActionsConfig {
	return PluginActionsConfig{
		Critical: SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		High:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Medium:   SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Low:      SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		Info:     SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}
}

func (a *PluginActionsConfig) Validate() error {
	return validateActions("plugin_actions", []struct {
		label  string
		action SeverityAction
	}{
		{"critical", a.Critical},
		{"high", a.High},
		{"medium", a.Medium},
		{"low", a.Low},
		{"info", a.Info},
	})
}

func validateActions(prefix string, entries []struct {
	label  string
	action SeverityAction
}) error {
	for _, e := range entries {
		switch e.action.Runtime {
		case RuntimeDisable, RuntimeEnable:
		default:
			return fmt.Errorf("config: %s.%s.runtime: invalid value %q (must be %q or %q)",
				prefix, e.label, e.action.Runtime, RuntimeDisable, RuntimeEnable)
		}
		switch e.action.File {
		case FileActionNone, FileActionQuarantine:
		default:
			return fmt.Errorf("config: %s.%s.file: invalid value %q (must be %q or %q)",
				prefix, e.label, e.action.File, FileActionNone, FileActionQuarantine)
		}
		switch e.action.Install {
		case InstallBlock, InstallAllow, InstallNone:
		default:
			return fmt.Errorf("config: %s.%s.install: invalid value %q (must be %q, %q, or %q)",
				prefix, e.label, e.action.Install, InstallBlock, InstallAllow, InstallNone)
		}
	}
	return nil
}
