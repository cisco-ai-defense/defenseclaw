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

package tui

import (
	"fmt"
	"strings"
	"time"
)

type CommandRisk string

const (
	CommandRiskReadOnly    CommandRisk = "read-only"
	CommandRiskSetup       CommandRisk = "setup"
	CommandRiskMutation    CommandRisk = "mutation"
	CommandRiskRestart     CommandRisk = "restart"
	CommandRiskDestructive CommandRisk = "destructive"
	CommandRiskSecret      CommandRisk = "secret"
)

type CommandIntent struct {
	Binary        string
	Args          []string
	DisplayName   string
	Category      string
	Risk          CommandRisk
	RestartEffect string
	Origin        string
	Summary       string
	Interactive   bool
}

type CommandResultMeta struct {
	Origin               string
	Category             string
	Risk                 CommandRisk
	MaskedArgv           []string
	StartedAt            time.Time
	FinishedAt           time.Time
	ExitCode             int
	Duration             time.Duration
	Cancelled            bool
	ConfigReloaded       bool
	RestartCompleted     bool
	DoctorCacheRefreshed bool
	SuggestedNextAction  string
}

func NewCommandIntent(binary string, args []string, displayName, category, origin string) CommandIntent {
	cp := make([]string, len(args))
	copy(cp, args)
	intent := CommandIntent{
		Binary:      binary,
		Args:        cp,
		DisplayName: strings.TrimSpace(displayName),
		Category:    strings.TrimSpace(category),
		Origin:      strings.TrimSpace(origin),
	}
	if intent.DisplayName == "" {
		intent.DisplayName = strings.Join(cp, " ")
	}
	if intent.Category == "" {
		intent.Category = inferCommandCategory(cp)
	}
	intent.Risk = inferCommandRisk(intent.Category, cp)
	intent.RestartEffect = inferRestartEffect(cp)
	intent.Summary = inferIntentSummary(intent)
	return intent
}

func CommandIntentFromEntry(entry *CmdEntry, extra, origin string) (CommandIntent, error) {
	if entry == nil {
		return CommandIntent{}, fmt.Errorf("missing command entry")
	}
	if entry.NeedsArg && strings.TrimSpace(extra) == "" {
		return CommandIntent{}, fmt.Errorf("%s needs %s", entry.TUIName, entry.ArgHint)
	}
	args, err := buildCLIArgs(entry, extra)
	if err != nil {
		return CommandIntent{}, err
	}
	displayName := entry.TUIName
	if strings.TrimSpace(extra) != "" {
		displayName += " " + strings.TrimSpace(extra)
	}
	return NewCommandIntent(entry.CLIBinary, args, displayName, entry.Category, origin), nil
}

func (i CommandIntent) Normalized() CommandIntent {
	normalized := NewCommandIntent(i.Binary, i.Args, i.DisplayName, i.Category, i.Origin)
	normalized.Interactive = i.Interactive
	return normalized
}

func (i CommandIntent) MaskedArgs() []string {
	return MaskArgv(i.Args)
}

func (i CommandIntent) MaskedCommandLine() string {
	parts := append([]string{i.Binary}, i.MaskedArgs()...)
	return strings.Join(parts, " ")
}

func (i CommandIntent) MaskedDisplayName() string {
	if strings.TrimSpace(i.DisplayName) == "" {
		return strings.Join(i.MaskedArgs(), " ")
	}
	if SecretArgIndexes(i.Args) == nil {
		return i.DisplayName
	}
	// Avoid trying to parse the display name; use the exact masked argv
	// when secrets are present so activity and previews share one source.
	return strings.Join(i.MaskedArgs(), " ")
}

func (i CommandIntent) HasSecretArgs() bool {
	return len(SecretArgIndexes(i.Args)) > 0
}

func (i CommandIntent) NeedsConfirmation() bool {
	if i.HasSecretArgs() {
		return true
	}
	return i.Risk != CommandRiskReadOnly
}

func (i CommandIntent) Meta(start time.Time) CommandResultMeta {
	return CommandResultMeta{
		Origin:     i.Origin,
		Category:   i.Category,
		Risk:       i.Risk,
		MaskedArgv: append([]string{i.Binary}, i.MaskedArgs()...),
		StartedAt:  start,
	}
}

func inferCommandCategory(args []string) string {
	if len(args) == 0 {
		return "other"
	}
	switch args[0] {
	case "setup", "keys", "settings", "init", "quickstart":
		return "setup"
	case "doctor", "status", "config", "version", "guardrail":
		return "info"
	case "skill", "mcp", "plugin", "tool":
		return "enforce"
	case "policy":
		return "policy"
	case "sandbox":
		return "sandbox"
	default:
		return "other"
	}
}

func inferCommandRisk(category string, args []string) CommandRisk {
	if len(SecretArgIndexes(args)) > 0 {
		return CommandRiskSecret
	}
	if len(args) == 0 {
		return CommandRiskReadOnly
	}
	if hasAnyArg(args, "uninstall", "reset", "remove", "delete", "quarantine", "wipe") {
		return CommandRiskDestructive
	}
	if hasAnyArg(args, "restart", "rotate-token") {
		return CommandRiskRestart
	}
	if hasAnyArg(args, "block", "disable", "teardown", "stop", "down", "approve", "reject", "allow", "unblock", "unset") {
		return CommandRiskMutation
	}
	if args[0] == "doctor" && hasAnyArg(args, "--fix") {
		return CommandRiskSetup
	}
	if args[0] == "keys" {
		if len(args) > 1 && (args[1] == "list" || args[1] == "check") {
			return CommandRiskReadOnly
		}
		return CommandRiskSetup
	}
	if args[0] == "setup" {
		if setupArgsReadOnly(args) {
			return CommandRiskReadOnly
		}
		return CommandRiskSetup
	}
	if args[0] == "config" || args[0] == "status" || args[0] == "version" || args[0] == "doctor" {
		return CommandRiskReadOnly
	}
	switch category {
	case "info", "scan":
		return CommandRiskReadOnly
	case "daemon":
		return CommandRiskMutation
	case "setup", "install":
		return CommandRiskSetup
	case "enforce", "policy", "sandbox", "other":
		if hasAnyArg(args, "info", "list", "scan", "show", "status", "validate", "test", "evaluate", "domains", "export", "dry-run") {
			return CommandRiskReadOnly
		}
		return CommandRiskMutation
	default:
		return CommandRiskReadOnly
	}
}

func setupArgsReadOnly(args []string) bool {
	if len(args) == 1 {
		return true
	}
	last := args[len(args)-1]
	if hasAnyArg(args, "show", "list", "status", "url", "logs", "--show") {
		return true
	}
	return last == "--help" || last == "-h"
}

func inferRestartEffect(args []string) string {
	if len(args) == 0 {
		return "none"
	}
	if hasAnyArg(args, "restart") {
		return "restarts the gateway or sandbox immediately"
	}
	if args[0] == "setup" || args[0] == "guardrail" || args[0] == "settings" || args[0] == "init" {
		return "may require or trigger a gateway restart"
	}
	return "none"
}

func inferIntentSummary(i CommandIntent) string {
	switch i.Risk {
	case CommandRiskReadOnly:
		return "Reads current state and does not intentionally change local configuration."
	case CommandRiskSecret:
		return "Passes a secret-bearing argument to the CLI; preview and activity logs mask it."
	case CommandRiskRestart:
		return "Changes process lifecycle and may briefly interrupt agent connectivity."
	case CommandRiskDestructive:
		return "Can remove, reset, quarantine, or uninstall local state."
	case CommandRiskSetup:
		return "Updates DefenseClaw setup/configuration through the CLI source of truth."
	default:
		return "Mutates DefenseClaw state through the CLI source of truth."
	}
}

func hasAnyArg(args []string, needles ...string) bool {
	for _, arg := range args {
		for _, needle := range needles {
			if arg == needle {
				return true
			}
		}
	}
	return false
}

func suggestedNextAction(command string, exitCode int) string {
	cmd := strings.ToLower(strings.TrimSpace(command))
	if exitCode != 0 {
		if strings.Contains(cmd, "keys") {
			return "open Credentials or run keys check"
		}
		if strings.Contains(cmd, "doctor") {
			return "open readiness or rerun doctor"
		}
		return "review output and rerun when fixed"
	}
	switch {
	case strings.Contains(cmd, "keys"):
		return "rerun readiness"
	case strings.Contains(cmd, "doctor"):
		return "review readiness"
	case strings.Contains(cmd, "setup"):
		return "rerun readiness"
	case strings.Contains(cmd, "restart"):
		return "refresh gateway health"
	default:
		return ""
	}
}
