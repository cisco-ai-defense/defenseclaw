// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"

	"github.com/spf13/viper"
)

// secureClientV8ActionKeys are the config_version 8 action keys a Secure
// Client source still carries, with the defaults main filled in.
var secureClientV8ActionKeys = []struct {
	key      string
	defaults [5]SeverityAction // critical, high, medium, low, info
}{
	{"skill_actions", [5]SeverityAction{
		{File: FileActionQuarantine, Runtime: RuntimeDisable, Install: InstallBlock},
		{File: FileActionQuarantine, Runtime: RuntimeDisable, Install: InstallBlock},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}},
	{"mcp_actions", [5]SeverityAction{
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallBlock},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallBlock},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}},
	{"plugin_actions", [5]SeverityAction{
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
		{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone},
	}},
}

var secureClientV8ActionSeverities = [5]string{"critical", "high", "medium", "low", "info"}

// readSecureClientV8Actions reads skill_actions, mcp_actions and
// plugin_actions from the source viper holds into cfg.SecureClientV8Actions,
// and refuses an invalid value with the error main gave. Nothing enforces
// these keys (the Secure Client admission reads data.json), but main
// validated them at load and a reload that changed one needed a restart, so
// a Secure Client gateway still does (issue #1092).
func readSecureClientV8Actions(cfg *Config) error {
	actions := make(map[string][5]SeverityAction, len(secureClientV8ActionKeys))
	for _, entry := range secureClientV8ActionKeys {
		var values [5]SeverityAction
		for i, severity := range secureClientV8ActionSeverities {
			key := entry.key + "." + severity
			viper.SetDefault(key+".file", string(entry.defaults[i].File))
			viper.SetDefault(key+".runtime", string(entry.defaults[i].Runtime))
			viper.SetDefault(key+".install", string(entry.defaults[i].Install))
			values[i] = SeverityAction{
				File:    FileAction(viper.GetString(key + ".file")),
				Runtime: RuntimeAction(viper.GetString(key + ".runtime")),
				Install: InstallAction(viper.GetString(key + ".install")),
			}
			if err := validateSecureClientV8Action(entry.key, severity, values[i]); err != nil {
				if ReportConfigLoadError != nil {
					ReportConfigLoadError(context.Background(), entry.key+"_invalid")
				}
				return err
			}
		}
		actions[entry.key] = values
	}
	cfg.SecureClientV8Actions = actions
	return nil
}

func validateSecureClientV8Action(prefix, label string, action SeverityAction) error {
	switch action.Runtime {
	case RuntimeDisable, RuntimeEnable:
	default:
		return fmt.Errorf("config: %s.%s.runtime: invalid value %q (must be %q or %q)",
			prefix, label, action.Runtime, RuntimeDisable, RuntimeEnable)
	}
	switch action.File {
	case FileActionNone, FileActionQuarantine:
	default:
		return fmt.Errorf("config: %s.%s.file: invalid value %q (must be %q or %q)",
			prefix, label, action.File, FileActionNone, FileActionQuarantine)
	}
	switch action.Install {
	case InstallBlock, InstallAllow, InstallNone:
	default:
		return fmt.Errorf("config: %s.%s.install: invalid value %q (must be %q, %q, or %q)",
			prefix, label, action.Install, InstallBlock, InstallAllow, InstallNone)
	}
	return nil
}
