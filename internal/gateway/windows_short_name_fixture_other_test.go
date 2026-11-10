// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// windowsManagedSettingsShortNames are 8.3 spellings of the managed agent
// settings files. Off Windows no volume can say which names exist, so the
// shape of the name names the file.
func windowsManagedSettingsShortNames(*testing.T) []string {
	return []string{
		`C:\PROGRA~1\ClaudeCode\managed-settings.json`,
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.JSO`,
		`C:\PROGRA~1\CLAUDE~1\managed-settings.json`,
		`C:\PROGRA~1\CLAUDE~1\managed-settings.d\90-defenseclaw.json`,
		`C:\PROGRA~3\OpenAI\Codex\requirements.toml`,
	}
}
