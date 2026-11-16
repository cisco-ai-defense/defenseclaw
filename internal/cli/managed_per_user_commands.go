// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/spf13/cobra"
)

// perUserCommandsJSON lists every top-level command of the per-user (Python)
// CLI. cli/tests/test_managed_per_user_commands.py pins it to that CLI's
// command table, so a command added there fails until it is listed here.
//
//go:embed embed/per-user-commands.json
var perUserCommandsJSON []byte

var perUserCommands = sync.OnceValue(func() []string {
	var table struct {
		Commands []string `json:"commands"`
	}
	if err := json.Unmarshal(perUserCommandsJSON, &table); err != nil {
		panic(fmt.Sprintf("embed/per-user-commands.json: %v", err))
	}
	return table.Commands
})

// addManagedWindowsPerUserAnswers gives every per-user command that the
// installed managed Windows binary does not serve itself, and that has no
// answer of its own yet, the managed answer. Each was a bare "unknown
// command" with the generic usage and no administrator command, unlike
// doctor, upgrade and tui (GAP-0795, `alerts`). The list is the per-user
// CLI's own table, not the commands someone noticed, so a new per-user
// command is covered once the pytest that keeps the table current passes.
// Only a word that is no per-user command stays an unknown command.
func addManagedWindowsPerUserAnswers(root *cobra.Command, where string) {
	for _, name := range perUserCommands() {
		addManagedWindowsAnswer(root, name, func([]string) error {
			return managedWindowsPerUserCommandAnswer(where, name)
		})
	}
}

// managedWindowsPerUserCommandAnswer tells a user on a managed Windows
// computer that a per-user command is not installed there, and names the
// administrator's checks instead.
func managedWindowsPerUserCommandAnswer(where, command string) error {
	return managedDeviceAnswer(fmt.Sprintf("this computer's DefenseClaw is managed by your organization (%s), so `%s` is not available on this computer: "+
		"it is part of the per-user DefenseClaw, which a managed computer does not have, and there is nothing for you to set up. "+
		"Your administrator can check the managed deployment %s, and your account's agents with %s. "+
		"Nothing was changed.",
		where, command, managedWindowsAdminStatusHint(), managedWindowsAccountAgentsCommand()))
}
