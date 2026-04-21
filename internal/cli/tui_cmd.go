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

package cli

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/tui"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive TUI dashboard",
	Long: `Launch the DefenseClaw unified TUI — a full-screen interactive dashboard
for monitoring, scanning, enforcing, and managing your OpenClaw deployment.

All CLI operations are accessible via the built-in command palette (Ctrl+K or :).`,
	RunE: runTUI,
}

func init() {
	tuiCmd.PersistentPreRunE = rootCmd.PersistentPreRunE
	rootCmd.AddCommand(tuiCmd)
}

func runTUI(_ *cobra.Command, _ []string) error {
	deps := tui.Deps{
		Store:   auditStore,
		Config:  cfg,
		Version: appVersion,
	}

	model := tui.New(deps)

	p := tea.NewProgram(model)

	model.SetProgram(p)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}
