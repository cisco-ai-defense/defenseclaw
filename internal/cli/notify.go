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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func init() {
	rootCmd.AddCommand(newNotifyCmd())
}

// newNotifyCmd builds the hidden native counterpart to Codex's historical
// notify-bridge.sh. Codex appends exactly one JSON payload argument to the
// configured argv array; forwarding is telemetry-only and always best-effort.
func newNotifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "notify EVENT_JSON",
		Short:             "Forward a Codex notification to the local gateway",
		Hidden:            true,
		Args:              cobra.ExactArgs(1),
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := buildHookOptions("codex", "notify", "", "open")
			hookexec.RunCodexNotify(cmd.Context(), opts, []byte(args[0]))
			if !opts.ManagedEnterprise && !opts.SecureClient {
				runOriginalCodexNotify(opts.Home, args[0])
			}
			return nil
		},
	}
}

// The native Windows notifier keeps the user program that setup displaced.
// Its argv is the pre-DefenseClaw snapshot, never a shell command.
func runOriginalCodexNotify(dataDir, payload string) {
	data, err := os.ReadFile(filepath.Join(dataDir, "codex_config_backup.json"))
	if err != nil || len(data) > 1<<20 {
		return
	}
	var backup struct {
		OriginalNotify []string `json:"original_notify"`
	}
	if json.Unmarshal(data, &backup) != nil || len(backup.OriginalNotify) == 0 ||
		strings.TrimSpace(backup.OriginalNotify[0]) == "" {
		return
	}
	argv := backup.OriginalNotify
	if filepath.Base(argv[0]) == "defenseclaw-hook.exe" && len(argv) > 1 && argv[1] == "notify" {
		return
	}
	command := exec.Command(argv[0], append(argv[1:], payload)...)
	_ = command.Run() // The user's notifier and gateway telemetry are independent.
}
