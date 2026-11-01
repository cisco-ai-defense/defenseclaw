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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
			if codexNotifyChainEnded(opts, args[0]) {
				// A notifier this command started called it back with the
				// same turn: it is already forwarded, and chaining again
				// would loop.
				return nil
			}
			hookexec.RunCodexNotify(cmd.Context(), opts, []byte(args[0]))
			if !opts.ManagedEnterprise && !opts.SecureClient {
				runOriginalCodexNotify(opts.Home, args[0])
			}
			return nil
		},
	}
}

// codexNotifyChainedEnv marks the notifier runOriginalCodexNotify starts. Its
// value is the hex SHA-256 of that turn's payload, so only a call that carries
// the same payload ends the chain: a wrapper that runs DefenseClaw's notifier
// again, in a spelling the backup check does not know, stops after one pass
// instead of looping (a notify loop of Codex computer-use). A constant or
// inherited value, such as one a nested Codex got for another turn, matches no
// payload and suppresses nothing.
const codexNotifyChainedEnv = "DEFENSECLAW_CODEX_NOTIFY_CHAINED"

func codexNotifyPayloadDigest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// codexNotifyChainEnded reports whether this per-user notify call is the
// second pass of a turn the chained notifier handed back. Managed and Secure
// Client installs never chain and never read the marker.
func codexNotifyChainEnded(opts hookexec.Options, payload string) bool {
	if opts.ManagedEnterprise || opts.SecureClient {
		return false
	}
	value := envvars.Getenv(codexNotifyChainedEnv)
	return value != "" && value == codexNotifyPayloadDigest(payload)
}

// The native Windows notifier keeps the user program that setup displaced.
// Its argv is the pre-DefenseClaw snapshot, never a shell command.
func runOriginalCodexNotify(dataDir, payload string) {
	command := originalCodexNotifyCommand(dataDir, payload)
	if command == nil {
		return
	}
	_ = command.Run() // The user's notifier and gateway telemetry are independent.
}

func originalCodexNotifyCommand(dataDir, payload string) *exec.Cmd {
	argv := connector.CodexOriginalNotify(dataDir)
	if len(argv) == 0 {
		return nil
	}
	command := exec.Command(argv[0], append(argv[1:], payload)...)
	command.Env = append(os.Environ(), codexNotifyChainedEnv+"="+codexNotifyPayloadDigest(payload))
	return command
}
