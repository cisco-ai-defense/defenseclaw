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
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/idfabric"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func init() {
	rootCmd.AddCommand(newIDFabricCmd())
}

// newIDFabricCmd builds the hidden `idfabric` command group.
func newIDFabricCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "idfabric",
		Short:  "Identity Fabric telemetry (invoked by the agent runtime)",
		Hidden: true,
	}
	cmd.AddCommand(newIDFabricCaptureCmd())
	return cmd
}

// newIDFabricCaptureCmd builds the entrypoint the Unix hook scripts use to
// capture Identity Fabric telemetry for one event.
//
// The native `hook` command captures inline, but the .sh hooks do not run it:
// they POST the payload to the gateway with curl and exit. Capture cannot move
// to the gateway, because the gateway runs as a service account whose token,
// home directory, and workspace are its own - it would attribute every event
// on the machine to that one service identity. This command exists so the
// shell hooks can perform the same capture in the real user's process.
//
// It reports success unconditionally. The shell invokes it detached from a
// guardrail hook, and a telemetry failure must not surface as a hook failure.
func newIDFabricCaptureCmd() *cobra.Command {
	var (
		connector         string
		event             string
		enterpriseManaged bool
	)

	cmd := &cobra.Command{
		Use:    "capture",
		Short:  "Capture Identity Fabric telemetry for one hook event from stdin",
		Hidden: true,
		Args:   cobra.NoArgs,
		// Skip the daemon's config load and audit-store open, matching the
		// hook command: this is a short-lived per-event process that must not
		// hold the audit DB.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(*cobra.Command, []string) error {
			receivedAt := time.Now().UTC()
			if !idfabric.Enabled("", enterpriseManaged) {
				return nil
			}
			defer func() {
				// A telemetry defect must not produce a nonzero exit next to a
				// guardrail hook, however it is invoked.
				if recovered := recover(); recovered != nil {
					reportIdentityFabricFailure("capture panicked")
				}
			}()

			payload, err := io.ReadAll(io.LimitReader(os.Stdin, idFabricStdinCap))
			if err != nil {
				reportIdentityFabricFailure("stdin capture failed")
				return nil
			}

			if _, err := idfabric.CaptureHookEvent(idfabric.HookContext{
				Connector:         connector,
				Event:             event,
				Payload:           payload,
				Home:              identityFabricCaptureHome(),
				ManagedEnterprise: enterpriseManaged,
				ProducerVersion:   version.Current().BinaryVersion,
				ReceivedAt:        receivedAt,
			}); err != nil {
				reportIdentityFabricFailure("record write failed")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&connector, "connector", "", "connector name (e.g. claudecode, codex, cursor)")
	cmd.Flags().StringVar(&event, "event", "", "agent hook event name (inferred from the payload when omitted)")
	cmd.Flags().BoolVar(&enterpriseManaged, "enterprise-managed", false, "the invoking hook is administrator-managed")
	_ = cmd.MarkFlagRequired("connector")

	return cmd
}

// identityFabricCaptureHome resolves the DefenseClaw home the same way the
// native hook does, so the device identity read from it is identical on both
// paths. The home is only read from; the records go to the per-user spool.
func identityFabricCaptureHome() string {
	if home, trusted := trustedNativeHookHome(); trusted {
		return home
	}
	return config.DefaultDataPath()
}
