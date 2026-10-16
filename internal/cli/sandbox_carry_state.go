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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/openshell/statecarry"
)

func newSandboxCarryStateCmd() *cobra.Command {
	var o statecarry.Options
	cmd := &cobra.Command{
		Use:   "carry-state",
		Short: "Keep the sandbox setup across an install swap (run by the installer)",
		Long: `Copy the sandbox setup of the install the installer leaves (its openshell:
settings and its sandboxes, snapshots and shadows folders) into the install it
makes live. Sandboxes keep running while 'defenseclaw rollback' puts back the
data of the install the upgrade replaced, which had sandboxes off and none of
their hook bindings: every hook of a running sandbox then failed closed until
the user set sandboxes up again (rel-1-0-2:GAP-0483). The install left keeps
its own copy. Nothing is copied when the install left has sandboxes off; with
--only-if-unset, also when the live install has a sandbox setup of its own.`,
		Hidden: true,
		Args:   cobra.NoArgs,
		// The installer runs it between the swap and the gateway start, on
		// the two data directories it names: no config.yaml is loaded, no
		// sandbox daemon is asked and no audit store is opened.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			res, err := statecarry.Carry(ctx, o)
			if err != nil {
				return fmt.Errorf("sandbox carry-state: %w; the live install is unchanged", err)
			}
			if line := res.Summary(); line != "" {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&o.FromDataDir, "from-data", "", "data directory of the install the installer leaves")
	flags.StringVar(&o.FromConfig, "from-config", "", "config.yaml of the install the installer leaves")
	flags.StringVar(&o.DataDir, "data-dir", "", "data directory of the live install")
	flags.StringVar(&o.Config, "config", "", "config.yaml of the live install")
	flags.BoolVar(&o.OnlyIfUnset, "only-if-unset", false, "copy nothing when the live install has a sandbox setup of its own")
	for _, name := range []string{"from-data", "from-config", "data-dir", "config"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func init() {
	sandboxCmd.AddCommand(newSandboxCarryStateCmd())
}
