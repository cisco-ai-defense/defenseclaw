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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newSubstrateBundleRollbackCmd() *cobra.Command {
	var (
		out   substrateOutput
		com   substrateCommon
		stage string
	)
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Put a stage's previous policy bundle back in force",
		Long: `Puts the previous policy bundle of a stage back in force. The cluster checks its signature again first, so a
bundle signed with a key revoked since is refused. Running it again puts the newer bundle back. Needs an administrator
sign-in.`,
		Example: "defenseclaw substrate bundle rollback --stage canary",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			if strings.TrimSpace(stage) == "" {
				return withExitCode(errors.New("name the stage to roll back with --stage (see: defenseclaw substrate bundle status)"), 2)
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			res, err := s.Client.RollbackBundle(ctx, stage)
			if err != nil {
				return substrateBundleFail(err)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeSubstrateJSON(w, res)
			}
			fmt.Fprintf(w, "Stage %s rolled back.\n", stage)
			printSubstrateMap(w, res, "")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&stage, "stage", "", "the stage to roll back")
	return cmd
}
