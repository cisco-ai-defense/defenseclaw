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
	"errors"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/spf13/cobra"
)

type sgwConsoleOpener func(string) (gateway.SGWConsoleStatus, error)

func newSGWConsoleOpenCommand(open sgwConsoleOpener) *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:    "sgw-console-open",
		Hidden: true,
		Args:   cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return nil
		},
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dataDir == "" || strings.ContainsRune(dataDir, '\x00') || !filepath.IsAbs(dataDir) ||
				filepath.Clean(dataDir) != dataDir {
				return errors.New("DefenseClaw data directory must be a clean absolute path")
			}
			status, err := open(dataDir)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "absolute DefenseClaw data directory")
	_ = cmd.MarkFlagRequired("data-dir")
	return cmd
}

func init() {
	rootCmd.AddCommand(newSGWConsoleOpenCommand(gateway.OpenInstalledSGWConsole))
}
