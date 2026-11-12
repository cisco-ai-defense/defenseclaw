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

// The administrator commands of the substrate launcher: bundle (here),
// doctor (substrate_admin_doctor.go), setup (substrate_admin_setup.go) and
// template (substrate_admin_template.go). They need no managed install:
// bundle talks to the cluster with the administrator's own sign-in, the
// others read and write files named on the command line.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

func newSubstrateBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Send a signed policy bundle to the cluster, or see what is in force (administrators)",
		Long: `A policy bundle is a signed file your organization's policy tooling makes. Administrators send it to the cluster
with "bundle apply" and read which bundles are in force with "bundle status". The cluster checks the signature; this
command only sends the file as it is.`,
	}
	cmd.AddCommand(newSubstrateBundleApplyCmd(), newSubstrateBundleStatusCmd(), newSubstrateBundleRollbackCmd())
	return cmd
}

func newSubstrateBundleApplyCmd() *cobra.Command {
	var (
		out       substrateOutput
		com       substrateCommon
		atespaces []string
		stage     string
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   "apply <file>",
		Short: "Send a signed policy bundle to the cluster",
		Long: `Sends the bundle file to the cluster as it is (up to 48 KiB). With --atespaces the bundle applies to those groups
of agents only; without it, to the whole cluster. With --dry-run it only checks that the file can be read and is not
empty, and sends nothing. Needs an administrator sign-in.`,
		Example: "defenseclaw substrate bundle apply policy.bundle\ndefenseclaw substrate bundle apply policy.bundle --atespaces team-a,team-b --dry-run",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			path := args[0]
			f, size, err := openSubstrateBundle(path)
			if err != nil {
				return withExitCode(err, 2)
			}
			defer f.Close()
			name := filepath.Base(path)
			w := cmd.OutOrStdout()
			if dryRun {
				if asJSON {
					return writeSubstrateJSON(w, map[string]any{"dry_run": true, "bundle": name, "bytes": size, "atespaces": atespaces})
				}
				fmt.Fprintf(w, "Dry run: %s (%d bytes) can be read and would be sent%s. Nothing was sent.\n", name, size, atespaceWords(atespaces))
				return nil
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			res, err := s.Client.ApplyBundle(ctx, name, f, stage, atespaces)
			if err != nil {
				return substrateBundleFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{"bundle": name, "bytes": size, "atespaces": atespaces, "answer": res})
			}
			fmt.Fprintf(w, "Sent %s (%d bytes)%s.\n", name, size, atespaceWords(atespaces))
			if len(res) > 0 {
				printSubstrateMap(w, res, "")
			}
			fmt.Fprintln(w, "See what is in force with: defenseclaw substrate bundle status")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringSliceVar(&atespaces, "atespaces", nil, "apply to these groups of agents only (comma separated)")
	cmd.Flags().StringVar(&stage, "stage", "", "rollout stage name (default: all without --atespaces, one stage per atespace set with it)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "check the file and send nothing")
	return cmd
}

func newSubstrateBundleStatusCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show which policy bundles are in force",
		Long:  `Shows the policy bundles the cluster has accepted and which groups of agents each applies to. Needs an administrator sign-in.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			res, err := s.Client.BundleStatus(ctx)
			if err != nil {
				return substrateBundleFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), res)
			}
			if len(res) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No policy bundle is in force.")
				return nil
			}
			printSubstrateMap(cmd.OutOrStdout(), res, "")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

// openSubstrateBundle opens the bundle and checks it is a readable, non-empty
// file under the cap. It does not look inside it.
func openSubstrateBundle(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("the bundle cannot be read: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("the bundle cannot be read: %w", err)
	}
	switch {
	case st.IsDir():
		f.Close()
		return nil, 0, errors.New("the bundle is a folder; give the bundle file")
	case st.Size() == 0:
		f.Close()
		return nil, 0, errors.New("the bundle file is empty")
	case st.Size() > api.MaxBundleBytes:
		f.Close()
		return nil, 0, api.ErrBundleTooLarge
	}
	return f, st.Size(), nil
}

func atespaceWords(atespaces []string) string {
	if len(atespaces) == 0 {
		return ""
	}
	return " for " + strings.Join(atespaces, ", ")
}

// substrateBundleFail is substrateFail with the answer of a cluster that has
// no bundle routes yet.
func substrateBundleFail(err error) error {
	if e, ok := api.AsError(err); ok && (e.NotImplemented() || e.Status == 404) {
		return withExitCode(errors.New("this cluster does not accept bundles yet; ask your administrator to upgrade DefenseClaw on it"), substrateExitRefused)
	}
	if errors.Is(err, api.ErrBundleTooLarge) {
		return withExitCode(err, 2)
	}
	return substrateFail(err)
}
