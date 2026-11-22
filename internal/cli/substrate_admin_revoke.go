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
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

func newSubstrateAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administer people's access to the cluster (administrators)",
	}
	cmd.AddCommand(newSubstrateAdminRevokeCmd())
	return cmd
}

func newSubstrateAdminRevokeCmd() *cobra.Command {
	var (
		out          substrateOutput
		com          substrateCommon
		user, reason string
		list, lift   bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "End every sign-in of a person, list the ended ones, or lift an end",
		Long: `--user PERSON ends every token of that person issued before now, on every device, and closes their open
terminals (PERSON is a principal such as bob@example.com, or issuer#subject to end the sign-ins of a person who
has not signed in yet). A refresh token the person holds can still get new tokens from the sign-in server: to
lock someone out, also end their sessions there. --list shows the people whose sign-ins are ended. --lift --user
PERSON removes an end early; it is audited.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return cliusage.WithExitCode(err, 2)
			}
			user = strings.TrimSpace(user)
			switch {
			case list && (lift || user != "" || reason != ""):
				return cliusage.WithExitCode(errors.New("--list takes no --user, --lift or --reason"), 2)
			case !list && user == "":
				return cliusage.WithExitCode(errors.New("name the person with --user (a principal or issuer#subject), or use --list"), 2)
			case lift && reason != "":
				return cliusage.WithExitCode(errors.New("--lift takes no --reason"), 2)
			}
			sess, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			w := cmd.OutOrStdout()
			if list {
				revs, err := sess.Client.SigninEnds(ctx)
				if err != nil {
					return substrateRevokeFail(err, "")
				}
				if asJSON {
					return json.NewEncoder(w).Encode(map[string]any{"revocations": revs})
				}
				if len(revs) == 0 {
					fmt.Fprintln(w, "No sign-ins are ended.")
					return nil
				}
				var rows [][]string
				for _, r := range revs {
					reason := orWord(r.Reason, "-")
					if r.Scope == "overflow" {
						reason = "ended tokens past the per-person cap (a lift keeps this)"
					}
					rows = append(rows, []string{r.Person, r.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"), orWord(r.By, "-"),
						reason, r.Until.UTC().Format("2006-01-02 15:04 MST")})
				}
				substrateTable(w, []string{"PERSON", "ENDED BEFORE", "BY", "REASON", "UNTIL"}, rows)
				return nil
			}
			var rev api.Revocation
			if lift {
				rev, err = sess.Client.LiftSigninEnd(ctx, user)
			} else {
				rev, err = sess.Client.EndSigninsOf(ctx, user, reason)
			}
			if err != nil {
				return substrateRevokeFail(err, user)
			}
			if asJSON {
				return json.NewEncoder(w).Encode(rev)
			}
			if lift {
				fmt.Fprintf(w, "Lifted the end of the sign-ins of %s: tokens issued before it work again until they expire. Tokens ended one at a time stay ended.\n", safetext.Line(user))
				return nil
			}
			terminals := "open terminals"
			if rev.Closed == 1 {
				terminals = "open terminal"
			}
			fmt.Fprintf(w, "Ended every token of %s issued before %s, on every device. %d %s were closed. "+
				"A refresh token the person holds can still get new tokens: to lock them out, also end their sessions at the sign-in server.\n",
				safetext.Line(user), rev.NotBefore.UTC().Format("15:04:05 MST"), rev.Closed, terminals)
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&user, "user", "", "the person: a principal (bob@example.com) or issuer#subject")
	cmd.Flags().StringVar(&reason, "reason", "", "why (one line, up to 256 characters; kept with the end and audited)")
	cmd.Flags().BoolVar(&list, "list", false, "list the people whose sign-ins are ended")
	cmd.Flags().BoolVar(&lift, "lift", false, "remove the end of --user's sign-ins early")
	return cmd
}

// substrateRevokeFail words the answers only admin revoke gets.
func substrateRevokeFail(err error, user string) error {
	e, ok := api.AsError(err)
	switch {
	case ok && e.Reason == "person_unknown":
		return cliusage.WithExitCode(fmt.Errorf("no sign-in of %s has been seen. Use issuer#subject to revoke ahead of a first sign-in", safetext.Line(user)), substrateExitRefused)
	case ok && e.Status == http.StatusNotFound:
		return cliusage.WithExitCode(errors.New("this cluster's gateway can't end sign-ins (it is older than DefenseClaw 1.0.11, or ending sign-ins is off there)"), substrateExitRefused)
	case ok && e.Reason == "admin_only":
		return cliusage.WithExitCode(errors.New("only an administrator can end another person's sign-ins"), substrateExitRefused)
	}
	return substrateFail(err)
}
