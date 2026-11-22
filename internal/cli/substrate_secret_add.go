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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// substrateBindingNameRE is the gateway's own-binding name shape
// (secretbind.Binding.Check), checked first so the person gets a plain
// message instead of secret_invalid.
var substrateBindingNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func newSubstrateSecretsTemplatesCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "List the templates you may use to add your own secrets",
		Long: `Lists the templates your administrator approved for your own secrets: the hosts each one
covers without an approval and how the value goes into the request. Use one with secrets add.`,
		Args: cobra.NoArgs,
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
			list, mode, err := s.Client.SecretTemplates(ctx)
			if err != nil {
				return substrateFail(err)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{"templates": list, "mode": mode})
			}
			if mode == "values_only" {
				fmt.Fprintln(w, "Your administrator allows values only: you can store values for the secrets they defined\n(secrets set), but you cannot add your own.")
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(w, "No templates are available to you.")
				return nil
			}
			rows := make([][]string, 0, len(list))
			for _, t := range list {
				hosts := strings.Join(t.Hosts, ",")
				if hosts == "" {
					hosts = "(each host needs an admin)"
				}
				rows = append(rows, []string{t.Name, hosts, substrateTemplateHeader(t)})
			}
			substrateTable(w, []string{"NAME", "HOSTS", "HEADER"}, rows)
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

// substrateTemplateHeader says how the value goes into the request.
func substrateTemplateHeader(t api.SecretTemplate) string {
	switch t.Form {
	case "bearer":
		return t.Header + ": Bearer <token>"
	case "basic":
		user := t.BasicUser
		if user == "" {
			user = "<--user>"
		}
		return t.Header + ": Basic " + user + ":<token>"
	}
	return t.Header + ": <token>"
}

func newSubstrateSecretsAddCmd() *cobra.Command {
	var (
		com                          substrateCommon
		src                          substrateSecretSource
		template, host, expires, usr string
		allowEcho                    bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret of your own for one host, under a template",
		Long: `Creates your own secret NAME for HOST under TEMPLATE (see secrets templates) and stores its
value. A host the template covers is used from your agents' next request; any other host waits
until an administrator approves it. For a basic template (git hosts, PyPI) give only the token:
the cluster adds the user name. generic-basic needs --user.

` + substrateSourceHelp,
		Example: "defenseclaw substrate secrets add gl-work --template gitlab --host gitlab.com --from-op op://eng/gitlab/token\n" +
			"defenseclaw substrate secrets add nexus --template generic-basic --host nexus.corp.example --user ci-bot --from-file ~/.nexus-token",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !substrateBindingNameRE.MatchString(name) {
				return cliusage.UsageError(cmd, fmt.Errorf("%q is not a secret name: use lowercase letters, digits and -, up to 63", name))
			}
			if usr != "" && strings.ContainsAny(usr, ": \t") {
				return cliusage.UsageError(cmd, errors.New("--user cannot contain a colon or a space"))
			}
			exp, err := substrateParseExpiry(expires, time.Now())
			if err != nil {
				return cliusage.UsageError(cmd, err)
			}
			value, _, err := src.read(cmd)
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			res, err := s.Client.AddSecret(ctx, api.AddSecretRequest{Name: name, Template: template, Host: host,
				Value: value, Expires: exp, AllowEcho: allowEcho, User: usr})
			if err != nil {
				return substrateFail(err)
			}
			w := cmd.OutOrStdout()
			if res.Reason != "" {
				fmt.Fprintf(w, "%s is not covered by the %s template, so an administrator must approve it.\n", res.Host, res.Template)
				asked := ""
				if res.AskID != "" {
					asked = "Asked as " + res.AskID + ". "
				}
				fmt.Fprintln(w, asked+"Your value is stored and is not used until then. See it with: defenseclaw substrate approvals")
				return nil
			}
			fmt.Fprintf(w, "Stored %s for %s (template %s). Your agents use it from their next request.\n", res.Name, res.Host, res.Template)
			fmt.Fprintf(w, "Check it with: defenseclaw substrate secrets test %s\n", res.Name)
			return nil
		},
	}
	com.add(cmd)
	src.add(cmd)
	f := cmd.Flags()
	f.StringVar(&template, "template", "", "the template to use (see secrets templates)")
	f.StringVar(&host, "host", "", "the one host the secret is for")
	f.StringVar(&expires, "expires", "", "when the secret stops being used: 90d, 12h or a date (2027-01-31); at most 400 days")
	f.StringVar(&usr, "user", "", "the user name for a basic template (generic-basic needs it)")
	f.BoolVar(&allowEcho, "allow-echo", false, "allow a host that returns the requests it gets (only when your administrator allows it)")
	_ = cmd.MarkFlagRequired("template")
	_ = cmd.MarkFlagRequired("host")
	return cmd
}

// substrateParseExpiry reads --expires: empty (no expiry), Nd, Nh or a
// date (YYYY-MM-DD, the end of that day in UTC). The gateway enforces
// the 400-day limit.
func substrateParseExpiry(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	bad := fmt.Errorf("--expires %q: use a number of days (90d), hours (12h) or a date (2027-01-31)", s)
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'h') {
		unit, most := time.Hour, 400*24
		if s[n-1] == 'd' {
			unit, most = 24*time.Hour, 400
		}
		v, err := strconv.Atoi(s[:n-1])
		if err != nil || v <= 0 || v > most {
			return time.Time{}, bad
		}
		return now.UTC().Add(time.Duration(v) * unit), nil
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil || !d.After(now) {
		return time.Time{}, bad
	}
	return d.Add(24*time.Hour - time.Second), nil
}
