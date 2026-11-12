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
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

type substrateLoginFlags struct {
	out          substrateOutput
	name         string
	adminURL     string
	adminCA      string
	issuer       string
	issuerCA     string
	clientID     string
	scopes       []string
	routerURL    string
	routerCA     string
	routerCert   string
	routerKey    string
	relayPort    int
	noBrowser    bool
	workload     bool
	workloadFile string
	profile      string
	template     string
}

func newSubstrateLoginCmd() *cobra.Command {
	var f substrateLoginFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to a cluster",
		Long: `Signs you in to the cluster your organization runs, with your own account. It prints a web
address and a short code; open the address in any browser, enter the code and approve. Your
sign-in is kept in the system keychain, never in a file you can read. The first time, give the cluster's
addresses (your administrator has them); after that, "defenseclaw substrate login" alone renews the sign-in.

In CI, use --workload (or set DEFENSECLAW_SUBSTRATE_WORKLOAD_TOKEN_FILE): the run is then attributed to the
pipeline's own identity, with a GitHub Actions or Kubernetes service-account token, and nothing is stored.`,
		Example: "defenseclaw substrate login --admin-url https://admin.example.test:9443 --issuer https://sso.example.test/realms/corp --client-id defenseclaw-launcher\n" +
			"defenseclaw substrate login\n" +
			"defenseclaw substrate login --workload --workload-token-file /var/run/secrets/ci/token",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runSubstrateLogin(cmd, &f) },
	}
	f.out.add(cmd)
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "name for this cluster in your list (default: the current one, else \"default\")")
	fl.StringVar(&f.adminURL, "admin-url", "", "the cluster's DefenseClaw address, https://HOST:PORT")
	fl.StringVar(&f.adminCA, "admin-ca-file", "", "certificate authority (PEM) that signed the cluster's certificate")
	fl.StringVar(&f.issuer, "issuer", "", "your organization's sign-in address (OpenID issuer)")
	fl.StringVar(&f.issuerCA, "issuer-ca-file", "", "certificate authority (PEM) that signed the sign-in server's certificate")
	fl.StringVar(&f.clientID, "client-id", "", "the sign-in application id for this launcher")
	fl.StringSliceVar(&f.scopes, "scope", nil, "sign-in scopes (default: openid profile email groups)")
	fl.StringVar(&f.routerURL, "router-url", "", "the cluster's agent entrance, https://HOST:PORT")
	fl.StringVar(&f.routerCA, "router-ca-file", "", "certificate authority (PEM) of the agent entrance")
	fl.StringVar(&f.routerCert, "router-cert-file", "", "client certificate (PEM) for the agent entrance, when your administrator issues one")
	fl.StringVar(&f.routerKey, "router-key-file", "", "private key (PEM) for --router-cert-file")
	fl.IntVar(&f.relayPort, "relay-port", 0, "the port of the terminal relay inside an agent (default 8080)")
	fl.BoolVar(&f.noBrowser, "no-browser", false, "do not open a browser; print the address and code only")
	fl.BoolVar(&f.workload, "workload", false, "sign in as a CI workload with the pipeline's own token")
	fl.StringVar(&f.workloadFile, "workload-token-file", "", "file holding the workload token (CI)")
	fl.StringVar(&f.profile, "default-profile", "", "profile to use when run is given none")
	fl.StringVar(&f.template, "default-template", "", "template to use when run is given none")
	return cmd
}

func runSubstrateLogin(cmd *cobra.Command, f *substrateLoginFlags) error {
	asJSON, err := f.out.wantJSON()
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	cf, err := auth.LoadContexts()
	if err != nil {
		return err
	}
	name := strings.TrimSpace(f.name)
	if name == "" {
		name = cf.Current
	}
	if name == "" {
		name = "default"
	}
	c := cf.Contexts[name]
	fl := cmd.Flags()
	set := func(flag string, dst *string, v string) {
		if fl.Changed(flag) {
			*dst = v
		}
	}
	set("admin-url", &c.AdminURL, f.adminURL)
	set("admin-ca-file", &c.AdminCAFile, f.adminCA)
	set("issuer", &c.Issuer, f.issuer)
	set("issuer-ca-file", &c.IssuerCAFile, f.issuerCA)
	set("client-id", &c.ClientID, f.clientID)
	set("router-url", &c.RouterURL, f.routerURL)
	set("router-ca-file", &c.RouterCAFile, f.routerCA)
	set("router-cert-file", &c.RouterCertFile, f.routerCert)
	set("router-key-file", &c.RouterKeyFile, f.routerKey)
	set("default-profile", &c.Profile, f.profile)
	set("default-template", &c.Template, f.template)
	if fl.Changed("scope") {
		c.Scopes = f.scopes
	}
	if fl.Changed("relay-port") {
		c.RelayPort = f.relayPort
	}
	workload := f.workload || substrateWorkloadFromEnv(cmd) != nil
	if c.AdminURL == "" {
		return withExitCode(errors.New("give the cluster's address the first time: defenseclaw substrate login --admin-url https://HOST:PORT --issuer URL --client-id ID (your administrator has these)"), 2)
	}
	if err := c.Validate(!workload); err != nil {
		return withExitCode(err, substrateExitRefused)
	}
	if !workload && (c.Issuer == "" || c.ClientID == "") {
		return withExitCode(errors.New("signing in needs --issuer and --client-id the first time (your administrator has them)"), 2)
	}
	store, err := auth.OpenStore()
	if err != nil {
		return err
	}
	var tok *auth.Token
	if workload {
		tok, err = auth.WorkloadLogin(ctx, c, auth.WorkloadOptions{TokenFile: f.workloadFile})
	} else {
		interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
		tok, err = auth.DeviceLogin(ctx, c, auth.LoginOptions{
			NoBrowser: f.noBrowser, Out: cmd.ErrOrStderr(), Interactive: interactive,
		})
	}
	if err != nil {
		return substrateFail(err)
	}
	if !workload {
		if err := store.Save(name, tok); err != nil {
			return err
		}
	}
	cf.Contexts[name] = c
	if cf.Current == "" || !fl.Changed("name") || cf.Current == name {
		cf.Current = name
	}
	if err := cf.Save(); err != nil {
		return err
	}
	// Check that the cluster takes this sign-in, so a wrong issuer shows now
	// and not at the first run.
	note := ""
	if cl, err := api.New(api.Options{Base: c.AdminURL, CAFile: c.AdminCAFile, Token: auth.NewSource(name, c, store, auth.SourceOptions{}).Token}); err == nil && !workload {
		if _, err := cl.List(ctx, api.ListOptions{}); err != nil {
			if e, ok := api.AsError(err); ok && !e.NotImplemented() {
				note = "You are signed in, but the cluster did not accept it yet: " + substrateAPIMessage(e)
			} else if !ok {
				note = "You are signed in, but the cluster could not be reached: " + err.Error()
			}
		}
	}
	w := cmd.OutOrStdout()
	who := substrateDash(tok.Principal)
	if asJSON {
		return writeSubstrateJSON(w, map[string]any{"context": name, "signed_in_as": tok.Principal, "subject": tok.Subject, "kind": tok.Kind, "note": note})
	}
	fmt.Fprintf(w, "Signed in as %s on %s.\n", who, name)
	if note != "" {
		fmt.Fprintln(w, note)
	}
	fmt.Fprintln(w, "Next: start a coding agent in a project folder with: defenseclaw substrate run claude")
	return nil
}

func newSubstrateLogoutCmd() *cobra.Command {
	var com substrateCommon
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Sign out of a cluster and forget the stored sign-in",
		Long:  `Removes your stored sign-in for the cluster and, where the sign-in server supports it, ends it there too. Your agents keep running; sign in again to reach them.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, c, err := auth.ResolveContext(com.context)
			if err != nil {
				return withExitCode(err, substrateExitSignedOut)
			}
			store, err := auth.OpenStore()
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			if err := auth.Logout(ctx, name, c, store, nil); err != nil {
				return substrateFail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signed out of %s.\n", name)
			return nil
		},
	}
	com.add(cmd)
	return cmd
}

func newSubstrateWhoamiCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show who you are signed in as",
		Long:  `Shows the account, groups and expiry of your sign-in for the cluster. The token itself is never shown.`,
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
			tok, err := s.Source.Current(ctx)
			if err != nil {
				return substrateFail(err)
			}
			if tok == nil {
				return withExitCode(auth.ErrNotSignedIn, substrateExitSignedOut)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{
					"context": s.Name, "admin_url": s.Ctx.AdminURL, "principal": tok.Principal, "subject": tok.Subject,
					"issuer": tok.Issuer, "groups": tok.Groups, "kind": tok.Kind, "expires": tok.Expiry,
				})
			}
			fmt.Fprintf(w, "Signed in as %s (%s) on %s\n", substrateDash(tok.Principal), substrateDash(tok.Kind), s.Name)
			if len(tok.Groups) > 0 {
				fmt.Fprintf(w, "Groups:   %s\n", strings.Join(tok.Groups, ", "))
			}
			if !tok.Expiry.IsZero() {
				fmt.Fprintf(w, "Token:    renews itself; the current one lasts until %s\n", tok.Expiry.Local().Format(time.RFC1123))
			}
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}
