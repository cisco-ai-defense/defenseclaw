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
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
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
	workloadAud  string
	kube         bool
	kubeconfig   string
	kubeContext  string
	kubeNS       string
	kubeSA       string
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
sign-in is kept in the system keychain, never in a file you can read. The first time, give the cluster
address with --admin-url (your administrator has it); the cluster tells the launcher which sign-in server to
use. After that, "defenseclaw substrate login" alone renews the sign-in.

On a cluster that has no sign-in server (an open-source install), use --kube: you are then the Kubernetes user of
your current kubeconfig, and nothing is stored.

In CI, use --workload (or set DEFENSECLAW_SUBSTRATE_WORKLOAD_TOKEN_FILE): the run is then attributed to the
pipeline's own identity, with a GitHub Actions token or a projected Kubernetes token minted for the cluster's workload audience, and nothing is stored.`,
		Example: "defenseclaw substrate login --admin-url https://admin.example.test:9443\n" +
			"defenseclaw substrate login --admin-url https://admin.example.test:9443 --issuer https://sso.example.test/realms/corp --client-id defenseclaw-launcher\n" +
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
	fl.StringVar(&f.workloadAud, "workload-audience", "", "the audience a workload token must be minted for (default: defenseclaw)")
	fl.BoolVar(&f.kube, "kube", false, "sign in with your current kubeconfig identity (clusters without a sign-in server)")
	fl.StringVar(&f.kubeconfig, "kubeconfig", "", "with --kube, the kubeconfig file (default: kubectl's own rules)")
	fl.StringVar(&f.kubeContext, "kube-context", "", "with --kube, the kubeconfig context (default: its current one)")
	fl.StringVar(&f.kubeNS, "kube-namespace", "", "with --kube, the namespace DefenseClaw runs in (required; without it login only says which namespace publishes --admin-url)")
	fl.StringVar(&f.kubeSA, "kube-service-account", "", "with --kube, sign in as this ServiceAccount (NAMESPACE/NAME or NAME) with a short-lived token; a client-certificate kubeconfig uses defenseclaw-launcher")
	fl.BoolVar(&f.noBrowser, "no-browser", false, "do not open a browser; print the address and code only")
	fl.BoolVar(&f.workload, "workload", false, "sign in as a CI workload with the pipeline's own token")
	fl.StringVar(&f.workloadFile, "workload-token-file", "", "file holding the workload token (CI)")
	fl.StringVar(&f.profile, "default-profile", "", "profile to use when run is given none")
	fl.StringVar(&f.template, "default-template", "", "template to use when run is given none")
	return cmd
}

// substrateLoginInfo asks the cluster how people sign in to it (GET /info,
// no token) and fills in the sign-in server and client id that were not
// given, so the first sign-in needs only --admin-url. A flag that was given
// wins. A cluster that signs people in with Kubernetes, or not at all, gets
// the command or the person to ask instead.
func substrateLoginInfo(ctx context.Context, c *auth.Context, w io.Writer) error {
	if err := c.Validate(false); err != nil {
		return cliusage.WithExitCode(err, substrateExitRefused)
	}
	cl, err := api.New(api.Options{Base: c.AdminURL, CAFile: c.AdminCAFile, Token: func(context.Context) (string, error) { return "", nil }})
	if err != nil {
		return cliusage.WithExitCode(err, substrateExitRefused)
	}
	info, err := cl.Info(ctx)
	if e, ok := api.AsError(err); ok && (e.Status == 404 || e.NotImplemented()) {
		return cliusage.WithExitCode(errors.New("this cluster does not say how to sign in; give --issuer URL and --client-id ID too (your administrator has them)"), 2)
	}
	if err != nil {
		return substrateFail(err)
	}
	switch info.SignIn {
	case "oidc":
		if c.Issuer == "" {
			c.Issuer = info.Issuer
		}
		if c.ClientID == "" {
			c.ClientID = info.ClientID
		}
		if c.Issuer == "" || c.ClientID == "" {
			return cliusage.WithExitCode(errors.New("the cluster does not name its whole sign-in server; give --issuer URL and --client-id ID (your administrator has them)"), 2)
		}
		fmt.Fprintf(w, "This cluster signs you in with %s.\n", safetext.Line(c.Issuer))
		return nil
	case "kubernetes":
		return cliusage.WithExitCode(fmt.Errorf("this cluster signs you in with your Kubernetes identity. Run: defenseclaw substrate login --kube --admin-url %s", safetext.Line(c.AdminURL)), 2)
	}
	return cliusage.WithExitCode(errors.New("this cluster has no sign-in set up yet; ask your administrator to set up substrate.identity.oidc"), substrateExitRefused)
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
	// A file is saved as an absolute path: later commands run from other
	// folders (GAP-0421).
	setFile := func(flag string, dst *string, v string) error {
		if !fl.Changed(flag) {
			return nil
		}
		if v = strings.TrimSpace(v); v != "" {
			abs, err := filepath.Abs(v)
			if err != nil {
				return cliusage.WithExitCode(fmt.Errorf("--%s: %w", flag, err), 2)
			}
			v = abs
		}
		*dst = v
		return nil
	}
	set("admin-url", &c.AdminURL, f.adminURL)
	if err := setFile("admin-ca-file", &c.AdminCAFile, f.adminCA); err != nil {
		return err
	}
	set("issuer", &c.Issuer, f.issuer)
	if err := setFile("issuer-ca-file", &c.IssuerCAFile, f.issuerCA); err != nil {
		return err
	}
	set("client-id", &c.ClientID, f.clientID)
	set("default-profile", &c.Profile, f.profile)
	set("default-template", &c.Template, f.template)
	if fl.Changed("scope") {
		c.Scopes = f.scopes
	}
	set("workload-audience", &c.WorkloadAudience, f.workloadAud)
	if f.kube {
		c.Kube = true
	}
	if err := setFile("kubeconfig", &c.Kubeconfig, f.kubeconfig); err != nil {
		return err
	}
	set("kube-context", &c.KubeContext, f.kubeContext)
	set("kube-namespace", &c.KubeNamespace, f.kubeNS)
	set("kube-service-account", &c.KubeServiceAccount, f.kubeSA)
	if c.Kube && (f.workload || f.noBrowser || fl.Changed("issuer") || fl.Changed("client-id")) {
		return cliusage.WithExitCode(errors.New("--kube signs in with your kubeconfig; leave --workload, --issuer, --client-id and --no-browser out"), 2)
	}
	kube := c.Kube
	workload := !kube && (f.workload || substrateWorkloadFromEnv(cmd) != nil)
	if c.AdminURL == "" {
		return cliusage.WithExitCode(errors.New("give the cluster address the first time: defenseclaw substrate login --admin-url https://HOST:PORT (your administrator has it)"), 2)
	}
	if !workload && !kube && (c.Issuer == "" || c.ClientID == "") {
		if err := substrateLoginInfo(ctx, &c, cmd.ErrOrStderr()); err != nil {
			return err
		}
	}
	if err := c.Validate(!workload && !kube); err != nil {
		return cliusage.WithExitCode(err, substrateExitRefused)
	}
	persist := !workload && !kube
	var store auth.Store
	if persist {
		var err error
		if store, err = auth.OpenStore(); err != nil {
			return err
		}
	}
	var tok *auth.Token
	if kube {
		// The kube credential goes only to an admin address the cluster itself
		// names (GAP-0130); the check sends it to the Kubernetes API server alone.
		var pin auth.KubePin
		if pin, err = auth.KubeVerifyEndpoint(ctx, c.KubeOptions(), c.AdminURL, c.KubeNamespace); err != nil {
			var found *auth.KubeNamespaceFound
			if errors.As(err, &found) {
				return cliusage.WithExitCode(fmt.Errorf("%s: %s", err.Error(), substrateLoginAgainWith(fl, "kube-namespace", found.Namespace)), 2)
			}
			return substrateFail(err)
		}
		c = c.WithKubePin(pin)
		tok, err = auth.KubeLogin(ctx, c.KubeOptions())
	} else if workload {
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
	if persist {
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
	note, warning := "", ""
	probe := auth.SourceOptions{}
	if kube {
		ko := c.KubeOptions()
		probe.Kube = &ko
	}
	if workload {
		// A workload token is checked like any sign-in, so a token the
		// cluster refuses shows now and not at the first run (GAP-0543).
		probe.Workload = &auth.WorkloadOptions{TokenFile: f.workloadFile}
	}
	if cl, err := api.New(api.Options{Base: c.AdminURL, CAFile: c.AdminCAFile, Token: auth.NewSource(name, c, store, probe).Token}); err == nil {
		_, wm, err := cl.ListWithWorkload(ctx, api.ListOptions{})
		if err != nil {
			if e, ok := api.AsError(err); ok && !e.NotImplemented() {
				note = "You are signed in, but the cluster did not accept it yet: " + substrateAPIMessage(e)
			} else if !ok {
				note = "You are signed in, but the cluster could not be reached: " + safetext.Line(err.Error())
			}
		} else if workload {
			warning = substrateWorkloadWarning(wm, tok.Subject)
		}
	}
	w := cmd.OutOrStdout()
	who := substrateDash(tok.Principal)
	if asJSON {
		out := map[string]any{"context": name, "signed_in_as": tok.Principal, "subject": tok.Subject, "kind": tok.Kind, "note": note}
		if warning != "" {
			out["warning"] = warning
		}
		return writeSubstrateJSON(w, out)
	}
	if kube && c.KubeServiceAccount == "" && strings.HasPrefix(tok.Principal, "system:serviceaccount:") {
		// GAP-0192: say once why the person is a ServiceAccount now.
		fmt.Fprintf(cmd.ErrOrStderr(), "Your kubeconfig signs in with a client certificate, which DefenseClaw cannot check, so you sign in as the ServiceAccount %s (name another with --kube-service-account NAMESPACE/NAME).\n",
			safetext.Line(strings.Replace(strings.TrimPrefix(tok.Principal, "system:serviceaccount:"), ":", "/", 1)))
	}
	fmt.Fprintf(w, "Signed in as %s on %s.\n", who, name)
	if note != "" {
		fmt.Fprintln(w, note)
	}
	if warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Warning: "+warning)
	}
	fmt.Fprintln(w, "Next: start a coding agent in a project folder with: defenseclaw substrate run claude")
	return nil
}

// substrateWorkloadWarning is what login --workload warns when the cluster
// says no match.substrate.workloads entry matches the workload's subject
// (GAP-0542), "" when one matches or the cluster sent no answer (an older
// cluster). The subject is the cluster's, else the token's, made one safe
// line.
func substrateWorkloadWarning(m *api.WorkloadMatch, subject string) string {
	if m == nil || strings.TrimSpace(m.Entry) != "" {
		return ""
	}
	if s := strings.TrimSpace(m.Subject); s != "" {
		subject = s
	}
	return fmt.Sprintf("no match.substrate.workloads entry matches %s; it gets the default profile", substrateDash(subject))
}

func newSubstrateLogoutCmd() *cobra.Command {
	var (
		com substrateCommon
		all bool
	)
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Sign out of a cluster: end the sign-in there and forget it",
		Long: `Ends your sign-in on the cluster, so a copy of its token stops working there, then ends it at the sign-in server
where that server supports it, and removes the stored sign-in. --all ends every token of yours issued before now, on
every device, and closes their open terminals. An end covers tokens already issued: a refresh token held on another
device or in a copied store can still get new ones, so also end your sessions at the sign-in server (ask your
administrator). Your agents keep running; sign in again to reach them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, c, err := auth.ResolveContext(com.context)
			if err != nil {
				return cliusage.WithExitCode(err, substrateExitSignedOut)
			}
			store, err := auth.OpenStore()
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			saved, _ := store.Load(name)
			var cl substrateSigninEnder
			if all || saved != nil && (saved.AccessToken != "" || saved.IDToken != "") {
				sess, err := substrateOpen(cmd, &com)
				if err != nil {
					return err
				}
				cl = sess.Client
			}
			msg, err := substrateEndSignin(ctx, cl, name, saved, all, time.Now())
			if err != nil {
				// --all ended nothing: the stored sign-in is kept, so the
				// person can run it again.
				return err
			}
			if err := auth.Logout(ctx, name, c, store, nil); err != nil {
				return substrateFail(err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVar(&all, "all", false, "end every token of yours issued before now, on every device")
	return cmd
}

// substrateSigninEnder is the cluster call logout makes (api.Client).
type substrateSigninEnder interface {
	EndSignin(ctx context.Context, scope string, also ...string) (api.Revocation, error)
}

// substrateEndSignin ends the sign-in on the cluster before logout forgets
// it, and says what happened (B5.1). One sign-in (scope this) is forgotten
// whatever the cluster answers, with a note when a copy may still work;
// --all (scope all) is an error when the cluster ended nothing, and the
// stored sign-in is kept.
func substrateEndSignin(ctx context.Context, cl substrateSigninEnder, name string, saved *auth.Token, all bool, now time.Time) (string, error) {
	scope := "this"
	if all {
		scope = "all"
	}
	if cl == nil {
		// Nothing stored: no token of this context to end.
		return fmt.Sprintf("Signed out of %s.", name), nil
	}
	var also []string
	if !all && saved != nil {
		// Both stored tokens of this sign-in: the gateway accepts the
		// access token too when api_audience is set (RV1-03).
		for _, tok := range []string{saved.IDToken, saved.AccessToken} {
			if tok != "" {
				also = append(also, tok)
			}
		}
	}
	rev, err := cl.EndSignin(ctx, scope, also...)
	if err == nil {
		if all {
			who := orWord(safetext.Line(rev.Principal), safetext.Line(rev.Person))
			// Like the help: an end covers tokens already issued, not a
			// refresh token held elsewhere (RV2-02).
			return fmt.Sprintf("Signed out of %s: every token of %s issued before %s is refused, on every device. "+
				"A refresh token held elsewhere can still get new tokens: also end your sessions at the sign-in server (ask your administrator).",
				name, who, rev.NotBefore.UTC().Format("15:04:05 MST")), nil
		}
		return fmt.Sprintf("Signed out of %s. This sign-in no longer works on the cluster.", name), nil
	}
	e, isAPI := api.AsError(err)
	switch {
	case isAPI && e.Status == http.StatusNotFound:
		// A gateway before 1.0.11, or one with ending sign-ins off (kept
		// for those gateways until 1.0.14).
		if all {
			return "", cliusage.WithExitCode(fmt.Errorf("this cluster's gateway can't end sign-ins (it is older than DefenseClaw 1.0.11, "+
				"or ending sign-ins is off there): nothing was changed and you are still signed in to %s", name), substrateExitRefused)
		}
		return strings.TrimSpace(fmt.Sprintf("Signed out of %s. %s", name, substrateLogoutNote(saved, now))), nil
	case isAPI && e.Reason == "signin_ended":
		if all {
			return "", cliusage.WithExitCode(fmt.Errorf("this sign-in to %s was already ended, so it can't end your other sign-ins: "+
				"sign in again with defenseclaw substrate login, then run defenseclaw substrate logout --all", name), substrateExitSignedOut)
		}
		return fmt.Sprintf("Signed out of %s. This sign-in had already been ended on the cluster.", name), nil
	case !all && (errors.Is(err, auth.ErrNotSignedIn) || isAPI && e.Unauthorized()):
		// The cluster does not take this token (expired, refused): there is
		// nothing of it to end there.
		return fmt.Sprintf("Signed out of %s.", name), nil
	case all:
		return "", substrateFail(err)
	}
	why := err.Error()
	if isAPI {
		why = substrateAPIMessage(e)
	}
	msg := fmt.Sprintf("Signed out of %s, but the cluster could not end this sign-in: %s.", name, safetext.Line(why))
	if note := substrateLogoutCopyNote(saved, now); note != "" {
		msg += " " + note
	}
	return msg, nil
}

// substrateLogoutNote is what logout says when the cluster's gateway can't
// end sign-ins (a 404 from a gateway before 1.0.11 or with ending sign-ins
// off; GAP-0409): how long a copy of the token still works. "" when nothing
// was stored or it has already expired. Kept for those gateways until
// 1.0.14.
func substrateLogoutNote(saved *auth.Token, now time.Time) string {
	note := substrateLogoutCopyNote(saved, now)
	if note == "" {
		return ""
	}
	return "This cluster's gateway can't end sign-ins (it is older than DefenseClaw 1.0.11, or ending sign-ins is off there). " + note
}

// substrateLogoutCopyNote says until when a copy of saved works: its
// expiry, or 15 minutes after it was issued (identity.MaxPersonSignInAge)
// when that comes first, as the admin listener accepts it (GAP-0409).
func substrateLogoutCopyNote(saved *auth.Token, now time.Time) string {
	if saved == nil || saved.AccessToken == "" && saved.IDToken == "" {
		return ""
	}
	until := saved.UsableUntil()
	if until.IsZero() {
		until = saved.Expiry
	}
	if !until.After(now) {
		return ""
	}
	left := max(int(until.Sub(now).Round(time.Minute)/time.Minute), 1)
	return fmt.Sprintf("A copy of the token works until %s (about %d min; the cluster accepts a sign-in token for at most %d minutes after it was issued).",
		until.UTC().Format("15:04 MST"), left, int(identity.MaxPersonSignInAge/time.Minute))
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
				return cliusage.WithExitCode(auth.ErrNotSignedIn, substrateExitSignedOut)
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
				fmt.Fprintf(w, "Groups:   %s\n", safetext.Line(strings.Join(tok.Groups, ", ")))
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

// substrateLoginAgainWith is the login command the person typed, with
// --name value set (replaced if given), as one line they can copy.
func substrateLoginAgainWith(fl *pflag.FlagSet, name, value string) string {
	parts := []string{"defenseclaw", "substrate", "login"}
	fl.Visit(func(f *pflag.Flag) {
		if f.Name == name {
			return
		}
		if f.Value.Type() == "bool" {
			if f.Value.String() == "true" {
				parts = append(parts, "--"+f.Name)
			}
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			for _, v := range sv.GetSlice() {
				parts = append(parts, "--"+f.Name, substrateShellWord(v))
			}
			return
		}
		parts = append(parts, "--"+f.Name, substrateShellWord(f.Value.String()))
	})
	parts = append(parts, "--"+name, substrateShellWord(value))
	return "run: " + strings.Join(parts, " ")
}

// substrateShellWord quotes v for a POSIX shell when it needs it.
func substrateShellWord(v string) string {
	if v != "" && strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@,+%") == "" {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
