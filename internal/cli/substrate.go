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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
)

// Exit codes of the substrate commands, besides 0 (done) and 1 (failed):
// 2 is a usage error (cobra), 3 a refusal the user cannot fix by retrying,
// 4 not signed in.
const (
	substrateExitRefused   = 3
	substrateExitSignedOut = 4
)

var substrateCmd = &cobra.Command{
	Use:   "substrate",
	Short: "Run coding agents on Agent Substrate, in your organization's cluster",
	Long: `Run Claude Code, Codex and other coding agents in a Kubernetes cluster that runs
Agent Substrate, with DefenseClaw guarding every tool call, model call and network
request the same way it does on a laptop. The agent works on a copy of your folder
inside a sandbox in the cluster; no keys are in it. It keeps running when you
detach, and you can come back from any machine.

Sign in once with "defenseclaw substrate login", then run "defenseclaw substrate run claude"
in a project folder. These commands need no local DefenseClaw install.`,
	PersistentPreRunE: substratePreRun,
	// The substrate commands never open the audit store.
	PersistentPostRun: func(*cobra.Command, []string) {},
	SilenceUsage:      true,
}

// substratePreRun skips the daemon bootstrap and the local config: the
// launcher talks to a cluster and runs on a laptop with nothing installed.
// The administrator commands read config.yaml themselves when they need it.
// A terminal whose locale is not UTF-8 gets agent text as ASCII only
// (safetext.UseASCII): it would read parts of ordinary characters as 8-bit
// controls.
func substratePreRun(cmd *cobra.Command, _ []string) error {
	safetext.UseASCII(!safetext.TerminalUTF8(os.Getenv))
	substrateShowErrors(cmd)
	return nil
}

// substrateShowErrors makes the error cmd returns safe to print: its text
// can carry what the cluster or the agent answered, and cobra prints it as
// it is. The launcher writes its own hints over several lines, so the text
// keeps its newlines (safetext.Clean); a value inside it that could forge a
// line is already one line where it was read (api, workspace). Exit codes
// survive (the error is wrapped, not replaced).
func substrateShowErrors(cmd *cobra.Command) {
	run := cmd.RunE
	if run == nil {
		return
	}
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if err := run(c, args); err != nil {
			return substrateShownError{err}
		}
		return nil
	}
}

type substrateShownError struct{ err error }

func (e substrateShownError) Error() string { return safetext.Clean(e.err.Error()) }
func (e substrateShownError) Unwrap() error { return e.err }

// substrateOutput is the --output/--json pair every read command has.
type substrateOutput struct {
	output string
	json   bool
}

func (o *substrateOutput) add(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	cmd.Flags().BoolVar(&o.json, "json", false, "same as --output json")
}

func (o *substrateOutput) wantJSON() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(o.output)) {
	case "", "text":
		return o.json, nil
	case "json":
		return true, nil
	}
	return false, fmt.Errorf("--output must be text or json, not %q", o.output)
}

// substrateCommon is the flag set every command that talks to a cluster has.
type substrateCommon struct {
	context string
}

func (c *substrateCommon) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&c.context, "context", "", "cluster to use (default: the one you signed in to last)")
}

// substrateSession is a resolved context with a way to get its bearer.
type substrateSession struct {
	Name   string
	Ctx    auth.Context
	Source *auth.Source
	// Bearer is the sign-in token for one request (Source.Token, or a fake in tests).
	Bearer func(ctx context.Context) (string, error)
	Client *api.Client
}

// substrateOpen resolves the context, builds the token source and the admin
// client. It does not need the user to be signed in until a call is made.
var substrateOpen = func(cmd *cobra.Command, c *substrateCommon) (*substrateSession, error) {
	name, actx, err := auth.ResolveContext(c.context)
	if err != nil {
		return nil, withExitCode(err, substrateExitSignedOut)
	}
	if err := actx.Validate(false); err != nil {
		return nil, withExitCode(err, substrateExitRefused)
	}
	// A kube context signs in with the kubeconfig, a workload with the
	// pipeline's token: neither keeps a secret, so neither needs a keychain.
	opts := auth.SourceOptions{}
	var store auth.Store
	switch w := substrateWorkloadFromEnv(cmd); {
	case actx.Kube:
		ko := actx.KubeOptions()
		opts.Kube = &ko
	case w != nil:
		opts.Workload = w
	default:
		if store, err = auth.OpenStore(); err != nil {
			return nil, err
		}
	}
	src := auth.NewSource(name, actx, store, opts)
	cl, err := api.New(api.Options{Base: actx.AdminURL, CAFile: actx.AdminCAFile, Token: src.Token})
	if err != nil {
		return nil, withExitCode(err, substrateExitRefused)
	}
	return &substrateSession{Name: name, Ctx: actx, Source: src, Bearer: src.Token, Client: cl}, nil
}

// substrateWorkloadFromEnv selects workload identity (CI) when the command
// line or the environment names one.
func substrateWorkloadFromEnv(cmd *cobra.Command) *auth.WorkloadOptions {
	file := ""
	if f := cmd.Flags().Lookup("workload-token-file"); f != nil {
		file = f.Value.String()
	}
	if file == "" {
		file = envvars.Getenv("DEFENSECLAW_SUBSTRATE_WORKLOAD_TOKEN_FILE")
	}
	if file != "" || (os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "") ||
		envvars.Getenv("DEFENSECLAW_SUBSTRATE_K8S_TOKEN_FILE") != "" {
		return &auth.WorkloadOptions{TokenFile: file}
	}
	return nil
}

// substrateContext is the command's context: Ctrl-C and SIGTERM cancel it.
func substrateContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// substrateFail turns an error from the launcher into one with a plain
// message, the fix, and the exit code.
func substrateFail(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, auth.ErrNotSignedIn) || errors.Is(err, attach.ErrNotSignedIn) {
		return withExitCode(err, substrateExitSignedOut)
	}
	for _, refused := range []error{attach.ErrNotAllowed, attach.ErrNoActor, attach.ErrNotOffered, attach.ErrAttachOff} {
		if errors.Is(err, refused) {
			return withExitCode(err, substrateExitRefused)
		}
	}
	if e, ok := api.AsError(err); ok {
		return withExitCode(errors.New(substrateAPIMessage(e)), substrateAPIExit(e))
	}
	return err
}

func substrateAPIExit(e *api.Error) int {
	switch {
	case e.Unauthorized():
		return substrateExitSignedOut
	case e.Status == 403 || e.Status == 404 || e.NotImplemented():
		return substrateExitRefused
	}
	return 1
}

// substrateAPIMessage says what the cluster answered in plain words, with
// the fix where there is one.
func substrateAPIMessage(e *api.Error) string {
	switch {
	case e.Unauthorized():
		return "the cluster did not accept your sign-in (" + orWord(e.Reason, "token refused") + "). Sign in again with: defenseclaw substrate login"
	case e.NotImplemented():
		return "this cluster does not offer that yet; ask your administrator to upgrade DefenseClaw on it"
	case e.Status == 403 && e.Reason == "profile_not_allowed":
		return "you may not use that profile. Ask your administrator which profiles you can run, or leave --profile out to use your default"
	case e.Status == 403 && e.Reason == "atespace_not_allowed":
		return "that group of agents is not open to you; ask your administrator"
	case e.Status == 403 && e.Reason == "actor_refused":
		return "the cluster refused to start this agent: " + orWord(e.Detail, "it got no network policy") + " (" + orWord(e.Refusal, "refused") +
			"). Nothing was started. If this is unexpected, give your administrator the agent id " + orWord(e.ActorUID, "(none)") + " (" + orWord(e.Actor, "unknown") + ")"
	case e.Status == 403 && e.Reason == "template_attestation_unreadable" && e.Retryable:
		return "the cluster could not check the template's attestation right now (retryable: " + orWord(safetext.Line(e.Detail), "the check did not finish") +
			"), so it started nothing; try again in a minute, and if it stays, ask your administrator to check the template with defenseclaw substrate template verify"
	case e.Status == 403 && e.Reason == "template_attestation_unreadable":
		return "the cluster could not read the template's attestation, so it started nothing; try again in a minute, and if it stays, ask your administrator to check the template with defenseclaw substrate template verify"
	case e.Status == 403 && e.Reason == "template_not_attested":
		return "the template is not attested (" + orWord(safetext.Line(e.Detail), "no valid attestation") +
			"), so a managed cluster starts nothing from it; ask your administrator to rebuild and publish it with defenseclaw substrate template build"
	case e.Status == 403 && e.Reason == "template_connector_unlabeled":
		return "the template's attestation names no agent connector, so a managed cluster starts nothing from it; ask your administrator to rebuild it with defenseclaw substrate template build"
	case e.Status == 403:
		return "the cluster refused this (" + orWord(e.Reason, "not allowed") + ")"
	case e.Status == 404:
		return "the cluster has no such item, or it is not yours"
	case e.Status == 413:
		return "that was too large for the cluster (" + orWord(e.Reason, "too large") + ")"
	case e.Status == 503 && e.Reason == "no_free_worker":
		return "the cluster has no free worker for a new agent right now; nothing was started. Your running agents hold workers: see them with defenseclaw substrate list, and free one with defenseclaw substrate delete NAME, or ask your administrator for more workers"
	case e.Status == 429:
		return "the cluster is rate limiting you; wait a moment and try again"
	case e.Status == 502 || e.Status == 503:
		return "the cluster could not do that right now (" + orWord(e.Reason, "unavailable") + "); try again in a minute"
	}
	return e.Error()
}

func orWord(v, def string) string {
	if v = safetext.Line(v); v == "" {
		return def
	}
	return strings.ReplaceAll(v, "_", " ")
}

func writeSubstrateJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(safetext.JSON(b), '\n'))
	return err
}

// substrateTable prints rows under a header with aligned columns.
func substrateTable(w io.Writer, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		// Cells can hold text an agent or the cluster chose.
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = safetext.Line(c)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	_ = tw.Flush()
}

func init() {
	substrateCmd.AddCommand(
		newSubstrateLoginCmd(), newSubstrateLogoutCmd(), newSubstrateWhoamiCmd(),
		newSubstrateRunCmd(), newSubstrateConnectCmd(), newSubstrateListCmd(), newSubstrateStatusCmd(),
		newSubstrateLogsCmd(), newSubstratePullCmd(), newSubstrateCheckpointCmd(), newSubstrateUndoCmd(),
		newSubstrateDeleteCmd(), newSubstrateMigrateCmd(),
		newSubstrateApprovalsCmd(), newSubstrateApproveCmd(), newSubstrateRejectCmd(), newSubstrateUsageCmd(),
		newSubstrateSecretsCmd(), newSubstratePolicyCmd(),
		newSubstrateDoctorCmd(), newSubstrateVerifyCmd(), newSubstrateSetupCmd(), newSubstrateBundleCmd(), newSubstrateTemplateCmd(),
	)
	rootCmd.AddCommand(substrateCmd)
}
