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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
	"github.com/defenseclaw/defenseclaw/internal/substrate/launcherpresence"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/signin"
)

// substrateAsks adapts the admin client to attach.AskSource for one person.
type substrateAsks struct{ cl *api.Client }

func (a substrateAsks) Pending(ctx context.Context, t attach.Target) ([]attach.Ask, error) {
	asks, err := a.cl.Asks(ctx)
	if err != nil {
		return nil, err
	}
	// Only an ask that names this exact agent is shown here: a bare name or
	// an empty actor could be another of the person's agents (GAP-0112).
	// The gateway lists an ask's atespace and actor name apart, so the
	// agent is atespace/name (GAP-0483: matching the bare name against
	// atespace/name showed no ask on the pane, ever).
	var out []attach.Ask
	for _, k := range asks {
		ref := substrateAskActor(k)
		if ref == "" || ref != t.Atespace+"/"+t.Name {
			continue
		}
		out = append(out, attach.Ask{ID: k.ID, Actor: ref, Tool: k.Tool, Summary: k.Summary, Reason: k.Reason, Severity: k.Severity, Created: k.Created})
	}
	return out, nil
}

// substrateAskActor is the atespace/name of the agent that raised an ask,
// or "" when the gateway named no atespace (never matched by name alone).
func substrateAskActor(k api.Ask) string {
	if k.Atespace == "" || k.Actor == "" || strings.Contains(k.Actor, "/") {
		return ""
	}
	return k.Atespace + "/" + k.Actor
}

func (a substrateAsks) Decide(ctx context.Context, id string, d attach.Decision) error {
	var err error
	switch d {
	case attach.Decision("once"):
		_, err = a.cl.Decide(ctx, id, "approve", false, "")
	case attach.Decision("always"):
		_, err = a.cl.Decide(ctx, id, "approve", true, "")
	default:
		_, err = a.cl.Decide(ctx, id, "deny", false, "")
	}
	return err
}

func substrateTransport(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return "auto", nil
	case "websocket", "ws":
		return "websocket", nil
	case "longpoll", "long-poll", "poll":
		return "longpoll", nil
	}
	return "", fmt.Errorf("--transport must be auto, websocket or longpoll, not %q", v)
}

// substrateBanner fills the banner from the actor and, when the cluster
// answers, from its policy (model, route, allow list, asks).
func substrateBanner(ctx context.Context, cl *api.Client, a api.Actor) attach.Banner {
	b := attach.Banner{Name: a.Name, Connector: a.Connector, Profile: a.Profile}
	pol, err := cl.PolicyQuery(ctx, a.Atespace+"/"+a.Name, nil)
	if err != nil {
		return b
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := pol[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	b.Model, b.Route, b.Asks = str("model"), str("route"), str("asks")
	for _, k := range []string{"allow_list", "allow"} {
		if list, ok := pol[k].([]any); ok {
			for _, v := range list {
				if sv, ok := v.(string); ok {
					b.AllowList = append(b.AllowList, sv)
				}
			}
			break
		}
	}
	return b
}

func substrateAttachOptions(cmd *cobra.Command, s *substrateSession, a api.Actor, transport string, noAsks bool, keyReplay string) (attach.Options, error) {
	tr, err := substrateTransport(transport)
	if err != nil {
		return attach.Options{}, err
	}
	replay, err := substrateKeyReplay(cmd, s, keyReplay)
	if err != nil {
		return attach.Options{}, err
	}
	o := attach.Options{
		Target:  attach.Target{Atespace: a.Atespace, Name: a.Name},
		Gateway: attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, Bearer: s.Bearer, In: os.Stdin, Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(),
		Transport: tr, NoAsks: noAsks, KeyReplay: replay,
	}
	// The agent starts in the copy of the project, so what it writes where
	// it starts comes back with pull (GAP-0163). A computer that did not
	// upload the folder has no record and keeps the relay default.
	o.Dir = workspace.RemoteDirOf(auth.StateDir(), substrateCopyName(a))
	if !noAsks {
		o.Asks = substrateAsks{s.Client}
	}
	o.Health = substrateCrashCheck(s.Client, a)
	return o, nil
}

// substrateCrashedErr says a crashed agent cannot be reached and how to get
// it back (GAP-0410): its worker went away, and waiting does not bring it
// back.
func substrateCrashedErr(a api.Actor) error {
	return fmt.Errorf("the agent %s/%s crashed (its worker went away) and is not running. "+
		"Bring it back to its last saved state with: defenseclaw substrate undo %s", a.Atespace, a.Name, a.Name)
}

// substrateCrashCheck is the attach wait's health check: a crashed agent
// ends the wait with substrateCrashedErr instead of "the cluster is full".
func substrateCrashCheck(cl *api.Client, a api.Actor) func(context.Context) error {
	return func(ctx context.Context) error {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		now, err := cl.Get(cctx, a.Atespace, a.Name)
		if err == nil && now.State == substrateStateCrashed {
			return substrateCrashedErr(a)
		}
		return nil
	}
}

// substrateStateCrashed is the state the gateway shows for a crashed actor.
const substrateStateCrashed = "crashed"

// --- connect ----------------------------------------------------------------

func runSubstrateConnect(cmd *cobra.Command, f *substrateAttachFlags, ref string) error {
	specs, err := substrateMCPSpecs(f.mcp, false, false)
	if err != nil {
		return err
	}
	s, err := substrateOpen(cmd, &f.com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	egress := substrateEgressAhead(ctx, s)
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	if a.State == substrateStateCrashed {
		return substrateFail(substrateCrashedErr(a))
	}
	o, err := substrateAttachOptions(cmd, s, a, f.transport, f.noAsks, f.keyReplay)
	if err != nil {
		return err
	}
	o.Banner = substrateBanner(ctx, s.Client, a)
	mcp, err := startSubstrateMCP(ctx, cmd, s, a, specs, true)
	if err != nil {
		return err
	}
	defer mcp.Close()
	o.Notices = mcp.Notices()
	// GAP-0505: the person learns here, not from a DNS error in the agent,
	// that another callout holds Substrate's egress slot.
	egress(cmd.ErrOrStderr())
	return substrateAttachAndReport(ctx, cmd, o, a)
}

// substratePresence records this launcher for AI discovery while it is
// attached (E26: discovery labels it the Agent Substrate launcher; process
// snapshots keep no command line). The record holds the command, the
// connector and the context name only. It returns the cleanup.
func substratePresence(cmd *cobra.Command, a api.Actor) func() {
	remove, _ := launcherpresence.Write(auth.StateDir(), substrateRecord(cmd, a))
	return remove
}

// substrateRecord is the presence record of this launcher: the command, the
// connector and the context name.
func substrateRecord(cmd *cobra.Command, a api.Actor) launcherpresence.Record {
	ctxName := ""
	if name, _, err := auth.ResolveContext(""); err == nil {
		ctxName = name
	}
	return launcherpresence.Record{Command: cmd.Name(), Connector: strings.ToLower(a.Connector), Context: strings.ToLower(ctxName)}
}

// substrateAttachAndReport attaches and says how the session ended.
func substrateAttachAndReport(ctx context.Context, cmd *cobra.Command, o attach.Options, a api.Actor) error {
	defer substratePresence(cmd, a)()
	res, err := attach.Attach(ctx, o)
	w := cmd.ErrOrStderr()
	if err != nil {
		return substrateFail(err)
	}
	switch {
	case res.Detached:
		// The attach package prints the way back.
	case res.ExitCode != nil:
		fmt.Fprintf(w, "\nThe agent finished (exit %d). Bring its changes home with: defenseclaw substrate pull %s\n", *res.ExitCode, a.Name)
	default:
		fmt.Fprintf(w, "\nThe connection ended. Come back with: defenseclaw substrate connect %s\n", a.Name)
	}
	return nil
}

// --- run --------------------------------------------------------------------

// substrateTask is one unit of unattended work.
type substrateTask struct {
	Name  string `yaml:"name"`
	Task  string `yaml:"task"`
	Agent string `yaml:"agent"`
}

// parseSubstrateBatch reads a batch file: a list of task texts, or a list
// of {name, task, agent}, either bare or under "tasks:".
func parseSubstrateBatch(data []byte) ([]substrateTask, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("the batch file is not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil, errors.New("the batch file is empty")
	}
	list := doc.Content[0]
	if list.Kind == yaml.MappingNode {
		var found *yaml.Node
		for i := 0; i+1 < len(list.Content); i += 2 {
			if list.Content[i].Value == "tasks" {
				found = list.Content[i+1]
			}
		}
		if found == nil {
			return nil, errors.New(`the batch file needs a "tasks:" list`)
		}
		list = found
	}
	if list.Kind != yaml.SequenceNode {
		return nil, errors.New("the batch file must be a list of tasks")
	}
	var out []substrateTask
	for i, n := range list.Content {
		var t substrateTask
		switch n.Kind {
		case yaml.ScalarNode:
			t.Task = n.Value
		default:
			if err := n.Decode(&t); err != nil {
				return nil, fmt.Errorf("task %d: %w", i+1, err)
			}
		}
		t.Task = strings.TrimSpace(t.Task)
		if t.Task == "" {
			return nil, fmt.Errorf("task %d has no text", i+1)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("the batch file has no tasks")
	}
	if len(out) > 500 {
		return nil, fmt.Errorf("the batch file has %d tasks; the most one batch takes is 500", len(out))
	}
	return out, nil
}

func newSubstrateID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// substrateProven lists the connectors that run on Substrate although their
// OpenShell harness is unverified (GAP-0184): that status is about an
// OpenShell V2 sandbox, not an actor. The value is a note the launcher prints
// when the agent starts ("" for none). This is the only list; the cluster
// decides the rest for every connector.
//
//   - opencode: its plugin posts through the actor kit's hook-post, live on a
//     Bedrock model (lane A10, TST-0125, TST-0184).
//   - cursor, devin, amp: vendor sign-in connectors (PLAN E9, lane A11, J41
//     TST-0286 to TST-0299). The gateway decides at create with
//     signin.Evaluate: open source answers a create 428
//     signin_ack_required with the warning that the sign-in token sits in
//     the actor and its snapshots, before any actor exists; run shows it,
//     asks for a yes (or takes --yes) and creates again with the
//     acknowledgement, which the gateway audits (GAP-0482). A managed
//     deployment refuses it with subscription_signin_refused before any
//     actor exists. Kiro and
//     Antigravity are verified harnesses with no entry here; the same rule
//     applies to them.
var substrateProven = map[string]string{
	"opencode": "",
	"cursor":   "",
	"devin":    "",
	"amp":      "Amp reaches its service over WebSocket connections that the cluster's network guard does not pass through yet, so it may not reach its model.",
}

// substrateRunTarget is what one run needs, resolved from flags and context.
type substrateRunTarget struct {
	spec     *harness.Spec
	connName string
	profile  string
	template string
	// loginTemplate marks a template taken from the login's default
	// (GAP-0469); agentTemplate is the named agent's own template, used when
	// the cluster says the login default is another agent's.
	loginTemplate bool
	agentTemplate string
	// loginProfile marks a profile taken from the login's default
	// (GAP-0527): when the cluster says it is not the person's, the run
	// lets the cluster pick the person's own instead.
	loginProfile bool
	// note is the substrateProven note, printed when the agent starts.
	note string
}

func resolveSubstrateRunTarget(s *substrateSession, f *substrateRunFlags, agent string) (substrateRunTarget, error) {
	spec, err := sandboxcli.ResolveHarness(agent)
	if err != nil {
		return substrateRunTarget{}, cliusage.WithExitCode(err, 2)
	}
	note, proven := substrateProven[spec.Name]
	if spec.Verification().Status == harness.Unverified && !proven {
		return substrateRunTarget{}, cliusage.WithExitCode(fmt.Errorf("%s is not verified yet, so it does not run (%s)", spec.DisplayName, spec.Verification().Note), substrateExitRefused)
	}
	t := substrateRunTarget{spec: spec, connName: spec.Name, note: note}
	// No profile named: the cluster gives the person the profile their
	// groups map to (GAP-0166); --profile is only for someone with several.
	t.profile = substrateFirst(f.profile, os.Getenv("DEFENSECLAW_SUBSTRATE_PROFILE"), s.Ctx.Profile)
	t.loginProfile = substrateFirst(f.profile, os.Getenv("DEFENSECLAW_SUBSTRATE_PROFILE")) == "" && strings.TrimSpace(s.Ctx.Profile) != ""
	t.agentTemplate = sandboxcli.HarnessArg(spec)
	t.template = substrateFirst(f.template, os.Getenv("DEFENSECLAW_SUBSTRATE_TEMPLATE"), s.Ctx.Template, t.agentTemplate)
	t.loginTemplate = substrateFirst(f.template, os.Getenv("DEFENSECLAW_SUBSTRATE_TEMPLATE")) == "" && strings.TrimSpace(s.Ctx.Template) != ""
	return t, nil
}

// substrateNoWorkerError is a create the pool had no worker for.
type substrateNoWorkerError struct{ msg string }

func (e substrateNoWorkerError) Error() string { return e.msg }

// A batch task waits up to substrateBatchWorkerWait for a free worker,
// trying again every substrateBatchWorkerPoll.
const (
	substrateBatchWorkerWait = 15 * time.Minute
	substrateBatchWorkerPoll = 15 * time.Second
)

// substrateWaitForWorker runs try again while it finds no free worker, for
// up to wait; note is called once, at the first wait. The last result is
// returned, so a pool that stays full still says so.
func substrateWaitForWorker(ctx context.Context, wait, poll time.Duration, try func() (int, error), note func()) (int, error) {
	deadline := time.Now().Add(wait)
	noted := false
	for {
		code, err := try()
		var full substrateNoWorkerError
		if !errors.As(err, &full) || time.Now().Add(poll).After(deadline) {
			return code, err
		}
		if !noted && note != nil {
			note()
			noted = true
		}
		select {
		case <-ctx.Done():
			return code, err
		case <-time.After(poll):
		}
	}
}

// A run (and a single --task run) on a full pool waits for room as connect
// does (GAP-0528): up to substrateRunWorkerWait, trying again every
// substrateRunWorkerPoll, with connect's message; Ctrl-C stops it, and
// nothing is left behind. Tests shorten them.
var (
	substrateRunWorkerWait = 10 * time.Minute
	substrateRunWorkerPoll = 5 * time.Second
)

// substrateRunWaitingForWorker is substrateWaitForWorker for one run: it
// prints connect's "The cluster is full. Waiting for room (Ctrl-C to
// stop)..." once, at the first wait. A pool still full at the end returns
// the no-worker error, which names the person's own agents.
func substrateRunWaitingForWorker(ctx context.Context, cmd *cobra.Command, try func() (int, error)) (int, error) {
	return substrateWaitForWorker(ctx, substrateRunWorkerWait, substrateRunWorkerPoll, try, func() {
		fmt.Fprintln(cmd.ErrOrStderr(), attach.ClusterFullMessage)
	})
}

// substrateNoWorkerMessage says the pool is full (GAP-0167), how many of the
// person's own agents hold a worker, and how to free one.
func substrateNoWorkerMessage(ctx context.Context, s *substrateSession) string {
	msg := "the cluster has no free worker for a new agent right now; nothing was started."
	actors, err := s.Client.List(ctx, api.ListOptions{})
	if err != nil {
		return msg + " " + substrateNoWorkerNext
	}
	var running []string
	for _, a := range actors {
		if !a.Deleted && (a.State == "running" || a.State == "resuming") {
			running = append(running, a.Name)
		}
	}
	switch len(running) {
	case 0:
		return msg + " None of your agents are running, so the pool is busy with other work; try again later or ask your administrator for more workers."
	case 1:
		return msg + " 1 of your agents is running (" + running[0] + "). " + substrateNoWorkerNext
	}
	shown := running
	if len(shown) > 3 {
		shown = shown[:3]
	}
	return msg + fmt.Sprintf(" %d of your agents are running (%s). ", len(running), strings.Join(shown, ", ")) + substrateNoWorkerNext
}

const substrateNoWorkerNext = "Free a worker with: defenseclaw substrate delete NAME (see them all with defenseclaw substrate list), or ask your administrator for more workers."

func substrateFirst(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// substrateCreate makes the actor, uploads the folder and returns a tunnel
// to it. When anything after the create fails the half-made actor is
// deleted, so a failed run leaves nothing behind.
func substrateCreate(ctx context.Context, cmd *cobra.Command, s *substrateSession, t substrateRunTarget, f *substrateRunFlags, req api.CreateRequest, project string) (a api.Actor, err error) {
	w := cmd.ErrOrStderr()
	req.Profile, req.Template, req.Connector = t.profile, t.template, t.connName
	// Substrate's egress caches an actor's identity token by name, so a new
	// actor that reuses a name is refused until the old token expires
	// (GAP-0133). Every actor gets a name nobody had before.
	req.Name = uniqueSubstrateActorName(req.Name, t.spec.Command)
	req.Secrets = f.secrets
	var prepared *workspace.PreparedUpload
	if project != "" {
		prepared, err = substratePreflight(ctx, cmd, s, f, project)
		if err != nil {
			return a, err
		}
		defer prepared.Close()
	}
	// GAP-0505: read during the create, printed after "Started". A batch
	// prints it once for all of its tasks (runSubstrateBatch).
	egress := func(io.Writer) {}
	if req.BatchID == "" {
		egress = substrateEgressAhead(ctx, s)
	}
	a, err = s.Client.Create(ctx, req)
	// GAP-0527: the profile login saved (--default-profile) is a preference,
	// not the person's assignment. Refused (a contractor whose login saved
	// eng), the run asks again with no profile, so the cluster gives the
	// person the profile their groups map to, as policy show reports it. A
	// profile the person named (--profile or the environment) is not
	// replaced.
	if e, ok := api.AsError(err); ok && e.Status == http.StatusForbidden && e.Reason == "profile_not_allowed" && t.loginProfile && req.Profile != "" {
		fmt.Fprintf(w, "The default profile %s from login is not one you may use; using the profile the cluster gives you.\n", req.Profile)
		req.Profile = ""
		a, err = s.Client.Create(ctx, req)
	}
	// GAP-0469: the template login saved is the default for its own agent.
	// Named another agent (run codex after a claude login), the cluster
	// answers connector_mismatch: run that agent's own template instead.
	if e, ok := api.AsError(err); ok && e.Status == 400 && e.Reason == "connector_mismatch" {
		if t.loginTemplate && t.agentTemplate != "" && t.agentTemplate != req.Template {
			fmt.Fprintf(w, "The default template %s from login is not a %s template; using %s.\n", req.Template, t.spec.DisplayName, t.agentTemplate)
			req.Template = t.agentTemplate
			a, err = s.Client.Create(ctx, req)
		}
		if e, ok := api.AsError(err); ok && e.Status == 400 && e.Reason == "connector_mismatch" {
			return a, cliusage.WithExitCode(fmt.Errorf("template %s is not a %s template; name one with --template TEMPLATE, for example --template %s", req.Template, t.spec.DisplayName, t.agentTemplate), 2)
		}
	}
	// GAP-0482: an open-source cluster warns about a vendor sign-in before
	// it creates anything; the person's yes (or --yes) sends the create
	// again, and the cluster audits it.
	acked := ""
	if e, ok := api.AsError(err); ok && e.Status == http.StatusPreconditionRequired && e.Reason == signin.AckRequiredCode {
		acked = substrateFirst(e.Message, "the cluster warns about this agent's vendor sign-in.")
		if err = substrateAckSignin(cmd, t, f, req, acked); err != nil {
			return a, err
		}
		req.AcknowledgeSignin = true
		a, err = s.Client.Create(ctx, req)
	}
	if err != nil {
		if e, ok := api.AsError(err); ok && e.Status == 503 && e.Reason == "no_free_worker" {
			return a, cliusage.WithExitCode(substrateNoWorkerError{substrateNoWorkerMessage(ctx, s)}, substrateAPIExit(e))
		}
		if e, ok := api.AsError(err); ok && e.Status == http.StatusForbidden && e.Reason == "profile_not_allowed" && req.Profile == "" {
			// No profile was sent, so "leave --profile out" is no fix: the
			// cluster has no profile that runs agents for this person.
			return a, cliusage.WithExitCode(errors.New("no profile that runs agents is assigned to you on this cluster; nothing was started. See yours with: defenseclaw substrate policy show, and ask your administrator to assign you one"), substrateAPIExit(e))
		}
		return a, substrateFail(err)
	}
	fmt.Fprintf(w, "Started %s/%s (%s, profile %s).\n", a.Atespace, a.Name, t.spec.DisplayName, substrateDash(substrateFirst(a.Profile, req.Profile)))
	// E9: in open source the cluster says what a vendor sign-in costs; the
	// warning the person just acknowledged is not printed twice.
	for _, warn := range a.Warnings {
		if warn != acked {
			fmt.Fprintf(w, "Warning: %s\n", warn)
		}
	}
	if t.note != "" {
		fmt.Fprintf(w, "Note: %s\n", t.note)
	}
	egress(w)
	defer func() {
		if err != nil {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if _, derr := s.Client.Delete(cctx, a.Atespace, a.Name); derr == nil {
				fmt.Fprintf(w, "Removed the half-made agent %s/%s.\n", a.Atespace, a.Name)
			} else {
				fmt.Fprintf(w, "Could not remove %s/%s (%v); delete it with: defenseclaw substrate delete %s\n", a.Atespace, a.Name, substrateFail(derr), a.Name)
			}
		}
	}()
	substrateGitRewriteAtStart(ctx, cmd, s, a, f)
	if prepared != nil {
		if err = substrateUploadFolder(ctx, cmd, s, a, prepared); err != nil {
			return a, err
		}
	}
	if f.clone != "" {
		if err = substrateCloneInActor(ctx, cmd, s, a, f); err != nil {
			return a, err
		}
	}
	// Before the agent starts (attach or the task does that): the registry
	// placeholders of the bindings in its policy (B1 2.6, S7).
	substrateRegistryFiles(ctx, cmd, s, a)
	return a, nil
}

// substrateAckSignin shows the cluster's sign-in warning and takes the
// person's yes before anything is created or uploaded (GAP-0482). --yes
// answers it; a batch, or a run with no terminal, needs --yes. No is a run
// that started nothing.
func substrateAckSignin(cmd *cobra.Command, t substrateRunTarget, f *substrateRunFlags, req api.CreateRequest, warning string) error {
	w := cmd.ErrOrStderr()
	switch {
	case f.yes:
		fmt.Fprintf(w, "Warning: %s\nAcknowledged with --yes.\n", warning)
		return nil
	case req.BatchID != "":
		return cliusage.WithExitCode(fmt.Errorf("%s signs in to a vendor account, and the cluster asks for a yes first; nothing was started. Run the batch again with --yes to acknowledge it", t.spec.DisplayName), 2)
	case !substrateInteractive():
		return cliusage.WithExitCode(fmt.Errorf("%s Nothing was started: run it again with --yes to acknowledge this warning", warning), 2)
	}
	fmt.Fprintf(w, "Warning: %s\n", warning)
	ok, err := substrateConfirm(cmd, "Start "+t.spec.DisplayName+" anyway?")
	if err != nil {
		return cliusage.WithExitCode(err, 2)
	}
	if !ok {
		return cliusage.WithExitCode(errors.New("not started: the warning was not acknowledged, so nothing was created or uploaded"), 1)
	}
	return nil
}

// substrateCloneInActor clones --clone into the actor through the relay
// (GAP-0175): the clone goes out through the actor's egress rules, which add
// the credential for a host the profile allows; nothing of this computer's
// credentials is sent. The agent then starts in the clone.
func substrateCloneInActor(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, f *substrateRunFlags) error {
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	fmt.Fprintf(cmd.ErrOrStderr(), "Cloning %s in the agent...\n", safetext.Line(f.clone))
	g := substrateGitSettings(ctx, s, f)
	res, err := substrateCloneOnce(ctx, cmd, s.Client, a, f, func() (*workspace.CloneResult, error) {
		return workspace.Clone(ctx, rel.Client, auth.StateDir(), substrateCopyName(a), f.clone, f.ref,
			workspace.CloneOptions{Submodules: g.Submodules, LFS: g.LFS})
	})
	if err != nil {
		return cliusage.WithExitCode(err, 1)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Cloned into %s.\n", safetext.Line(res.Dir))
	for _, warn := range res.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s.\n", safetext.Line(warn))
	}
	if res.Note != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: %s.\n", safetext.Line(res.Note))
	}
	return nil
}

func runSubstrateRun(cmd *cobra.Command, f *substrateRunFlags, args []string) error {
	asJSON, err := f.out.wantJSON()
	if err != nil {
		return err
	}
	switch {
	case f.task != "" && f.batch != "":
		return cliusage.WithExitCode(errors.New("use --task for one task or --batch for a file of tasks, not both"), 2)
	case f.detach && f.task == "" && f.batch == "":
		return cliusage.WithExitCode(errors.New("--detach needs --task or --batch; to leave a running session press Ctrl-] instead"), 2)
	case f.parallel != 0 && f.batch == "":
		return cliusage.WithExitCode(errors.New("--parallel goes with --batch"), 2)
	case f.clone != "" && f.noUpload:
		return cliusage.WithExitCode(errors.New("--clone and --no-upload both say what the agent starts with; use one"), 2)
	case f.clone != "" && !substrateCloneHere(f.clone) && workspace.CheckCloneURL(f.clone) != nil:
		return cliusage.WithExitCode(workspace.CheckCloneURL(f.clone), 2)
	case f.ref != "" && f.clone != "" && substrateCloneHere(f.clone):
		return cliusage.WithExitCode(errors.New("--ref goes with --clone URL; --clone . starts at this checkout's HEAD"), 2)
	case workspace.CheckCloneRef(f.ref) != nil:
		return cliusage.WithExitCode(workspace.CheckCloneRef(f.ref), 2)
	case f.ref != "" && f.clone == "":
		return cliusage.WithExitCode(errors.New("--ref goes with --clone URL"), 2)
	}
	if _, err := substrateTransport(f.transport); err != nil {
		return cliusage.WithExitCode(err, 2)
	}
	if f.mcpSpecs, err = substrateMCPSpecs(f.mcp, f.detach, f.batch != ""); err != nil {
		return err
	}
	s, err := substrateOpen(cmd, &f.com)
	if err != nil {
		return err
	}
	t, err := resolveSubstrateRunTarget(s, f, args[0])
	if err != nil {
		return err
	}
	var agentArgs []string
	if dash := cmd.ArgsLenAtDash(); dash >= 0 {
		agentArgs = args[dash:]
	}
	project := ""
	if f.clone != "" && substrateCloneHere(f.clone) {
		if project, err = substratePrepareCloneHere(cmd, s, f); err != nil {
			return err
		}
	}
	if f.clone == "" && !f.noUpload && project == "" {
		project, err = os.Getwd()
		if err != nil {
			return err
		}
		if err := substrateCheckProject(project); err != nil {
			return err
		}
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	switch {
	case f.batch != "":
		return runSubstrateBatch(ctx, cmd, s, t, f, project, agentArgs, asJSON)
	case f.task != "":
		_, err := substrateRunWaitingForWorker(ctx, cmd, func() (int, error) {
			return runSubstrateOneTask(ctx, cmd, s, t, f, project, f.task, "", f.name, agentArgs, asJSON)
		})
		return err
	}
	var a api.Actor
	_, err = substrateRunWaitingForWorker(ctx, cmd, func() (int, error) {
		var cerr error
		a, cerr = substrateCreate(ctx, cmd, s, t, f, api.CreateRequest{Name: f.name}, project)
		return 0, cerr
	})
	if err != nil {
		return err
	}
	o, err := substrateAttachOptions(cmd, s, a, f.transport, f.noAsks, f.keyReplay)
	if err != nil {
		return err
	}
	o.Banner = substrateBanner(ctx, s.Client, a)
	mcp, err := startSubstrateMCP(ctx, cmd, s, a, f.mcpSpecs, true)
	if err != nil {
		return err
	}
	defer mcp.Close()
	o.Notices = mcp.Notices()
	return substrateAttachAndReport(ctx, cmd, o, a)
}

// substrateCheckProject refuses a folder that is clearly not a project.
func substrateCheckProject(dir string) error {
	home, _ := os.UserHomeDir()
	clean := filepath.Clean(dir)
	if clean == filepath.VolumeName(clean)+string(filepath.Separator) || (home != "" && clean == filepath.Clean(home)) {
		return cliusage.WithExitCode(fmt.Errorf("%s is not a project folder (it is your home or the top of a disk); change to a project folder, or use --clone URL or --no-upload", dir), 2)
	}
	return nil
}

// runSubstrateOneTask runs one headless task: create, upload, post the task
// to the relay and follow it. It returns the agent and the task's exit code
// (-1 when the run was detached).
func runSubstrateOneTask(ctx context.Context, cmd *cobra.Command, s *substrateSession, t substrateRunTarget, f *substrateRunFlags, project, task, batchID, name string, agentArgs []string, asJSON bool) (code int, err error) {
	var a api.Actor
	a, err = substrateCreate(ctx, cmd, s, t, f, api.CreateRequest{Name: name, Task: task, BatchID: batchID, Unattended: true}, project)
	if err != nil {
		return -1, err
	}
	o, err := substrateAttachOptions(cmd, s, a, f.transport, true, attach.KeyReplayOff)
	if err != nil {
		return -1, err
	}
	mcp, err := startSubstrateMCP(ctx, cmd, s, a, f.mcpSpecs, false)
	if err != nil {
		return -1, err
	}
	defer mcp.Close()
	w := cmd.OutOrStdout()
	// GAP-0420: what undo needs to start the task again after a crash.
	rec := substrateTaskRecord{Prompt: task, Clone: f.clone, Ref: f.ref, RemoteDir: f.remoteDir, Exclude: f.exclude,
		Unmask: f.unmask, MaxUploadMB: f.maxUploadMB, Transport: f.transport, Started: time.Now().UTC()}
	if project != "" {
		if abs, aerr := filepath.Abs(project); aerr == nil {
			rec.Project = abs
		}
	}
	if serr := saveSubstrateTaskRecord(auth.StateDir(), a, rec); serr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: could not keep a record of the task on this computer (%v); after a crash it cannot be started again from here.\n", serr)
	}
	if f.detach {
		// The first event is the task's start; once it is seen the task
		// runs on its own.
		if serr := substrateStartDetached(ctx, o, task, agentArgs); serr != nil {
			return -1, substrateFail(serr)
		}
		if asJSON {
			return -1, writeSubstrateJSON(w, map[string]any{"atespace": a.Atespace, "name": a.Name, "batch_id": batchID, "state": "started"})
		}
		fmt.Fprintf(w, "Started the task in %s/%s. Follow it with: defenseclaw substrate logs -f %s\n", a.Atespace, a.Name, a.Name)
		return -1, nil
	}
	tctx := ctx
	if f.timeout > 0 {
		var cancel context.CancelFunc
		tctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}
	emit := attach.TextEmitter(w, cmd.ErrOrStderr())
	if asJSON {
		emit = func(e relay.TaskEvent) { _ = writeSubstrateJSONLine(w, e) }
	}
	started := time.Now()
	code, err = attach.RunTask(tctx, attach.TaskOptions{Options: o, Prompt: task, Args: agentArgs, Emit: emit})
	if err != nil {
		return -1, substrateFail(err)
	}
	info := substrateTaskEndInfo(ctx, s)
	// GAP-0505: a task whose other hosts were refused because another
	// callout holds Substrate's egress slot says so where it ends.
	if info != nil {
		if line := substrateEgressLine(info.EgressCallout); line != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), line)
		}
	}
	// A task whose hook and model calls the gateway refused may still end
	// with exit 0; it did not finish (GAP-0194).
	if msg, refused := substrateTokenRefusal(info, started); refused {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s\nReview it with: defenseclaw substrate logs %s\n", msg, a.Name)
		return 1, cliusage.WithExitCode(errors.New("the task did not run: the cluster refused its calls"), 1)
	}
	if code != 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "The task ended with exit code %d. Review it with: defenseclaw substrate logs %s; bring changes home with: defenseclaw substrate pull %s\n", code, a.Name, a.Name)
		return code, cliusage.WithExitCode(fmt.Errorf("the task failed (exit %d)", code), 1)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "The task finished. Bring changes home with: defenseclaw substrate pull %s\n", a.Name)
	return code, substrateMCPNone(mcp, f.mcpSpecs)
}

// substrateTaskEndInfo is the one /info read made when a task ends (the
// token refusal and the egress callout), nil when it failed.
func substrateTaskEndInfo(ctx context.Context, s *substrateSession) *api.Info {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	info, err := s.Client.Info(cctx)
	if err != nil {
		return nil
	}
	return &info
}

// substrateTokenRefusal says whether the cluster (its /info, nil when the
// read failed) refused every agent's token since start, in words a person
// can act on.
func substrateTokenRefusal(info *api.Info, start time.Time) (string, bool) {
	if info == nil || !info.ActorTokens.Refusing(start) {
		return "", false
	}
	why := "the agent's identity could not be checked"
	switch info.ActorTokens.Reason {
	case "keyset_unavailable":
		why = "the cluster gateway cannot read the keys that sign agent tokens"
	case "issuer":
		why = "the agent's token names another issuer than the cluster gateway trusts"
	case "verifier_unavailable":
		why = "the cluster gateway cannot reach the Substrate control API"
	}
	return fmt.Sprintf("The task did not run: the cluster gateway refused its tool and model calls (%s: %s). "+
		"Ask your administrator to run: defenseclaw substrate verify", info.ActorTokens.Reason, why), true
}

func substrateFirstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func writeSubstrateJSONLine(w io.Writer, v any) error {
	return writeSubstrateJSONCompact(w, v)
}

// runSubstrateBatch runs a file of tasks, one agent each, at most
// --parallel at a time, and prints one line per task at the end.
func runSubstrateBatch(ctx context.Context, cmd *cobra.Command, s *substrateSession, t substrateRunTarget, f *substrateRunFlags, project string, agentArgs []string, asJSON bool) error {
	data, err := os.ReadFile(f.batch)
	if err != nil {
		return cliusage.WithExitCode(fmt.Errorf("cannot read the batch file: %w", err), 2)
	}
	tasks, err := parseSubstrateBatch(data)
	if err != nil {
		return cliusage.WithExitCode(err, 2)
	}
	par := f.parallel
	if par <= 0 {
		par = 4
	}
	if par > 50 {
		par = 50
	}
	batchID := "b-" + newSubstrateID(4)
	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "Batch %s: %d task(s), %d at a time.\n", batchID, len(tasks), par)
	// GAP-0505: the tasks' own output is not shown, so the batch says once
	// at its start and once at its end that another callout holds
	// Substrate's egress slot.
	substrateEgressAhead(ctx, s)(w)
	type result struct {
		Task   string `json:"task"`
		Name   string `json:"name,omitempty"`
		Status string `json:"status"`
		Code   int    `json:"exit_code"`
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, len(tasks))
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	// One run's output stays on its own lines: the batch prints a summary,
	// not interleaved agent output.
	quiet := *f
	quiet.out = substrateOutput{}
	for i, task := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			tt := t
			if task.Agent != "" {
				if rt, err := resolveSubstrateRunTarget(s, f, task.Agent); err == nil {
					tt = rt
				}
			}
			name := task.Name
			if name == "" && f.name != "" {
				name = fmt.Sprintf("%s-%d", f.name, i+1)
			}
			sub := &cobra.Command{}
			sub.SetOut(io.Discard)
			sub.SetErr(io.Discard)
			sub.SetContext(ctx)
			// A full pool is waited out: a finished task frees its worker
			// about a minute after it ends (GAP-0274), so a batch larger
			// than the pool drains through it.
			code, err := substrateWaitForWorker(ctx, substrateBatchWorkerWait, substrateBatchWorkerPoll, func() (int, error) {
				return runSubstrateOneTask(ctx, sub, s, tt, &quiet, project, task.Task, batchID, name, agentArgs, false)
			}, func() {
				fmt.Fprintf(w, "Task %d waits for a free worker (a finished task frees its worker about a minute after it ends).\n", i+1)
			})
			r := result{Task: task.Task, Code: code, Status: "finished"}
			switch {
			case err != nil && code < 0:
				r.Status, r.Error = "failed to start", err.Error()
			case err != nil:
				r.Status = "failed"
			case code < 0:
				r.Status = "started"
			}
			results[i] = r
		}()
	}
	wg.Wait()
	substrateEgressAhead(ctx, s)(w)
	out := cmd.OutOrStdout()
	failed := 0
	for _, r := range results {
		if r.Status != "finished" && r.Status != "started" {
			failed++
		}
	}
	if asJSON {
		if err := writeSubstrateJSON(out, map[string]any{"batch_id": batchID, "results": results}); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, len(results))
		for i, r := range results {
			rows = append(rows, []string{fmt.Sprintf("%d", i+1), substrateClip(r.Task, 40), r.Status, fmt.Sprintf("%d", r.Code), r.Error})
		}
		substrateTable(out, []string{"#", "TASK", "STATUS", "EXIT", "NOTE"}, rows)
		fmt.Fprintf(out, "\nSee them with: defenseclaw substrate status --batch %s\nBring the changes home with: defenseclaw substrate pull NAME (list the names with: defenseclaw substrate list --batch %s)\n", batchID, batchID)
	}
	if failed > 0 {
		return cliusage.WithExitCode(fmt.Errorf("%d of %d task(s) did not finish well", failed, len(results)), 1)
	}
	return nil
}

func substrateClip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func writeSubstrateJSONCompact(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", safetext.JSON(b))
	return err
}

// uniqueSubstrateActorName returns label (or the agent's command when the
// person gave none) with a random suffix. The launcher never reuses a name:
// the label is only the readable part, and the full name is what list, connect
// and delete show. The result is a DNS label of at most 63 characters.
func uniqueSubstrateActorName(label, agent string) string {
	clean := func(s string) string {
		var b strings.Builder
		dash := false
		for _, r := range strings.ToLower(s) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
				dash = false
			case !dash && b.Len() > 0:
				b.WriteByte('-')
				dash = true
			}
		}
		return strings.Trim(b.String(), "-")
	}
	base := clean(label)
	if base == "" {
		base = clean(agent)
	}
	if base == "" {
		base = "agent"
	}
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	return base + "-" + newSubstrateID(4)
}

// substrateKeyReplay is what happens to keys typed while the terminal link
// is down (B3.1): the tighter of the cluster's substrate.launcher.key_replay
// and the --key-replay flag, which can only tighten it. A gateway that does
// not report it (older than this launcher) leaves the default, ask.
func substrateKeyReplay(cmd *cobra.Command, s *substrateSession, flag string) (string, error) {
	if flag != "" && !attach.ValidKeyReplay(flag) {
		return "", cliusage.WithExitCode(fmt.Errorf("--key-replay %q: use ask, on or off", flag), 2)
	}
	if flag == attach.KeyReplayOff || s == nil || s.Client == nil {
		return attach.TightestKeyReplay("", flag), nil
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	settings, err := s.Client.Launcher(ctx)
	if err != nil {
		return attach.TightestKeyReplay("", flag), nil
	}
	return attach.TightestKeyReplay(settings.KeyReplay, flag), nil
}
