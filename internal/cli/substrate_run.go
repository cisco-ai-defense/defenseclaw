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
	"io"
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
	var out []attach.Ask
	for _, k := range asks {
		if k.Actor != t.Atespace+"/"+t.Name {
			continue
		}
		out = append(out, attach.Ask{ID: k.ID, Actor: k.Actor, Tool: k.Tool, Summary: k.Summary, Reason: k.Reason, Severity: k.Severity, Created: k.Created})
	}
	return out, nil
}

func (a substrateAsks) Decide(ctx context.Context, id string, d attach.Decision) error {
	switch d {
	case attach.Decision("once"):
		return a.cl.Decide(ctx, id, "approve", false, "")
	case attach.Decision("always"):
		return a.cl.Decide(ctx, id, "approve", true, "")
	}
	return a.cl.Decide(ctx, id, "deny", false, "")
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

func substrateAttachOptions(cmd *cobra.Command, s *substrateSession, a api.Actor, transport string, noAsks bool) (attach.Options, error) {
	tr, err := substrateTransport(transport)
	if err != nil {
		return attach.Options{}, err
	}
	o := attach.Options{
		Target:  attach.Target{Atespace: a.Atespace, Name: a.Name},
		Gateway: attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, Bearer: s.Bearer, In: os.Stdin, Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(),
		Transport: tr, NoAsks: noAsks,
	}
	// The agent starts in the copy of the project, so what it writes where
	// it starts comes back with pull (GAP-0163). A computer that did not
	// upload the folder has no record and keeps the relay default.
	o.Dir = workspace.RemoteDirOf(auth.StateDir(), substrateCopyName(a))
	if !noAsks {
		o.Asks = substrateAsks{s.Client}
	}
	return o, nil
}

// --- connect ----------------------------------------------------------------

func runSubstrateConnect(cmd *cobra.Command, f *substrateAttachFlags, ref string) error {
	s, err := substrateOpen(cmd, &f.com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	o, err := substrateAttachOptions(cmd, s, a, f.transport, f.noAsks)
	if err != nil {
		return err
	}
	o.Banner = substrateBanner(ctx, s.Client, a)
	return substrateAttachAndReport(ctx, cmd, o, a)
}

// substratePresence records this launcher for AI discovery while it is
// attached (E26: discovery labels it the Agent Substrate launcher; process
// snapshots keep no command line). The record holds the command, the
// connector and the context name only. It returns the cleanup.
func substratePresence(cmd *cobra.Command, a api.Actor) func() {
	ctxName := ""
	if name, _, err := auth.ResolveContext(""); err == nil {
		ctxName = name
	}
	remove, _ := launcherpresence.Write(auth.StateDir(), launcherpresence.Record{
		Command: cmd.Name(), Connector: strings.ToLower(a.Connector), Context: strings.ToLower(ctxName),
	})
	return remove
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

// substrateRunTarget is what one run needs, resolved from flags and context.
type substrateRunTarget struct {
	spec     *harness.Spec
	connName string
	profile  string
	template string
}

func resolveSubstrateRunTarget(s *substrateSession, f *substrateRunFlags, agent string) (substrateRunTarget, error) {
	spec, err := sandboxcli.ResolveHarness(agent)
	if err != nil {
		return substrateRunTarget{}, withExitCode(err, 2)
	}
	if spec.Verification().Status == harness.Unverified {
		return substrateRunTarget{}, withExitCode(fmt.Errorf("%s is not verified yet, so it does not run (%s)", spec.DisplayName, spec.Verification().Note), substrateExitRefused)
	}
	t := substrateRunTarget{spec: spec, connName: spec.Name}
	// No profile named: the cluster gives the person the profile their
	// groups map to (GAP-0166); --profile is only for someone with several.
	t.profile = substrateFirst(f.profile, os.Getenv("DEFENSECLAW_SUBSTRATE_PROFILE"), s.Ctx.Profile)
	t.template = substrateFirst(f.template, os.Getenv("DEFENSECLAW_SUBSTRATE_TEMPLATE"), s.Ctx.Template, sandboxcli.HarnessArg(spec))
	return t, nil
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
	a, err = s.Client.Create(ctx, req)
	if err != nil {
		if e, ok := api.AsError(err); ok && e.Status == 503 && e.Reason == "no_free_worker" {
			return a, withExitCode(errors.New(substrateNoWorkerMessage(ctx, s)), substrateAPIExit(e))
		}
		return a, substrateFail(err)
	}
	fmt.Fprintf(w, "Started %s/%s (%s, profile %s).\n", a.Atespace, a.Name, t.spec.DisplayName, substrateDash(substrateFirst(a.Profile, t.profile)))
	defer func() {
		if err != nil {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if derr := s.Client.Delete(cctx, a.Atespace, a.Name); derr == nil {
				fmt.Fprintf(w, "Removed the half-made agent %s/%s.\n", a.Atespace, a.Name)
			} else {
				fmt.Fprintf(w, "Could not remove %s/%s (%v); delete it with: defenseclaw substrate delete %s\n", a.Atespace, a.Name, substrateFail(derr), a.Name)
			}
		}
	}()
	if project != "" {
		if err = substrateUploadFolder(ctx, cmd, s, a, f, project); err != nil {
			return a, err
		}
	}
	if f.clone != "" {
		if err = substrateCloneInActor(ctx, cmd, s, a, f); err != nil {
			return a, err
		}
	}
	return a, nil
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
	res, err := workspace.Clone(ctx, rel.Client, auth.StateDir(), substrateCopyName(a), f.clone, f.ref)
	if err != nil {
		return withExitCode(err, 1)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Cloned into %s.\n", safetext.Line(res.Dir))
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
		return withExitCode(errors.New("use --task for one task or --batch for a file of tasks, not both"), 2)
	case f.detach && f.task == "" && f.batch == "":
		return withExitCode(errors.New("--detach needs --task or --batch; to leave a running session press Ctrl-] instead"), 2)
	case f.parallel != 0 && f.batch == "":
		return withExitCode(errors.New("--parallel goes with --batch"), 2)
	case f.clone != "" && f.noUpload:
		return withExitCode(errors.New("--clone and --no-upload both say what the agent starts with; use one"), 2)
	case f.clone != "" && workspace.CheckCloneURL(f.clone) != nil:
		return withExitCode(workspace.CheckCloneURL(f.clone), 2)
	case workspace.CheckCloneRef(f.ref) != nil:
		return withExitCode(workspace.CheckCloneRef(f.ref), 2)
	case f.ref != "" && f.clone == "":
		return withExitCode(errors.New("--ref goes with --clone URL"), 2)
	}
	if _, err := substrateTransport(f.transport); err != nil {
		return withExitCode(err, 2)
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
	if f.clone == "" && !f.noUpload {
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
		_, err := runSubstrateOneTask(ctx, cmd, s, t, f, project, f.task, "", f.name, agentArgs, asJSON)
		return err
	}
	a, err := substrateCreate(ctx, cmd, s, t, f, api.CreateRequest{Name: f.name}, project)
	if err != nil {
		return err
	}
	o, err := substrateAttachOptions(cmd, s, a, f.transport, f.noAsks)
	if err != nil {
		return err
	}
	o.Banner = substrateBanner(ctx, s.Client, a)
	return substrateAttachAndReport(ctx, cmd, o, a)
}

// substrateCheckProject refuses a folder that is clearly not a project.
func substrateCheckProject(dir string) error {
	home, _ := os.UserHomeDir()
	clean := filepath.Clean(dir)
	if clean == filepath.VolumeName(clean)+string(filepath.Separator) || (home != "" && clean == filepath.Clean(home)) {
		return withExitCode(fmt.Errorf("%s is not a project folder (it is your home or the top of a disk); change to a project folder, or use --clone URL or --no-upload", dir), 2)
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
	o, err := substrateAttachOptions(cmd, s, a, f.transport, true)
	if err != nil {
		return -1, err
	}
	w := cmd.OutOrStdout()
	if f.detach {
		// The first event is the task's start; once it is seen the task
		// runs on its own.
		dctx, cancel := context.WithCancel(ctx)
		started := false
		_, rerr := attach.RunTask(dctx, attach.TaskOptions{Options: o, Prompt: task, Args: agentArgs, Emit: func(e relay.TaskEvent) {
			if e.Type == "start" {
				started = true
				cancel()
			}
		}})
		cancel()
		if !started {
			return -1, substrateFail(substrateFirstErr(rerr, errors.New("the task did not start")))
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
	code, err = attach.RunTask(tctx, attach.TaskOptions{Options: o, Prompt: task, Args: agentArgs, Emit: emit})
	if err != nil {
		return -1, substrateFail(err)
	}
	if code != 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "The task ended with exit code %d. Review it with: defenseclaw substrate logs %s; bring changes home with: defenseclaw substrate pull %s\n", code, a.Name, a.Name)
		return code, withExitCode(fmt.Errorf("the task failed (exit %d)", code), 1)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "The task finished. Bring changes home with: defenseclaw substrate pull %s\n", a.Name)
	return code, nil
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
		return withExitCode(fmt.Errorf("cannot read the batch file: %w", err), 2)
	}
	tasks, err := parseSubstrateBatch(data)
	if err != nil {
		return withExitCode(err, 2)
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
			code, err := runSubstrateOneTask(ctx, sub, s, tt, &quiet, project, task.Task, batchID, name, agentArgs, false)
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
		return withExitCode(fmt.Errorf("%d of %d task(s) did not finish well", failed, len(results)), 1)
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
