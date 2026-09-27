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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// RunOptions are the `sandbox run` flags.
type RunOptions struct {
	Harness string
	Name    string
	Copy    bool
	Safe    bool
	Pack    string
	Profile string
	Context []string
	Unmask  []string
	// HostPorts open exactly these host loopback ports to the sandbox.
	HostPorts []int
	// Credentials are --credential NAME=host[:port].
	Credentials []string
	GitHubWrite bool
	NoMCP       bool
	Detach      bool
	// Rm deletes the sandbox when the session ends.
	Rm bool
	// Prompt runs the harness headless with one prompt.
	Prompt string
	// Env adds non-secret KEY=VALUE variables to the sandbox.
	Env []string
	// LLM selects the model credential (auto, none, or a provider).
	LLM           string
	BedrockRegion string
	NoSnapshot    bool
	// NoBuild refuses to build a missing overlay image.
	NoBuild bool
	// New skips the offer to resume this folder's existing sandbox;
	// Refresh re-copies a resumed copy-mode sandbox's project.
	New     bool
	Refresh bool
	CPU     string
	Memory  string
	// Yes answers the end-of-session prompts with their defaults.
	Yes bool
	// Args are passed to the harness after `--`.
	Args []string
}

// Probe exec timing. OpenShell 0.1.1 sometimes loses the first exec after
// a start (FINDINGS-core 13), so a trivial command goes first.
const (
	probeTimeout  = 30 * time.Second
	probeAttempts = 3
)

// Run is `sandbox run <harness>`.
func (a *App) Run(ctx context.Context, o RunOptions) error {
	a.defaults()
	spec, err := ResolveHarness(o.Harness)
	if err != nil {
		return err
	}
	// A shell inside a sandbox (the wrapper, or a nested call) runs the
	// harness natively: it is already sandboxed.
	if a.Getenv(openshell.EnvSandboxID) != "" {
		return a.runNative(spec, o.Args)
	}
	if err := a.CheckSupported(); err != nil {
		return err
	}
	if o.Detach && o.Rm {
		return errors.New("--rm cannot be combined with --detach: nothing is left to delete the sandbox when the run ends")
	}
	headless := o.Prompt != "" || printMode(spec, o.Args)
	if o.Detach && !headless {
		return fmt.Errorf("a detached run needs a prompt: pass --prompt TEXT%s", printHint(spec))
	}
	if !o.Detach && !headless && !a.IO.TTY {
		return fmt.Errorf("`sandbox run` attaches %s to your terminal, and there is none; pass --prompt TEXT (with --detach to run in the background)", spec.DisplayName)
	}
	env, err := ParseEnv(o.Env)
	if err != nil {
		return err
	}
	project, err := a.project()
	if err != nil {
		return err
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	st, err := a.preflight(ctx, api)
	if err != nil {
		return err
	}
	gateway := ""
	if st.Gateway != nil {
		gateway = st.Gateway.Name
	}
	cli := a.cli(gateway)
	if _, err := a.LookPath(cli.Binary); err != nil {
		return fmt.Errorf("the OpenShell CLI (%s) is not on PATH; run `%s setup`", cli.Binary, CommandName)
	}

	// Policy preflight: an organization's constraints refuse the run
	// before anything is created.
	ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{
		Harness: spec.Name, Pack: o.Pack, Profile: o.Profile, Project: project, Copy: o.Copy, Safe: o.Safe, Unmask: o.Unmask,
	})
	if err != nil {
		return apiError(err)
	}
	for _, v := range ex.Violations {
		if v.Fatal {
			return errors.New(violationMessage(&v, v.Message, v.Detail, v.Admin))
		}
	}
	copyMode := o.Copy || settingValue(ex.Settings, "workdir.mode") == config.OpenShellWorkdirCopy

	// Resume this folder's sandbox instead of starting another.
	if !o.New && o.Name == "" && a.IO.TTY && !o.Detach && !headless {
		if sb := a.resumable(ctx, api, project, spec.Name); sb != nil {
			resume, err := a.ask(fmt.Sprintf("Sandbox %s (%s, %s) already holds this folder. Resume it?", sb.Name, sb.Phase, sb.WorkdirMode), true, false)
			if err != nil {
				return err
			}
			if resume {
				return a.Connect(ctx, ConnectOptions{Name: sb.Name, Refresh: o.Refresh, Rm: o.Rm, Yes: o.Yes, Args: o.Args})
			}
		}
	}

	req, llm, err := a.createRequest(spec, project, o, copyMode, env)
	if err != nil {
		return err
	}
	var copyRec *workspace.CopyRecord
	if copyMode {
		// Stage first: a project that cannot be copied (too large, a
		// secret that cannot be held back) fails before a sandbox exists.
		if req.Name == "" {
			if req.Name, err = manager.GenerateName(spec.Name, project); err != nil {
				return err
			}
		}
		if copyRec, err = a.stageCopy(ctx, spec, project, req.Name, o); err != nil {
			return err
		}
	}

	a.println()
	a.note("Starting a " + spec.DisplayName + " sandbox… (the first run builds its image, about 3 GB)")
	sb, err := api.Create(ctx, req)
	if err != nil {
		return apiError(err)
	}
	s := &session{app: a, api: api, cli: cli, spec: spec, sb: sb, rm: o.Rm, yes: o.Yes, llm: llm}
	fail := func(err error) error {
		a.warn("removing sandbox " + sb.Name + " after the failure")
		ctx := context.WithoutCancel(ctx)
		if _, derr := api.Delete(ctx, sb.Name, sandboxapi.DeleteRequest{}); derr != nil {
			a.warn("could not delete " + sb.Name + ": " + derr.Error())
		}
		return err
	}
	if copyMode {
		if err := s.uploadCopy(ctx, copyRec); err != nil {
			return fail(err)
		}
	}
	a.banner(sb, llm, o)
	if err := s.probe(ctx); err != nil {
		return fail(err)
	}
	opts := harness.LaunchOptions{Mode: harness.Interactive, Yolo: sb.Launch.Yolo, CredentialProfile: sb.Launch.CredentialProfile,
		BedrockRegion: sb.Launch.BedrockRegion, Args: filterBypass(spec, sb.Launch.Yolo, o.Args, a)}
	if o.Prompt != "" {
		opts.Mode, opts.Prompt = harness.Headless, o.Prompt
	}
	if o.Detach {
		return s.detach(ctx, opts)
	}
	code, err := s.attach(ctx, opts, headless)
	if err != nil {
		return err
	}
	if err := s.end(ctx); err != nil {
		return err
	}
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

func printMode(spec *harness.Spec, args []string) bool {
	switch spec.Name {
	case "claudecode":
		for _, a := range args {
			if a == "-p" || a == "--print" || strings.HasPrefix(a, "--print=") {
				return true
			}
		}
	case "codex":
		return len(args) > 0 && args[0] == "exec"
	}
	return false
}

func printHint(spec *harness.Spec) string {
	switch spec.Name {
	case "claudecode":
		return ` or -- -p "TEXT"`
	case "codex":
		return ` or -- exec "TEXT"`
	}
	return ""
}

// bypassFlags are the harness flags that turn its own permission prompts
// off; a --safe run drops them from the pass-through arguments.
var bypassFlags = map[string][]string{
	"claudecode": {"--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"},
	"codex":      {"--dangerously-bypass-approvals-and-sandbox", "--yolo", "--full-auto"},
}

func filterBypass(spec *harness.Spec, yolo bool, args []string, a *App) []string {
	if yolo {
		return args
	}
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if slices.Contains(bypassFlags[spec.Name], arg) {
			a.warn(arg + " is ignored: this sandbox keeps " + spec.DisplayName + "'s permission prompts")
			continue
		}
		out = append(out, arg)
	}
	return out
}

// runNative execs the harness directly inside a sandbox.
func (a *App) runNative(spec *harness.Spec, args []string) error {
	path, err := a.LookPath(spec.Command)
	if err != nil {
		return fmt.Errorf("already inside sandbox %s, but %s is not on PATH", a.Getenv(openshell.EnvSandboxName), spec.Command)
	}
	return a.ExecProcess(path, append([]string{spec.Command}, args...), a.Environ())
}

// preflight checks that the daemon runs with sandboxes available.
func (a *App) preflight(ctx context.Context, api API) (*sandboxapi.Status, error) {
	st, err := api.Status(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	if !st.Enabled {
		return nil, fmt.Errorf("OpenShell sandboxes are off; run `%s setup` to turn them on", CommandName)
	}
	if !st.Available {
		reason := firstNonEmpty(st.Reason, "the daemon is not connected to an OpenShell gateway")
		return nil, fmt.Errorf("sandboxes are unavailable: %s (see `%s doctor`)", reason, CommandName)
	}
	return st, nil
}

// resumable returns this folder's most recent sandbox of the harness.
func (a *App) resumable(ctx context.Context, api API, project, harnessName string) *sandboxapi.Sandbox {
	list, err := api.List(ctx)
	if err != nil {
		return nil
	}
	var cands []sandboxapi.Sandbox
	for _, sb := range list {
		if sb.Project == project && sb.Harness == harnessName && !sb.Orphaned && sb.Phase != "missing" && sb.Phase != "deleting" {
			cands = append(cands, sb)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].CreatedAt.After(cands[j].CreatedAt) })
	return &cands[0]
}

func settingValue(settings []sandboxapi.Setting, key string) string {
	for _, s := range settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// createRequest turns the flags into the daemon's create request.
func (a *App) createRequest(spec *harness.Spec, project string, o RunOptions, copyMode bool, env map[string]string) (sandboxapi.CreateRequest, llmChoice, error) {
	req := sandboxapi.CreateRequest{
		Name: strings.TrimSpace(o.Name), Harness: spec.Name, Project: project, Pack: o.Pack, Profile: o.Profile,
		Copy: copyMode, Safe: o.Safe, Context: o.Context, Unmask: o.Unmask, HostPorts: o.HostPorts, NoMCP: o.NoMCP,
		CPU: o.CPU, Memory: o.Memory, NoSnapshot: o.NoSnapshot, NoBuild: o.NoBuild, Env: env,
	}
	if req.Name != "" && !openshell.ValidSandboxName(req.Name) {
		return req, llmChoice{}, fmt.Errorf("--name %q: use lowercase letters, digits and '-' (at most 63)", req.Name)
	}
	reserved := map[string]bool{}
	for _, c := range o.Credentials {
		b, err := a.ParseCredential(c)
		if err != nil {
			return req, llmChoice{}, err
		}
		reserved[b.Name] = true
		req.Credentials = append(req.Credentials, b)
	}
	if o.GitHubWrite {
		token, from := a.githubToken()
		if token == "" {
			return req, llmChoice{}, errors.New("--github-write needs your GitHub token in GH_TOKEN or GITHUB_TOKEN")
		}
		for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
			if !reserved[name] {
				req.Credentials = append(req.Credentials, sandboxapi.CredentialBinding{Name: name, Value: token, Host: "api.github.com"})
				reserved[name] = true
			}
		}
		_ = from
	}
	llm, err := a.detectLLM(spec, o.LLM, o.BedrockRegion, reserved)
	if err != nil {
		return req, llmChoice{}, err
	}
	req.LLM = llm.Credential
	return req, llm, nil
}

// stageCopy stages the copy-mode project with the effective workspace
// policy.
func (a *App) stageCopy(ctx context.Context, spec *harness.Spec, project, name string, o RunOptions) (*workspace.CopyRecord, error) {
	eff, _, err := packs.Resolve(a.Cfg, packs.Flags{Pack: o.Pack, Harness: spec.Name, Project: project, Profile: o.Profile, Copy: true, Safe: o.Safe, Unmask: o.Unmask})
	if err != nil {
		return nil, err
	}
	home, _ := a.Home()
	a.note("Copying " + a.tildePath(project) + " (secrets are held back)…")
	rec, err := a.Workspace.Stage(ctx, workspace.StageOptions{
		Project: project, Name: name, DataDir: a.dataDir(), Home: home, GitDepth: eff.Workspace.GitDepth,
		MaxBytes: int64(eff.Workspace.MaxUploadMB) << 20, Masks: eff.Workspace.Masks, Unmask: eff.Workspace.Unmask, Replace: true,
	})
	if err != nil {
		return nil, fmt.Errorf("stage the project copy: %w", err)
	}
	return rec, nil
}

// banner prints the plan's launch banner.
func (a *App) banner(sb *sandboxapi.Sandbox, llm llmChoice, o RunOptions) {
	name := firstNonEmpty(sb.HarnessName, sb.Harness)
	perms := "skip-permissions ON"
	if !sb.Launch.Yolo {
		perms = "skip-permissions OFF (harness prompts kept)"
	}
	a.println()
	a.printf("%s %s · %s · %s · network: %s\n", a.bold("Sandbox"), a.bold(sb.Name), name, perms, networkLabel(sb))
	row := func(label, text string) { a.line(fmt.Sprintf("%-10s%s", label, text)) }
	switch {
	case sb.WorkdirMode == config.OpenShellWorkdirCopy:
		row("Project", a.tildePath(sb.Project)+" → "+sb.Workdir+" (copy)   changes come back with `"+CommandName+" pull "+sb.Name+"`")
		row("", "Not visible: everything else on this machine")
	case sb.Workspace != nil:
		sum := workspace.Summary{Project: sb.Workspace.Project, Hidden: sb.Workspace.Hidden, Protected: sb.Workspace.Protected,
			Context: sb.Workspace.Context, Warnings: sb.Workspace.Warnings}
		for i, l := range sum.Lines() {
			if i == 0 && sb.Snapshot != nil {
				l += "   snapshot taken → `" + CommandName + " undo` restores it"
			}
			a.line(l)
		}
	default:
		row("Project", a.tildePath(sb.Project)+" → "+sb.Workdir)
	}
	if llm.Credential != nil {
		row("Model", llm.Source+" → "+strings.Join(llm.Hosts, ", ")+" only (the sandbox sees a placeholder)")
	} else if llm.Note != "" {
		row("Model", llm.Note)
	}
	for _, c := range sbCredentials(o) {
		row("Secret", c)
	}
	if len(o.HostPorts) > 0 {
		var ports []string
		for _, p := range o.HostPorts {
			ports = append(ports, fmt.Sprintf("localhost:%d", p))
		}
		row("Host", strings.Join(ports, " ")+" reachable from the sandbox")
	}
	if sb.TamperTier != "" && sb.TamperTier != "managed" {
		row("Hooks", sb.TamperTier+" tier: the agent could edit its own hook settings (hook silence is detected)")
	}
	for _, v := range sb.Violations {
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	for _, w := range sb.Warnings {
		a.warn(w)
	}
	a.println()
}

func sbCredentials(o RunOptions) []string {
	var out []string
	for _, c := range o.Credentials {
		if name, host, ok := strings.Cut(c, "="); ok {
			out = append(out, name+" → "+host+" only")
		}
	}
	if o.GitHubWrite {
		out = append(out, "GH_TOKEN/GITHUB_TOKEN → api.github.com only (gh can push and open pull requests)")
	}
	return out
}

func networkLabel(sb *sandboxapi.Sandbox) string {
	switch sb.NetworkMode {
	case packs.NetworkOpen, "":
		return "open + blocklist"
	case packs.NetworkAllowlist:
		return "allowlist (" + sb.Profile + ")"
	case packs.NetworkDeny:
		return "provider hosts only (" + sb.Profile + ")"
	}
	return sb.NetworkMode
}
