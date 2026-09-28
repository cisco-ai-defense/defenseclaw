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
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
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
	if infoArgs(o) {
		return a.runInfo(spec, o.Args)
	}
	if hostArgs(spec, o) {
		return a.runHost(spec, o.Args)
	}
	if err := a.CheckSupported(); err != nil {
		return err
	}
	if o.Detach && o.Rm {
		return errors.New("--rm cannot be combined with --detach: nothing is left to delete the sandbox when the run ends")
	}
	o.Name = strings.TrimSpace(o.Name)
	if err := checkNewName(o.Name); err != nil {
		return err
	}
	headless := o.Prompt != "" || printMode(spec, o.Args)
	if o.Detach && !headless {
		return fmt.Errorf("a detached run needs a prompt: pass --prompt TEXT%s", printHint(spec))
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
	// The organization's refusals come first; then what the run needs from
	// this terminal.
	if !o.Detach && !headless && !a.IO.TTY {
		return fmt.Errorf("`sandbox run` attaches %s to your terminal, and there is none; pass --prompt TEXT (with --detach to run in the background)", spec.DisplayName)
	}
	if err := a.checkHostPorts(spec, project, o, st); err != nil {
		return err
	}
	// What the policy changed about the request is said before anything
	// is copied or created, and a loosening flag it overrode is confirmed.
	shown, err := a.preflightViolations(ex.Violations)
	if err != nil {
		return err
	}
	copyMode := o.Copy || settingValue(ex.Settings, "workdir.mode") == config.OpenShellWorkdirCopy

	// Resume this folder's sandbox instead of starting another. The
	// sandbox keeps the settings it was created with, so flags that only a
	// new sandbox takes turn the default answer to no.
	if !o.New && o.Name == "" && a.IO.TTY && !o.Detach {
		if sb := a.resumable(ctx, api, project, spec.Name); sb != nil {
			question := fmt.Sprintf("Sandbox %s (%s, %s) already holds this folder. Resume it?", sb.Name, sb.Phase, sb.WorkdirMode)
			ignored := resumeIgnores(o, sb)
			if len(ignored) > 0 {
				question = fmt.Sprintf("Sandbox %s (%s, %s) already holds this folder. Resuming it keeps its own settings and ignores %s. Resume it anyway?",
					sb.Name, sb.Phase, sb.WorkdirMode, strings.Join(ignored, ", "))
			}
			resume, err := a.ask(question, len(ignored) == 0, false)
			if err != nil {
				return err
			}
			if resume {
				if len(ignored) > 0 {
					a.warn("resuming " + sb.Name + " without " + strings.Join(ignored, ", ") + " (they apply to a new sandbox: pass --new)")
				}
				return a.Connect(ctx, ConnectOptions{Name: sb.Name, Refresh: o.Refresh, Rm: o.Rm, Yes: o.Yes, Prompt: o.Prompt, Args: o.Args})
			}
		}
	}
	// A name in use is refused before anything is staged: a copy-mode
	// stage would replace that sandbox's copy record.
	if o.Name != "" {
		if err := a.checkNameFree(ctx, api, o.Name, headless); err != nil {
			return err
		}
	}

	req, llm, err := a.createRequest(spec, project, o, copyMode, env)
	if err != nil {
		return err
	}
	// A launch the harness cannot take (OmniGent with a profile that names
	// no default model and no --model) fails before a sandbox exists.
	pre := harness.LaunchOptions{Mode: harness.Interactive, Yolo: !o.Safe, Args: o.Args}
	if o.Prompt != "" {
		pre.Mode, pre.Prompt = harness.Headless, o.Prompt
	}
	if llm.Credential != nil {
		pre.CredentialProfile, pre.BedrockRegion = llm.Credential.Profile, llm.Credential.BedrockRegion
	}
	if _, err := spec.LaunchArgv(pre); err != nil {
		return err
	}
	var copyRec *workspace.CopyRecord
	if copyMode {
		// Stage first: a project that cannot be copied (too large, a
		// secret that cannot be held back) fails before a sandbox exists.
		if req.Name == "" {
			if req.Name, err = a.freeName(ctx, api, project); err != nil {
				return err
			}
		}
		if copyRec, err = a.stageCopy(ctx, spec, project, req.Name, o); err != nil {
			return err
		}
	}

	a.println()
	a.note("Starting a " + spec.DisplayName + " sandbox…" + a.buildNote(spec, o))
	sb, err := api.Create(ctx, req)
	if err != nil && !copyMode && sandboxapi.IsCode(err, sandboxapi.CodeNeedsCopy) {
		// A linked worktree, a git directory outside the folder and the
		// like cannot be protected in place: the run falls back to copy
		// mode, saying why.
		why := sandboxapi.AsError(err).Detail
		if why == "" {
			why = sandboxapi.AsError(err).Message
		}
		a.warn(a.tildePath(project) + " cannot be mounted live (" + why + "); running it in copy mode: the agent works on a copy, and `" +
			CommandName + " pull` brings its changes back")
		copyMode, req.Copy = true, true
		if req.Name == "" {
			if req.Name, err = a.freeName(ctx, api, project); err != nil {
				return err
			}
		}
		if copyRec, err = a.stageCopy(ctx, spec, project, req.Name, o); err != nil {
			return err
		}
		sb, err = api.Create(ctx, req)
	}
	if err != nil {
		taken := req.Name != "" && nameConflict(err)
		if copyRec != nil && !taken {
			// Unless a sandbox has the name, the stage was this run's own.
			a.discardStagedCopy(ctx, api, req.Name)
		}
		if taken {
			return nameTakenError(req.Name, headless)
		}
		return apiError(err)
	}
	s := &session{app: a, api: api, cli: cli, spec: spec, sb: sb, rm: o.Rm, yes: o.Yes, started: true, headless: headless}
	// fail removes the sandbox of a launch that failed before the harness
	// ran: the upload, the probe, or starting the harness. An error from
	// attach means the harness never started (its exit status, a signal's
	// included, comes back as a code); one from detach, that the
	// background start failed.
	fail := func(err error) error {
		a.warn("removing sandbox " + sb.Name + " after the failure")
		ctx := context.WithoutCancel(ctx)
		if _, derr := api.Delete(ctx, sb.Name, sandboxapi.DeleteRequest{}); derr != nil {
			a.warn("could not delete " + sb.Name + ": " + derr.Error())
		}
		return err
	}
	// Copy mode: create, upload, baseline, then the probe in the workdir the
	// upload made, then the harness.
	if copyMode {
		if err := s.uploadCopy(ctx, copyRec); err != nil {
			return fail(err)
		}
	}
	a.banner(sb, bannerInfo{llm: llm, o: o, shown: shown})
	if err := s.probe(ctx, sb.Workdir); err != nil {
		return fail(err)
	}
	opts := harness.LaunchOptions{Mode: harness.Interactive, Yolo: sb.Launch.Yolo, CredentialProfile: sb.Launch.CredentialProfile,
		BedrockRegion: sb.Launch.BedrockRegion, Args: filterBypass(spec, sb.Launch.Yolo, o.Args, a)}
	if o.Prompt != "" {
		opts.Mode, opts.Prompt = harness.Headless, o.Prompt
	}
	if o.Detach {
		if err := s.detach(ctx, opts); err != nil {
			return fail(err)
		}
		return nil
	}
	code, err := s.attach(ctx, opts, headless)
	if err != nil {
		return fail(err)
	}
	if err := s.end(ctx); err != nil {
		return err
	}
	return s.exit(code)
}

func printMode(spec *harness.Spec, args []string) bool {
	has := func(flags ...string) bool {
		for _, a := range args {
			for _, f := range flags {
				if a == f || strings.HasPrefix(a, f+"=") {
					return true
				}
			}
		}
		return false
	}
	switch spec.Name {
	case "claudecode", "cursor", "devin":
		return has("-p", "--print")
	case "codex":
		return len(args) > 0 && args[0] == "exec"
	case "opencode":
		return len(args) > 0 && args[0] == "run"
	case "copilot":
		return has("-p", "--prompt")
	case "amp":
		return has("-x", "--execute")
	case "kiro":
		return has("--no-interactive")
	case "hermes":
		return has("-q", "--query")
	case "openhands":
		return has("--headless")
	case "antigravity":
		return has("-p", "--print", "--prompt", "-print", "-prompt")
	case "omnigent":
		return has("-p", "--prompt")
	}
	return false
}

func printHint(spec *harness.Spec) string {
	switch spec.Name {
	case "claudecode", "cursor", "devin":
		return ` or -- -p "TEXT"`
	case "codex":
		return ` or -- exec "TEXT"`
	case "opencode":
		return ` or -- run "TEXT"`
	case "copilot":
		return ` or -- -p "TEXT"`
	case "amp":
		return ` or -- -x "TEXT"`
	case "kiro":
		return ` or -- --no-interactive "TEXT"`
	case "hermes":
		return ` or -- chat -q "TEXT"`
	case "openhands":
		return ` or -- --headless -t "TEXT"`
	case "antigravity", "omnigent":
		return ` or -- -p "TEXT"`
	}
	return ""
}

// filterBypass drops, from a safe run's pass-through arguments, the harness
// flags that turn its own permission prompts off (harness.Spec.BypassArgs),
// and says so.
func filterBypass(spec *harness.Spec, yolo bool, args []string, a *App) []string {
	if yolo {
		return args
	}
	kept, dropped := spec.BypassArgs(args)
	if len(dropped) > 0 {
		a.warn(strings.Join(dropped, " ") + " is ignored: this sandbox keeps " + spec.DisplayName + "'s permission prompts")
	}
	return kept
}

// infoArgs reports an invocation that only prints the harness's version or
// help (`claude --version` through the shell wrapper): no agent session, so
// no sandbox.
func infoArgs(o RunOptions) bool {
	if len(o.Args) != 1 || o.Prompt != "" || o.Detach {
		return false
	}
	switch o.Args[0] {
	case "--version", "-v", "-V", "--help", "-h":
		return true
	}
	return false
}

// runInfo answers a version or help invocation: with the harness installed
// on this machine it answers (it runs no agent); without it, the sandbox
// image's version, or how to run it.
func (a *App) runInfo(spec *harness.Spec, args []string) error {
	if a.Getenv(wrapper.EnvBypass) == "" {
		if path, err := a.LookPath(spec.Command); err == nil {
			// A command named like the harness that calls the sandbox
			// again answers from the image below instead.
			env := append(a.Environ(), wrapper.EnvBypass+"=1")
			return a.ExecProcess(path, append([]string{spec.Command}, args...), env)
		}
	}
	if args[0] == "--help" || args[0] == "-h" {
		a.println(spec.Command + " is not installed on this machine; DefenseClaw runs " + spec.DisplayName + " in a sandbox.")
		a.println("  " + CommandName + " run " + spec.Command + " [-- " + spec.DisplayName + " arguments]   (see `" + CommandName + " run --help`)")
		return nil
	}
	var latest image.Record
	if recs, err := a.Images.List(); err == nil {
		for _, r := range recs {
			if r.Connector == spec.Name && r.HookFireVerified && r.BuiltAt.After(latest.BuiltAt) {
				latest = r
			}
		}
	}
	if latest.HarnessVersion == "" {
		return fmt.Errorf("%s is not installed on this machine, and no %s sandbox image is built yet (`%s image build %s`)",
			spec.Command, spec.DisplayName, CommandName, spec.Command)
	}
	a.println(latest.HarnessVersion + " (" + spec.DisplayName + ", in the DefenseClaw sandbox image)")
	return nil
}

// hostSubcommands are the harness subcommands (with the second words they
// take, when they have some) that manage the harness installed on this
// machine: its settings, MCP server list, plugins, login and updates. They
// start no agent, and in a sandbox they would change only the sandbox's
// copy (after creating one, image build included). Anything not listed,
// `claude mcp serve` (Claude Code as an MCP server) among it, runs in the
// sandbox.
var hostSubcommands = map[string]map[string][]string{
	"claudecode": {
		"config": nil, "plugin": nil, "setup-token": nil, "doctor": nil, "update": nil, "install": nil, "migrate-installer": nil,
		"mcp": {"add", "add-json", "add-from-claude-desktop", "get", "list", "remove", "reset-project-choices"},
	},
	"codex": {
		"login": nil, "logout": nil, "completion": nil,
		"mcp": {"add", "get", "list", "remove", "login", "logout"},
	},
}

// hostArgs reports an invocation of one of spec's hostSubcommands (the
// wrapper's `claude mcp add ...`).
func hostArgs(spec *harness.Spec, o RunOptions) bool {
	if len(o.Args) == 0 || o.Prompt != "" || o.Detach {
		return false
	}
	second, ok := hostSubcommands[spec.Name][o.Args[0]]
	if !ok {
		return false
	}
	if second == nil || len(o.Args) == 1 {
		// `claude mcp` alone prints its help.
		return true
	}
	return o.Args[1] == "--help" || o.Args[1] == "-h" || slices.Contains(second, o.Args[1])
}

// runHost runs a hostSubcommands invocation with the harness installed on
// this machine, the way the user would without the wrapper.
func (a *App) runHost(spec *harness.Spec, args []string) error {
	what := "`" + spec.Command + " " + args[0] + "`"
	if a.Getenv(wrapper.EnvBypass) == "" {
		if path, err := a.LookPath(spec.Command); err == nil {
			fmt.Fprintln(a.IO.Err, terminalText(a.dim(what+" manages "+spec.DisplayName+" on this machine, so it runs outside the sandbox")))
			// A command named like the harness that calls the sandbox again
			// runs the harness directly.
			env := append(a.Environ(), wrapper.EnvBypass+"=1")
			return a.ExecProcess(path, append([]string{spec.Command}, args...), env)
		}
	}
	return fmt.Errorf("%s manages %s on this machine, where it is not installed; a sandbox has its own copy: "+
		"`%s connect NAME --shell` opens a shell in one", what, spec.DisplayName, CommandName)
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

// checkNewName refuses, before anything else happens, a --name OpenShell
// does not create.
func checkNewName(name string) error {
	switch {
	case name == "":
		return nil
	case openshell.ValidSandboxName(name) && len(name) > openshell.MaxSandboxNameLen:
		return fmt.Errorf("--name %q is %d characters; OpenShell takes at most %d", name, len(name), openshell.MaxSandboxNameLen)
	case !openshell.ValidNewSandboxName(name):
		return fmt.Errorf("--name %q: use at most %d lowercase letters, digits and '-', starting and ending with a letter or digit",
			name, openshell.MaxSandboxNameLen)
	case workspace.ValidateName(name) != nil:
		return fmt.Errorf("--name %q is reserved; choose another", name)
	}
	return nil
}

// checkNameFree refuses a name an existing sandbox has, with the ways on.
func (a *App) checkNameFree(ctx context.Context, api API, name string, headless bool) error {
	sb, err := api.Get(ctx, name)
	switch {
	case err == nil && sb.Phase == "deleted":
		// A deleted sandbox whose snapshot was kept: nothing to resume.
		return fmt.Errorf("the name %s holds the kept undo snapshot of a deleted sandbox: `%s undo %s` restores the folder to it, "+
			"`%s delete %s` drops it; or choose another --name", name, CommandName, name, CommandName, name)
	case err == nil:
		return nameTakenError(name, headless)
	case sandboxapi.IsCode(err, sandboxapi.CodeNotFound):
		return nil
	}
	return apiError(err)
}

func nameTakenError(name string, headless bool) error {
	resume := "`" + CommandName + " connect " + name + "`"
	if headless {
		resume = "`" + CommandName + " connect " + name + " --prompt TEXT`"
	}
	return fmt.Errorf("a sandbox named %s already exists: resume it with %s, delete it with `%s delete %s`, or choose another --name",
		name, resume, CommandName, name)
}

// nameConflict reports the daemon's refusal of a name one of its sandboxes
// has.
func nameConflict(err error) bool {
	var e *sandboxapi.Error
	return errors.As(err, &e) && e.Code == sandboxapi.CodeConflict && strings.HasPrefix(e.Message, "a sandbox named ")
}

// freeName generates a sandbox name no sandbox has (a copy-mode run stages
// under it before the daemon could refuse it).
func (a *App) freeName(ctx context.Context, api API, project string) (string, error) {
	for i := 0; i < 8; i++ {
		name, err := manager.GenerateName(project)
		if err != nil {
			return "", err
		}
		_, err = api.Get(ctx, name)
		switch {
		case sandboxapi.IsCode(err, sandboxapi.CodeNotFound):
			return name, nil
		case err != nil:
			return "", apiError(err)
		}
	}
	return "", errors.New("could not pick a free sandbox name; pass --name")
}

// buildNote says, when the harness image is missing, that the run builds
// it first.
func (a *App) buildNote(spec *harness.Spec, o RunOptions) string {
	if o.NoBuild {
		return ""
	}
	if ok, err := a.Images.Current(spec); err != nil || ok {
		return ""
	}
	return " (building its image first: about 3 GB, a few minutes)"
}

// checkHostPorts refuses a --host-port DefenseClaw does not open, the way
// the daemon refuses a --credential for one: DefenseClaw's own listeners
// and the gateways, and ports the organization or the pack keeps closed.
// The daemon would only drop them, after the banner promised them.
func (a *App) checkHostPorts(spec *harness.Spec, project string, o RunOptions, st *sandboxapi.Status) error {
	if len(o.HostPorts) == 0 || a.Cfg == nil {
		return nil
	}
	eff, _, err := packs.Resolve(a.Cfg, packs.Flags{Pack: o.Pack, Harness: spec.Name, Project: project, Profile: o.Profile,
		Copy: o.Copy, Safe: o.Safe, Unmask: o.Unmask, OpenShellGatewayPort: gatewayPort(st)})
	if err != nil {
		// The daemon resolved this run already; it reports what is wrong.
		return nil
	}
	for _, port := range o.HostPorts {
		err := eff.Allow(packs.Action{Kind: packs.ActionHostPort, Port: port})
		if err == nil {
			continue
		}
		var v *packs.Violation
		if !errors.As(err, &v) {
			return fmt.Errorf("--host-port %d: %w", port, err)
		}
		w := wireViolation(*v)
		return fmt.Errorf("--host-port %d: %s", port, violationMessage(&w, w.Message, w.Detail, w.Admin))
	}
	return nil
}

// gatewayPort is the OpenShell gateway's port from the daemon's status (0
// when unknown).
func gatewayPort(st *sandboxapi.Status) int {
	if st == nil || st.Gateway == nil {
		return 0
	}
	u, err := url.Parse(st.Gateway.Endpoint)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(u.Port())
	return port
}

// preflightViolations prints what the policy changed about the run before
// anything is copied or created, and returns them so the banner does not
// repeat them. A flag the organization overrode is confirmed on a
// terminal: the run would not do what was asked.
func (a *App) preflightViolations(list []sandboxapi.Violation) (map[string]bool, error) {
	shown := map[string]bool{}
	overridden := false
	for _, v := range list {
		if v.Fatal {
			continue
		}
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
		shown[violationKey(v)] = true
		overridden = overridden || (v.Admin && v.Source == string(packs.SourceFlag))
	}
	if overridden && a.IO.TTY {
		yes, err := a.ask("Your organization's policy overrides a flag you passed. Run with its setting?", true, false)
		if err != nil {
			return nil, err
		}
		if !yes {
			return nil, &Silent{Err: errors.New("the run was cancelled")}
		}
	}
	return shown, nil
}

func violationKey(v sandboxapi.Violation) string {
	return v.Key + "\x00" + v.Constraint + "\x00" + v.Attempted
}

// resumable returns this folder's most recent sandbox of the harness.
func (a *App) resumable(ctx context.Context, api API, project, harnessName string) *sandboxapi.Sandbox {
	list, err := api.List(ctx)
	if err != nil {
		return nil
	}
	var cands []sandboxapi.Sandbox
	for _, sb := range list {
		if sb.Project == project && sb.Harness == harnessName && !sb.Orphaned && sb.Phase != "missing" && sb.Phase != "deleting" &&
			sb.Phase != "deleted" {
			cands = append(cands, sb)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].CreatedAt.After(cands[j].CreatedAt) })
	return &cands[0]
}

// resumeIgnores lists the run flags a resume of sb would not honour: they
// shape a sandbox when it is created (its policy, mounts, credentials,
// environment and limits), and sb keeps its own. A flag sb already matches
// is left out.
func resumeIgnores(o RunOptions, sb *sandboxapi.Sandbox) []string {
	var out []string
	add := func(set bool, flag string) {
		if set {
			out = append(out, flag)
		}
	}
	add(o.Safe && sb.Launch.Yolo, "--safe")
	add(o.Pack != "" && o.Pack != sb.Pack, "--pack "+o.Pack)
	add(o.Profile != "" && o.Profile != sb.Profile, "--profile "+o.Profile)
	add(o.Copy && sb.WorkdirMode != config.OpenShellWorkdirCopy, "--copy")
	add(len(o.Context) > 0, "--context")
	add(len(o.Unmask) > 0, "--unmask")
	add(len(o.HostPorts) > 0, "--host-port")
	add(len(o.Credentials) > 0, "--credential")
	add(o.GitHubWrite, "--github-write")
	add(o.NoMCP, "--no-mcp")
	add(o.LLM != "" && !strings.EqualFold(o.LLM, LLMAuto), "--llm "+o.LLM)
	add(o.BedrockRegion != "", "--bedrock-region")
	add(len(o.Env) > 0, "--env")
	add(o.CPU != "", "--cpu")
	add(o.Memory != "", "--memory")
	add(o.NoSnapshot, "--no-snapshot")
	return out
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
		token := a.githubToken()
		if token == "" {
			return req, llmChoice{}, errors.New("--github-write needs your GitHub token in GH_TOKEN or GITHUB_TOKEN")
		}
		for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
			if !reserved[name] {
				req.Credentials = append(req.Credentials, sandboxapi.CredentialBinding{Name: name, Value: token, Host: "api.github.com"})
				reserved[name] = true
			}
		}
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
	opts, err := a.copyStageOptions(packs.Flags{Pack: o.Pack, Harness: spec.Name, Project: project, Profile: o.Profile, Safe: o.Safe, Unmask: o.Unmask}, name)
	if err != nil {
		return nil, err
	}
	a.note("Copying " + a.tildePath(project) + " (secrets are held back)…")
	rec, err := a.Workspace.Stage(ctx, opts)
	if err != nil {
		return nil, workspaceFailure("stage the project copy", err, "")
	}
	return rec, nil
}

// discardStagedCopy removes the copy staged for a sandbox the daemon did
// not create, unless a sandbox of that name exists (its copy is not this
// run's to remove).
func (a *App) discardStagedCopy(ctx context.Context, api API, name string) {
	ctx = context.WithoutCancel(ctx)
	if _, err := api.Get(ctx, name); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return
	}
	if err := a.Workspace.Discard(a.dataDir(), name); err != nil {
		a.warn("could not remove the staged copy of " + name + ": " + err.Error())
	}
}

// copyStageOptions stages flags.Project for sandbox name with the effective
// workspace policy: masks, exceptions, history depth and the size cap.
func (a *App) copyStageOptions(flags packs.Flags, name string) (workspace.StageOptions, error) {
	flags.Copy = true
	eff, _, err := packs.Resolve(a.Cfg, flags)
	if err != nil {
		return workspace.StageOptions{}, err
	}
	home, _ := a.Home()
	return workspace.StageOptions{
		Project: flags.Project, Name: name, DataDir: a.dataDir(), Home: home, GitDepth: eff.Workspace.GitDepth,
		MaxBytes: int64(eff.Workspace.MaxUploadMB) << 20, Masks: eff.Workspace.Masks, Unmask: eff.Workspace.Unmask, Replace: true,
	}, nil
}

// bannerInfo is what the launch banner shows beyond the sandbox itself.
type bannerInfo struct {
	llm llmChoice
	// o carries the run's --credential, --github-write and --host-port.
	o RunOptions
	// keptSnapshot marks an undo point an earlier session left (a resume
	// that did not take a new one).
	keptSnapshot bool
	// shown are the violations the preflight printed already.
	shown map[string]bool
}

// launchModel is the banner's model: the one a launch of sb with the
// pass-through args runs (named by args, or its provider profile's default),
// when DefenseClaw knows it.
func launchModel(sb *sandboxapi.Sandbox, args []string) string {
	spec, ok := harness.Get(sb.Harness)
	if !ok {
		return ""
	}
	model, isDefault, flag := spec.Model(sb.Launch.CredentialProfile, args)
	if model != "" && isDefault && flag != "" {
		model += " (the default; -- " + flag + " MODEL picks another)"
	}
	return model
}

// launchCaveat is the provider limit an interactive session of sb should
// know about (harness.CredentialProfile.Caveat); a one-prompt run has none.
func launchCaveat(sb *sandboxapi.Sandbox, o RunOptions) string {
	spec, ok := harness.Get(sb.Harness)
	if !ok || sb.Launch.CredentialProfile == "" || o.Prompt != "" || printMode(spec, o.Args) {
		return ""
	}
	cp, err := spec.CredentialProfile(sb.Launch.CredentialProfile, sb.Launch.BedrockRegion)
	if err != nil {
		return ""
	}
	return cp.Caveat
}

func joinNonEmpty(sep string, parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

// banner prints the plan's launch banner.
func (a *App) banner(sb *sandboxapi.Sandbox, b bannerInfo) {
	name := firstNonEmpty(sb.HarnessName, sb.Harness)
	perms := "skip-permissions ON"
	if !sb.Launch.Yolo {
		perms = "skip-permissions OFF (" + a.promptsKept(sb) + ")"
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
				l += "   " + a.undoPointText(sb, b.keptSnapshot)
			}
			a.line(l)
		}
	default:
		row("Project", a.tildePath(sb.Project)+" → "+sb.Workdir)
	}
	model := launchModel(sb, b.o.Args)
	switch {
	case b.llm.Credential != nil:
		row("Model", joinNonEmpty(" · ", model, b.llm.Source+" → "+strings.Join(b.llm.Hosts, ", ")+" only (the sandbox sees a placeholder)"))
	case b.llm.Note != "":
		row("Model", joinNonEmpty(" · ", model, b.llm.Note))
	case model != "":
		row("Model", model)
	}
	if caveat := launchCaveat(sb, b.o); caveat != "" {
		row("", "⚠ "+caveat)
	}
	for _, c := range sbCredentials(b.o) {
		row("Secret", c)
	}
	if ports := bannerHostPorts(sb, b.o); len(ports) > 0 {
		var hosts []string
		for _, p := range ports {
			hosts = append(hosts, fmt.Sprintf("localhost:%d", p))
		}
		row("Host", strings.Join(hosts, " ")+" (opens when you approve the sandbox's first connection)")
	}
	// Asks (a host port, a private address, a destination the profile
	// does not list) wait for the user while the harness owns the terminal.
	row("Asks", "shown here as they come; answer them in another terminal: "+CommandName+" approvals --sandbox "+sb.Name)
	if sb.MCP != nil && len(sb.MCP.Imported) > 0 {
		// Servers left behind and a repository's blocked servers arrive as
		// warnings below, one line each.
		row("MCP", strings.Join(sb.MCP.Imported, " ✓ · ")+" ✓")
	}
	if sb.TamperTier != "" && sb.TamperTier != "managed" {
		row("Hooks", sb.TamperTier+" tier: the agent could edit its own hook settings (hook silence is detected)")
	}
	for _, v := range sb.Violations {
		if !b.shown[violationKey(v)] {
			a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
		}
	}
	for _, w := range sb.Warnings {
		a.warn(w)
	}
	a.println()
}

// bannerHostPorts are the --host-port flags the policy accepted: the ones
// no violation refused (the pack, the organization, or a DefenseClaw port).
// None is open yet: the sandbox's first connection to one is an ask.
func bannerHostPorts(sb *sandboxapi.Sandbox, o RunOptions) []int {
	refused := map[string]bool{}
	for _, v := range sb.Violations {
		if v.Key == "mcp.host_ports" {
			refused[v.Attempted] = true
		}
	}
	var out []int
	for _, p := range o.HostPorts {
		if !refused[strconv.Itoa(p)] && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// promptsKept says why a sandbox keeps the harness's permission prompts.
func (a *App) promptsKept(sb *sandboxapi.Sandbox) string {
	const orgOff = "your organization disables skip-permissions"
	for _, v := range sb.Violations {
		if v.Key == "yolo" && v.Admin {
			if v.Constraint == "openshell.admin.allow_yolo" {
				return orgOff
			}
			return "harness prompts kept by your organization's policy"
		}
	}
	if a.Cfg != nil && a.Cfg.OpenShell.Admin.AllowYolo != nil && !*a.Cfg.OpenShell.Admin.AllowYolo {
		return orgOff
	}
	return "harness prompts kept"
}

// undoPointText is the banner's note on the mount-mode undo point.
func (a *App) undoPointText(sb *sandboxapi.Sandbox, kept bool) string {
	undo := "`" + CommandName + " undo " + sb.Name + "`"
	if kept {
		return "undo point from " + a.clock(sb.Snapshot.CreatedAt) + " kept → " + undo + " reverts every session since"
	}
	return "snapshot taken → " + undo + " restores it"
}

// clock is a local time of day, with the date when it is not today.
func (a *App) clock(t time.Time) string {
	if t.IsZero() {
		return "an earlier session"
	}
	t, now := t.Local(), a.Now().Local()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	return t.Format("Jan 2 15:04")
}

func sbCredentials(o RunOptions) []string {
	var out []string
	for _, c := range o.Credentials {
		if name, host, ok := strings.Cut(c, "="); ok {
			out = append(out, name+" → "+host+" only")
		}
	}
	if o.GitHubWrite {
		// OpenShell binds a placeholder to a host, not to a repository:
		// the token works there with everything it may do, and git's own
		// HTTPS traffic goes to github.com, which it is not bound to.
		out = append(out, "GH_TOKEN/GITHUB_TOKEN → api.github.com only: gh and the GitHub API (pull requests, issues) with everything the token may do, "+
			"in any repository it reaches; `git push` over HTTPS is not authenticated")
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
