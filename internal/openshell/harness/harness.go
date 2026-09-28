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

// Package harness describes how each supported coding harness is installed
// in a DefenseClaw OpenShell overlay image and launched inside a sandbox:
// the pinned install steps, the in-image launcher that refreshes first-run
// state from revision-scoped credential placeholders, launch argv for
// interactive, headless and skip-permissions runs, the environment passed at
// sandbox creation, the credential profiles and the user customization paths
// worth importing, plus the tamper tier of the hook registration and the
// evidence the harness was verified with. It covers claudecode, codex,
// opencode, copilot, amp, cursor, kiro, devin, hermes, openhands,
// antigravity and omnigent.
package harness

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// Layout shared by every harness.
const (
	// InstallRootBase is where harness binaries are relocated, root-owned,
	// so a native installer's $HOME copy never becomes the pinned binary.
	InstallRootBase = "/opt/defenseclaw-harness"
	// LauncherDir holds the root-owned in-image launchers.
	LauncherDir = connector.SandboxLibDir + "/bin"
	// SupervisorPath is the Python supervisor that resumes a stopped harness.
	SupervisorPath = LauncherDir + "/dc_supervisor.py"
	// WorkRoot is where projects are mounted in mount mode.
	WorkRoot = "/work"
)

// LauncherSystemPATH leads the PATH every launcher passes to its harness:
// the root-owned system directories, ahead of whatever the caller's PATH
// adds.
const LauncherSystemPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// launcherScrubbedEnv are variables no launcher passes to its harness. The
// harnesses run hooks and tool commands through bash, which reads the file
// BASH_ENV names before a -c command and applies SHELLOPTS and BASHOPTS
// (noexec among them), so one line in a shell start-up file the agent can
// edit would run inside, or silence, every hook. `bash -p` keeps them out of
// the launcher itself; the exec drops them from the harness environment
// (SHELLOPTS and BASHOPTS are read-only inside bash, so env removes them).
// The Node-based harnesses and wrappers (Cursor Agent, the npm launchers)
// would likewise load a file NODE_OPTIONS names (--require, --import) and
// resolve missing modules from NODE_PATH before any of their own code runs.
var launcherScrubbedEnv = []string{"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "NODE_OPTIONS", "NODE_PATH"}

// launcherPreamble is the environment set-up every launcher runs first:
// system directories lead PATH, Node's compile cache is off, and the egress
// proxy is exported (egressEnvScript, which the sandbox's login shells and
// `sandbox exec` commands run too; see shellenv.go). It also defines
// dc_launch, which launcherExec starts the harness with
// (launcherJobControl).
//
// Node keeps its compile cache wherever NODE_COMPILE_CACHE (or a harness's
// own module.enableCompileCache) says, which for the Cursor Agent wrapper is
// ~/.cache/cursor-compile-cache in the workload-writable HOME, and runs the
// V8 code it finds there in place of the root-owned sources (measured on
// Cursor's Node 24.5.0: a second start reads the cache and V8 accepts it).
// NODE_DISABLE_COMPILE_CACHE=1 switches the cache off, reads included.
const launcherPreamble = `PATH=` + LauncherSystemPATH + `${PATH:+:$PATH}
export PATH
# Node would run V8 code cached in the workload-writable HOME in place of the
# root-owned harness sources.
NODE_DISABLE_COMPILE_CACHE=1
export NODE_DISABLE_COMPILE_CACHE
` + egressEnvScript + launcherJobControl

// launcherJobControl defines dc_launch COMMAND..., which every launcher
// ends with: it execs COMMAND, except in a terminal session where nothing
// could resume a harness that stops itself.
//
// A harness TUI handles Ctrl-Z itself: it restores the terminal and stops
// its process group (Claude Code and OpenCode send SIGTSTP to it and redraw
// only on SIGCONT; Codex carries on once the signal returns). In an
// OpenShell sandbox that stop never happens: the seccomp filter refuses any
// kill() aimed at a process group, and `openshell sandbox exec --tty`
// starts the launcher as the leader of a new session whose parent, the
// sandbox supervisor, is outside it, so the harness's process group is
// orphaned and the kernel would discard the stop too. A harness waiting for
// SIGCONT then hangs with the terminal in cooked mode (measured on OpenShell
// 0.1.1 with Claude Code 2.1.156 and OpenCode 1.18.31).
//
// When stdin, stdout and stderr are a terminal whose foreground process
// group is the launcher's, and no ancestor outside that group shares its
// session (dc_orphaned: the group is orphaned, so no job-control shell is
// above it), dc_launch execs the root-owned dc_supervisor.py, which forks
// the harness into its own process group, makes it the terminal's foreground
// group (tcsetpgrp on fd 0), and loops on waitpid(WUNTRACED). When the
// harness stops (SIGTSTP, SIGTTIN, SIGTTOU or SIGSTOP), the supervisor
// re-asserts tcsetpgrp and sends SIGCONT to the child and every member of
// its process group (scanning /proc/*/stat, individual kill() calls, never
// killpg, because the sandbox's seccomp filter blocks kill() aimed at a
// process group). Because the harness's own suspend fails in the sandbox,
// the supervisor also watches the terminal: when the harness left raw mode
// for canonical mode and stays there for half a second, it is treated as
// suspended and sent SIGCONT. The supervisor forwards SIGHUP and SIGTERM it
// receives and exits with the harness's status (128+n for signals). Ctrl-C
// (SIGINT) and resizes (SIGWINCH) reach the harness as usual.
//
// Under a job-control shell (a `sandbox connect --shell` prompt) Ctrl-Z
// suspends the harness to that shell as usual, so dc_launch execs COMMAND
// directly, as it does without a terminal: headless and detached runs keep
// the launcher's pid for the harness. Without /proc, or when the supervisor
// is absent, it execs COMMAND too.
const launcherJobControl = `# A harness TUI stops itself on Ctrl-Z. With no job-control shell above
# the launcher (openshell sandbox exec --tty), run it under dc_supervisor.py,
# which resumes it whenever it stops.
dc_orphaned() {
  local stat ppid pgrp sid tpgid own_pgrp own_sid rest
  read -r stat 2>/dev/null </proc/$$/stat || return 1
  read -r rest ppid own_pgrp own_sid rest tpgid rest <<<"${stat##*) }"
  [ "$tpgid" = "$own_pgrp" ] || return 1
  while [ "$ppid" -gt 0 ] 2>/dev/null; do
    read -r stat 2>/dev/null </proc/$ppid/stat || return 0
    read -r rest ppid pgrp sid rest <<<"${stat##*) }"
    if [ "$pgrp" != "$own_pgrp" ]; then
      [ "$sid" != "$own_sid" ]
      return
    fi
  done
  return 0
}
dc_launch() {
  if [ -t 0 ] && [ -t 1 ] && [ -t 2 ] && dc_orphaned && [ -x ` + SupervisorPath + ` ]; then
    exec /usr/bin/python3 -I -S ` + SupervisorPath + ` "$@"
  fi
  exec "$@"
}
`

// launcherExec is the launcher's last line: start command (the pinned
// binary and its arguments, in shell syntax) without the shell start-up
// variables, through dc_launch (launcherJobControl), which execs it or, in a
// terminal session nothing else could resume it in, supervises it.
func launcherExec(command string) string {
	return "dc_launch " + launcherEnvCommand(command) + "\n"
}

// launcherEnvCommand is command run by /usr/bin/env without the shell
// start-up variables.
func launcherEnvCommand(command string) string {
	var b strings.Builder
	b.WriteString("/usr/bin/env")
	for _, name := range launcherScrubbedEnv {
		b.WriteString(" -u " + name)
	}
	b.WriteString(" " + command)
	return b.String()
}

// LaunchMode selects how the harness runs.
type LaunchMode string

const (
	// Interactive attaches the harness TUI to the sandbox terminal.
	Interactive LaunchMode = "interactive"
	// Headless runs one prompt to completion without a TTY.
	Headless LaunchMode = "headless"
)

// LaunchOptions shape one harness invocation.
type LaunchOptions struct {
	Mode LaunchMode
	// Yolo skips the harness's own permission prompts (the sandbox default);
	// DefenseClaw hooks still gate every tool call.
	Yolo bool
	// Prompt is required in headless mode.
	Prompt string
	// CredentialProfile is the provider profile ID the sandbox uses; it can
	// add provider-specific flags (Codex custom providers).
	CredentialProfile string
	// BedrockRegion parameterizes the Bedrock Mantle profiles.
	BedrockRegion string
	// Args are passed through after DefenseClaw's flags. Without Yolo the
	// harness's bypass flags are dropped from them (BypassArgs); the
	// sandbox's managed configuration refuses bypass mode either way.
	Args []string
}

// EnvOptions shape the sandbox-creation environment.
type EnvOptions struct {
	// Artifacts are the connector's rendered overlay artifacts; their Env is
	// always included.
	Artifacts connector.SandboxArtifacts
	// SandboxID and SandboxName populate DEFENSECLAW_SANDBOX_ID and
	// DEFENSECLAW_SANDBOX_NAME.
	SandboxID   string
	SandboxName string
	// EgressProxyURL is http://<binding>:<secret>@host.openshell.internal:<egress>
	// (empty for the strict profile).
	EgressProxyURL string
	// CredentialProfile and BedrockRegion select provider env and the hosts
	// that must bypass the egress proxy so OpenShell can inject credentials.
	CredentialProfile string
	BedrockRegion     string
}

// InstallStep is one Dockerfile RUN command, executed as root at image
// build.
type InstallStep struct {
	Comment string
	Run     string
}

// CustomizationPath is a host path worth importing into the sandbox HOME.
type CustomizationPath struct {
	// Host is relative to the user's home directory.
	Host string
	// Sandbox is the absolute in-sandbox destination.
	Sandbox string
	Dir     bool
	Note    string
}

// CredentialProfile is a provider profile a harness can run with.
type CredentialProfile struct {
	ProfileID string
	// Hosts that must bypass the egress proxy (credentials are injected only
	// on OpenShell's direct provider rules). Bedrock hosts are resolved from
	// the region at use.
	Hosts []string
	// Env is non-secret sandbox env the provider needs.
	Env map[string]string
	// LaunchArgs are harness flags the provider needs.
	LaunchArgs []string
	// DefaultModel is the model a sandbox with this profile runs because
	// the provider does not serve the harness's own default. It travels
	// with ModelProvider (Codex) or as ANTHROPIC_MODEL in Env (Claude Code)
	// into the run's managed configuration, above user config and
	// configuration overrides; only the harness's model flag picks another
	// (Spec.Model).
	DefaultModel string
	// ModelProvider is the Codex model provider the profile selects; the
	// sandbox manager pins it in the per-run managed configuration. Claude
	// Code profiles select their provider through Env instead.
	ModelProvider *connector.SandboxModelProvider
	Note          string
	// Unverified, when set, says why the endpoint set was not pinned from a
	// live run (for example a vendor account DefenseClaw could not use).
	Unverified string
	// Caveat is a limit of the provider the user should know before the
	// session starts; the launch banner prints it.
	Caveat string
}

// LoginOption is a vendor login run inside the sandbox instead of (or next
// to) a provider profile. Argv starts with the harness launcher, which
// exports the egress proxy (OpenShell refuses a connection around it), so
// the login's traffic goes through the proxy like the harness's own. The
// credential it stores is a long-lived vendor account token in the sandbox
// HOME, where the workload can read it and send it out (unlike a provider
// placeholder); a kept sandbox reuses it.
type LoginOption struct {
	// Argv runs the login inside the sandbox; Argv[0] is the launcher.
	Argv []string
	Note string
	// Unverified, when set, says why the login was not performed.
	Unverified string
}

// Verification states.
const (
	// VerifiedLive: the harness ran in an OpenShell sandbox built from its
	// overlay image, its hooks reached the ingress, a DefenseClaw-blocked
	// command was blocked and egress blocking held; its image's hook-fire
	// probe passes (hooks fire, a blocked tool call has no side effect, an
	// allowed one has).
	VerifiedLive = "verified"
	// Unverified: the overlay renders and builds, but an end-to-end run is
	// missing; Verification.Note says exactly what is missing. Its images
	// never pass VerifyHooks with the built-in mock and stay unselectable.
	Unverified = "unverified"
)

// Verification records how far a harness is proven in a sandbox.
type Verification struct {
	Status string
	// Note is the evidence (verified) or the missing step and its reason
	// (unverified).
	Note string
}

// ProbeSpec tells the image probe how to identify the installed harness.
type ProbeSpec struct {
	// VersionArgv prints the harness version.
	VersionArgv []string
	// VersionRE extracts the bare version (first submatch).
	VersionRE *regexp.Regexp
	// NetworkBinaries is a POSIX sh snippet printing, one per line, the
	// realpaths of the binaries that open LLM connections. Credential
	// profiles are pinned to exactly these.
	NetworkBinaries string
}

// Spec is one harness.
type Spec struct {
	// Name is the connector name (claudecode, codex, hermes, ...).
	Name        string
	DisplayName string
	// Command is the harness binary on the workload PATH.
	Command string
	// DefaultVersion is DefenseClaw's reviewed pin; it must resolve to a
	// Known Linux hook contract.
	DefaultVersion string
	// Provider renders the connector's overlay artifacts.
	Provider connector.SandboxArtifactProvider
	// TamperTier says whether the agent or a repository can switch the hooks
	// off: connector.SandboxTamperTierManaged (a root-owned system/managed
	// policy that user and project settings cannot switch off) or
	// connector.SandboxTamperTierUser (a file in the image HOME the agent can
	// edit, or code the user or a project adds that runs beside the hooks).
	// It always equals the rendered artifacts' tier.
	TamperTier string

	verification       Verification
	probe              ProbeSpec
	install            func(version string) ([]InstallStep, error)
	launcher           string
	launchArgv         func(LaunchOptions, CredentialProfile) ([]string, error)
	bypassFlags        []bypassFlag
	credentialProfiles []CredentialProfile
	login              *LoginOption
	customization      []CustomizationPath
	preseedRefresh     []string
	// versionPattern overrides the exact-release pattern for harnesses
	// whose releases carry a build suffix (Amp, Cursor Agent).
	versionPattern *regexp.Regexp
	// env is harness-level sandbox env that depends on the install layout
	// (the connector artifacts cannot know it).
	env map[string]string
	// modelArg returns the model the caller's pass-through arguments name
	// with the harness's model flag and with a configuration override
	// ("" when they name none); modelFlag is that flag. Harnesses without
	// them never report a model.
	modelArg  func(args []string) (flag, override string)
	modelFlag string
	// directFetches are requests the pinned harness makes around the
	// egress proxy that it does without (DirectFetch).
	directFetches []DirectFetch
}

// DirectFetch is a request the pinned harness binary makes on its own
// around the egress proxy (its HTTP client ignores the proxy variables)
// with no setting that turns it off, and that the harness does without
// when it fails. OpenShell refuses it and drafts a proposal to open the
// destination; triage rejects that proposal instead of adding a direct rule
// (and the policy reload that closes the sandbox's open connections) the
// harness does not need.
type DirectFetch struct {
	Host string
	Port int
	// What says what the request is for, for the activity feed.
	What string
}

// DirectFetches lists the requests the pinned harness makes around the
// egress proxy that triage rejects.
func (s *Spec) DirectFetches() []DirectFetch {
	return append([]DirectFetch(nil), s.directFetches...)
}

// InstallRoot is the harness's root-owned install prefix.
func (s *Spec) InstallRoot() string { return path.Join(InstallRootBase, s.Name) }

// LauncherPath is the in-image launcher every sandbox invocation goes
// through.
func (s *Spec) LauncherPath() string { return path.Join(LauncherDir, s.Name+"-launch") }

// Launcher returns the root-owned launcher file for the overlay image.
func (s *Spec) Launcher() connector.SandboxFile {
	return connector.SandboxFile{
		Path:  s.LauncherPath(),
		Mode:  0o755,
		Owner: connector.SandboxOwnerRoot,
		Data:  []byte(s.launcher),
	}
}

// Probe describes version and network-binary discovery.
func (s *Spec) Probe() ProbeSpec { return s.probe }

// Verification reports how far the harness is proven in a sandbox.
func (s *Spec) Verification() Verification { return s.verification }

// PreseedRefreshSteps documents what the launcher refreshes on every start
// (placeholders are revision-scoped, so first-run state cannot be baked).
func (s *Spec) PreseedRefreshSteps() []string {
	return append([]string(nil), s.preseedRefresh...)
}

// UserCustomization lists host paths worth importing into the sandbox.
func (s *Spec) UserCustomization() []CustomizationPath {
	return append([]CustomizationPath(nil), s.customization...)
}

// CredentialProfiles lists the provider profiles the harness supports, with
// Bedrock hosts resolved for region (empty selects the default region).
func (s *Spec) CredentialProfiles(region string) []CredentialProfile {
	out := make([]CredentialProfile, 0, len(s.credentialProfiles))
	for _, cp := range s.credentialProfiles {
		out = append(out, resolveCredentialProfile(cp, region))
	}
	return out
}

// Model reports the model a launch with credential profile profileID and
// pass-through args runs: the one the harness's model flag names, else the
// profile's DefaultModel (isDefault; pinned above configuration overrides),
// else the one a configuration override names. It is empty when none says,
// and the harness picks its own. flag is how a user picks another model.
func (s *Spec) Model(profileID string, args []string) (model string, isDefault bool, flag string) {
	if s.modelArg == nil {
		return "", false, ""
	}
	byFlag, byOverride := s.modelArg(args)
	if byFlag != "" {
		return byFlag, false, s.modelFlag
	}
	for _, cp := range s.credentialProfiles {
		if profileID != "" && cp.ProfileID == profileID && cp.DefaultModel != "" {
			return cp.DefaultModel, true, s.modelFlag
		}
	}
	return byOverride, false, s.modelFlag
}

// Login returns the harness's in-sandbox vendor login, if it has one.
func (s *Spec) Login() (LoginOption, bool) {
	if s.login == nil {
		return LoginOption{}, false
	}
	out := *s.login
	out.Argv = append([]string(nil), s.login.Argv...)
	return out, true
}

// CredentialProfile returns one supported profile resolved for region.
func (s *Spec) CredentialProfile(id, region string) (CredentialProfile, error) {
	for _, cp := range s.credentialProfiles {
		if cp.ProfileID == id {
			return resolveCredentialProfile(cp, region), nil
		}
	}
	return CredentialProfile{}, fmt.Errorf("harness %s does not support provider profile %q", s.Name, id)
}

// InstallSteps returns the Dockerfile RUN steps that install version. The
// version must resolve to a Known Linux hook contract.
func (s *Spec) InstallSteps(version string) ([]InstallStep, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		version = s.DefaultVersion
	}
	pattern := versionRE
	if s.versionPattern != nil {
		pattern = s.versionPattern
	}
	if !pattern.MatchString(version) {
		return nil, fmt.Errorf("harness %s: version %q is not an exact release", s.Name, version)
	}
	if err := CheckContract(s.Name, version); err != nil {
		return nil, err
	}
	return s.install(version)
}

// LaunchArgv returns the argv to run inside the sandbox (via
// `openshell sandbox exec|connect`).
func (s *Spec) LaunchArgv(opts LaunchOptions) ([]string, error) {
	switch opts.Mode {
	case Interactive:
	case Headless:
		if strings.TrimSpace(opts.Prompt) == "" {
			return nil, fmt.Errorf("harness %s: headless launch needs a prompt", s.Name)
		}
	default:
		return nil, fmt.Errorf("harness %s: unknown launch mode %q", s.Name, opts.Mode)
	}
	var cp CredentialProfile
	if opts.CredentialProfile != "" {
		var err error
		if cp, err = s.CredentialProfile(opts.CredentialProfile, opts.BedrockRegion); err != nil {
			return nil, err
		}
	}
	if !opts.Yolo {
		opts.Args, _ = s.BypassArgs(opts.Args)
	}
	return s.launchArgv(opts, cp)
}

// bypassFlag is a harness flag that turns its permission prompts off. When
// value is set the flag counts only with a matching value, given either as
// the next argument or after "=".
type bypassFlag struct {
	name  string
	value func(string) bool
	// abbrev, for a harness whose argparse parser accepts abbreviations
	// (allow_abbrev), is the shortest prefix of name the parser resolves to
	// it: every prefix at least that long counts as the flag.
	abbrev string
	// inline, for a flag without value, also counts name=<v> when
	// inline(v) (Go's flag package takes -flag=true for a boolean).
	inline func(string) bool
}

// names reports whether an argument's name part (before any "=") is f.
func (f bypassFlag) names(name string) bool {
	if name == f.name {
		return true
	}
	return f.abbrev != "" && len(name) >= len(f.abbrev) && strings.HasPrefix(f.name, name)
}

// goBoolTrue reports whether Go's strconv.ParseBool reads v as true.
func goBoolTrue(v string) bool {
	switch v {
	case "1", "t", "T", "TRUE", "true", "True":
		return true
	}
	return false
}

// BypassArgs splits passthrough args into the ones a safe (non-yolo) run
// keeps and the bypass flags it drops, with their values: Claude Code's
// --dangerously-skip-permissions, --allow-dangerously-skip-permissions and
// --permission-mode bypassPermissions; Codex's
// --dangerously-bypass-approvals-and-sandbox, --ask-for-approval never and
// -c approval_policy="never"; for argparse harnesses (Hermes, OpenHands)
// every prefix the parser resolves to a bypass flag, and for agy (Go flags)
// the single-dash and =true forms. Arguments after "--" are never flags. The
// filter spares the user a confusing refusal; the enforcement is the
// sandbox's managed configuration, which refuses bypass mode whatever the
// harness is asked.
func (s *Spec) BypassArgs(args []string) (kept, dropped []string) {
	kept = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			kept = append(kept, args[i:]...)
			break
		}
		name, inline, hasInline := strings.Cut(arg, "=")
		matched := false
		for _, f := range s.bypassFlags {
			if !f.names(name) {
				continue
			}
			switch {
			case f.value == nil && !hasInline:
				dropped, matched = append(dropped, arg), true
			case f.value == nil && hasInline && f.inline != nil && f.inline(inline):
				dropped, matched = append(dropped, arg), true
			case f.value != nil && hasInline && f.value(inline):
				dropped, matched = append(dropped, arg), true
			case f.value != nil && !hasInline && i+1 < len(args) && f.value(args[i+1]):
				dropped, matched = append(dropped, arg, args[i+1]), true
				i++
			}
			break
		}
		if !matched {
			kept = append(kept, arg)
		}
	}
	return kept, dropped
}

// tomlStringIs reports whether a -c override's value (a TOML literal, or a
// bare string Codex accepts) is want.
func tomlStringIs(value, want string) bool {
	return tomlStringValue(value) == want
}

// tomlStringValue is a -c override's value (a TOML literal, or a bare
// string Codex accepts) without its quotes.
func tomlStringValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return value
}

// Env returns the environment for `openshell sandbox create --env`: the
// connector artifacts' startup env, the DefenseClaw sandbox identity, the
// egress proxy settings and the credential profile's env. Provider hosts and
// host.openshell.internal bypass the proxy, so hooks reach the ingress and
// OpenShell can inject LLM credentials on its direct provider rules. The
// proxy settings are also passed as openshell.EnvEgressURL and
// openshell.EnvEgressBypass, from which the launcher exports them
// (OpenShell 0.1.1 drops the standard names).
func (s *Spec) Env(opts EnvOptions) (map[string]string, error) {
	if opts.Artifacts.Connector != s.Name {
		return nil, fmt.Errorf("harness %s: artifacts belong to connector %q", s.Name, opts.Artifacts.Connector)
	}
	env := map[string]string{}
	for key, value := range opts.Artifacts.Env {
		env[key] = value
	}
	for key, value := range s.env {
		env[key] = value
	}
	if opts.SandboxID != "" {
		env["DEFENSECLAW_SANDBOX_ID"] = opts.SandboxID
	}
	if opts.SandboxName != "" {
		env["DEFENSECLAW_SANDBOX_NAME"] = opts.SandboxName
	}
	noProxy := []string{connector.SandboxIngressHost}
	if opts.CredentialProfile != "" {
		cp, err := s.CredentialProfile(opts.CredentialProfile, opts.BedrockRegion)
		if err != nil {
			return nil, err
		}
		for key, value := range cp.Env {
			env[key] = value
		}
		noProxy = append(noProxy, cp.Hosts...)
	}
	if opts.EgressProxyURL != "" {
		if !strings.HasPrefix(opts.EgressProxyURL, "http://") || strings.ContainsAny(opts.EgressProxyURL, " \n\r\t") {
			return nil, errors.New("harness: egress proxy URL must be a plain http:// URL")
		}
		for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
			env[key] = opts.EgressProxyURL
		}
		env["NODE_USE_ENV_PROXY"] = "1"
		env[openshell.EnvEgressURL] = opts.EgressProxyURL
	}
	sort.Strings(noProxy)
	SetNoProxy(env, strings.Join(dedupe(noProxy), ","))
	return env, nil
}

// SetNoProxy sets the proxy bypass list in every spelling a sandbox needs:
// NO_PROXY and no_proxy for runtimes that read them, and
// openshell.EnvEgressBypass, which survives OpenShell's environment filter
// for the launchers.
func SetNoProxy(env map[string]string, list string) {
	env["NO_PROXY"] = list
	env["no_proxy"] = list
	env[openshell.EnvEgressBypass] = list
}

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ErrUnknownContract reports a harness version outside DefenseClaw's reviewed
// Linux hook contracts; overlay builds refuse it.
var ErrUnknownContract = errors.New("harness version has no reviewed Linux hook contract")

// CheckContract refuses a harness version whose Linux hook contract is not
// Known.
func CheckContract(connectorName, version string) error {
	resolution := connector.ResolveSandboxHookContract(connectorName, version)
	if resolution.Status != connector.HookCompatibilityKnown {
		return fmt.Errorf("%w: %s %s (%s)", ErrUnknownContract, connectorName, version, resolution.Reason)
	}
	return nil
}

func resolveCredentialProfile(cp CredentialProfile, region string) CredentialProfile {
	region = strings.TrimSpace(region)
	if region == "" {
		region = profiles.DefaultBedrockRegion
	}
	host := profiles.BedrockMantleHost(region)
	out := CredentialProfile{ProfileID: cp.ProfileID, Note: cp.Note, Unverified: cp.Unverified, DefaultModel: cp.DefaultModel, Caveat: cp.Caveat,
		Env: map[string]string{}}
	if cp.ModelProvider != nil {
		p := *cp.ModelProvider
		p.BaseURL = strings.ReplaceAll(p.BaseURL, bedrockHostToken, host)
		// The run's managed configuration pins the profile's default
		// model with its provider, so every harness start in the sandbox
		// gets it.
		p.DefaultModel = cp.DefaultModel
		out.ModelProvider = &p
	}
	for _, h := range cp.Hosts {
		out.Hosts = append(out.Hosts, strings.ReplaceAll(h, bedrockHostToken, host))
	}
	for key, value := range cp.Env {
		out.Env[key] = strings.ReplaceAll(value, bedrockHostToken, host)
	}
	for _, arg := range cp.LaunchArgs {
		out.LaunchArgs = append(out.LaunchArgs, strings.ReplaceAll(arg, bedrockHostToken, host))
	}
	return out
}

// bedrockHostToken is replaced by the region's Mantle host.
const bedrockHostToken = "{bedrock-mantle-host}"

func dedupe(in []string) []string {
	out := in[:0:0]
	for i, v := range in {
		if i > 0 && v == in[i-1] {
			continue
		}
		out = append(out, v)
	}
	return out
}

var registry = map[string]*Spec{}

func register(s *Spec) *Spec {
	registry[s.Name] = s
	return s
}

// Get returns the harness spec for a connector name.
func Get(name string) (*Spec, bool) {
	s, ok := registry[name]
	return s, ok
}

// Names lists the registered harnesses, sorted.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// shellQuote single-quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
