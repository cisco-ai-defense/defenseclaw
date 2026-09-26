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
// worth importing. Phase 1 covers claudecode and codex.
package harness

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// Layout shared by every harness.
const (
	// InstallRootBase is where harness binaries are relocated, root-owned,
	// so a native installer's $HOME copy never becomes the pinned binary.
	InstallRootBase = "/opt/defenseclaw-harness"
	// LauncherDir holds the root-owned in-image launchers.
	LauncherDir = connector.SandboxLibDir + "/bin"
	// WorkRoot is where projects are mounted in mount mode.
	WorkRoot = "/work"
)

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
	// Args are passed through after DefenseClaw's flags.
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
	Note       string
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
	// Name is the connector name (claudecode, codex).
	Name        string
	DisplayName string
	// Command is the harness binary on the workload PATH.
	Command string
	// DefaultVersion is DefenseClaw's reviewed pin; it must resolve to a
	// Known Linux hook contract.
	DefaultVersion string
	// Provider renders the connector's overlay artifacts.
	Provider connector.SandboxArtifactProvider

	probe              ProbeSpec
	install            func(version string) ([]InstallStep, error)
	launcher           string
	launchArgv         func(LaunchOptions, CredentialProfile) ([]string, error)
	credentialProfiles []CredentialProfile
	customization      []CustomizationPath
	preseedRefresh     []string
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
	if !versionRE.MatchString(version) {
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
	return s.launchArgv(opts, cp)
}

// Env returns the environment for `openshell sandbox create --env`: the
// connector artifacts' startup env, the DefenseClaw sandbox identity, the
// egress proxy settings and the credential profile's env. Provider hosts and
// host.openshell.internal bypass the proxy, so hooks reach the ingress and
// OpenShell can inject LLM credentials on its direct provider rules.
func (s *Spec) Env(opts EnvOptions) (map[string]string, error) {
	if opts.Artifacts.Connector != s.Name {
		return nil, fmt.Errorf("harness %s: artifacts belong to connector %q", s.Name, opts.Artifacts.Connector)
	}
	env := map[string]string{}
	for key, value := range opts.Artifacts.Env {
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
	}
	sort.Strings(noProxy)
	joined := strings.Join(dedupe(noProxy), ",")
	env["NO_PROXY"] = joined
	env["no_proxy"] = joined
	return env, nil
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
	out := CredentialProfile{ProfileID: cp.ProfileID, Note: cp.Note, Env: map[string]string{}}
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
