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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

// ResolveHarness accepts a connector name (claudecode, claude-code), the
// command a user types (claude, codex) or the display name.
func ResolveHarness(name string) (*harness.Spec, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return nil, fmt.Errorf("name a harness: %s", harnessList())
	}
	if spec, ok := harness.Get(config.NormalizeConnectorName(n)); ok {
		return spec, nil
	}
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		if spec.Command == n || strings.EqualFold(spec.DisplayName, name) || strings.ReplaceAll(strings.ToLower(spec.DisplayName), " ", "") == n {
			return spec, nil
		}
	}
	return nil, fmt.Errorf("unknown harness %q (supported: %s)", name, harnessList())
}

func harnessList() string {
	var parts []string
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		parts = append(parts, spec.Command+" ("+spec.DisplayName+")")
	}
	return strings.Join(parts, ", ")
}

// LLM credential selections for --llm.
const (
	LLMAuto        = "auto"
	LLMNone        = "none"
	LLMAnthropic   = "anthropic"
	LLMClaudeOAuth = "claude-oauth"
	LLMOpenAI      = "openai"
	LLMBedrock     = "bedrock"
	LLMGemini      = "gemini"
)

// EnvBedrockToken holds a short-term Amazon Bedrock API key.
const EnvBedrockToken = "AWS_BEARER_TOKEN_BEDROCK"

// llmChoice is the model credential a run shares with the sandbox.
type llmChoice struct {
	Credential *sandboxapi.LLMCredential
	// Source names where the secret came from (an env var or a file), for
	// the banner; the value is never printed.
	Source string
	// Hosts the placeholder resolves at.
	Hosts []string
	// Note explains a run without a credential.
	Note string
}

// llmCandidate is one model credential a harness can share: the --llm
// choice, the provider profile, the variable the sandbox reads, where the
// value comes from on this machine (for the banner), and the value.
type llmCandidate struct {
	llm, profile, envName, source string
	value                         func() string
}

// llmCandidates are the harness's model credentials in the order --llm
// auto tries them.
func (a *App) llmCandidates(spec *harness.Spec) []llmCandidate {
	fromEnv := func(names ...string) func() string {
		return func() string {
			for _, n := range names {
				if v := strings.TrimSpace(a.Getenv(n)); v != "" {
					return v
				}
			}
			return ""
		}
	}
	switch spec.Name {
	case "claudecode":
		return []llmCandidate{
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMClaudeOAuth, profiles.ClaudeOAuthID, "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", fromEnv("CLAUDE_CODE_OAUTH_TOKEN")},
			{LLMBedrock, profiles.ClaudeBedrockMantleID, "ANTHROPIC_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "codex":
		return []llmCandidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY", "CODEX_API_KEY")},
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "~/.codex/auth.json", a.codexAuthKey},
			{LLMBedrock, profiles.CodexBedrockMantleID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "opencode":
		return []llmCandidate{
			{LLMAnthropic, profiles.OpenCodeAnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMOpenAI, profiles.OpenCodeOpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMBedrock, profiles.OpenCodeBedrockMantleID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "copilot":
		// Bring-your-own-provider mode: the key goes to Copilot as
		// COPILOT_PROVIDER_API_KEY. The GitHub-token profile (Copilot's own
		// models) has no --llm choice; its endpoint set is unverified.
		return []llmCandidate{
			{LLMAnthropic, profiles.CopilotAnthropicID, "COPILOT_PROVIDER_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.CopilotBedrockMantleID, "COPILOT_PROVIDER_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "hermes", "openhands":
		return []llmCandidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.BedrockMantleOpenAIID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "antigravity":
		// An API key skips the Google sign-in; without one, sign in inside
		// the sandbox.
		return []llmCandidate{
			{LLMGemini, profiles.GeminiID, "GEMINI_API_KEY", "GEMINI_API_KEY", fromEnv("GEMINI_API_KEY")},
		}
	case "omnigent":
		// The sandbox agent runs on OmniGent's openai-agents harness.
		return []llmCandidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.BedrockMantleOpenAIID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	}
	return nil
}

// modelKeyVariables are variables besides the provider profiles' own that
// a harness reads its model key from: a --credential binding of one is the
// run's model credential. Hermes's managed provider reads its key from
// HERMES_DEFENSECLAW_API_KEY, for the OpenAI-compatible endpoint in
// HERMES_DEFENSECLAW_BASE_URL.
var modelKeyVariables = map[string][]string{
	"hermes": {connector.HermesSandboxProviderKeyEnv},
}

// detectLLM picks the harness's model credential from the user's
// environment (and, for Codex, ~/.codex/auth.json). reserved are variable
// names --credential already binds; they win.
func (a *App) detectLLM(spec *harness.Spec, choice, region string, reserved map[string]bool) (llmChoice, error) {
	choice = strings.ToLower(strings.TrimSpace(choice))
	if choice == "" {
		choice = LLMAuto
	}
	if region == "" {
		region = firstNonEmpty(a.Getenv("AWS_REGION"), a.Getenv("AWS_DEFAULT_REGION"))
	}
	cands := a.llmCandidates(spec)
	// A --credential binding of the model's own variable wins.
	for _, c := range cands {
		if reserved[c.envName] && (choice == LLMAuto || choice == LLMNone || c.llm == choice) {
			return llmChoice{Note: c.envName + " comes from --credential"}, nil
		}
	}
	for _, name := range modelKeyVariables[spec.Name] {
		if reserved[name] && (choice == LLMAuto || choice == LLMNone) {
			return llmChoice{Note: name + " comes from --credential"}, nil
		}
	}
	if choice == LLMNone {
		return llmChoice{Note: "no model credential is shared (--llm none); " + insideLoginCaveat}, nil
	}
	known := choice == LLMAuto
	for _, c := range cands {
		if c.llm == choice {
			known = true
		}
	}
	if !known {
		return llmChoice{}, fmt.Errorf("--llm %s is not available for %s (choose auto, none or one of its providers)", choice, spec.DisplayName)
	}
	for _, c := range cands {
		if choice == LLMAuto && c.llm == LLMBedrock {
			continue // Bedrock is chosen explicitly
		}
		if choice != LLMAuto && c.llm != choice {
			continue
		}
		if reserved[c.envName] {
			return llmChoice{Note: c.envName + " is bound by --credential"}, nil
		}
		v := c.value()
		if v == "" {
			continue
		}
		cred := &sandboxapi.LLMCredential{Profile: c.profile, Credentials: map[string]string{c.envName: v}}
		if c.llm == LLMBedrock {
			cred.BedrockRegion = region
		}
		cp, err := spec.CredentialProfile(c.profile, cred.BedrockRegion)
		if err != nil {
			return llmChoice{}, err
		}
		return llmChoice{Credential: cred, Source: c.source, Hosts: cp.Hosts}, nil
	}
	if choice != LLMAuto {
		return llmChoice{}, fmt.Errorf("--llm %s: no credential found (%s)", choice, a.llmHint(spec, choice))
	}
	return llmChoice{Note: "no model credential found (" + a.llmHint(spec, choice) + "); " + insideLoginCaveat}, nil
}

// insideLoginCaveat is what a login inside the sandbox costs: unlike a
// shared credential, which the sandbox sees only as a placeholder, the
// token it stores is real, and the agent can read it and send it out.
const insideLoginCaveat = "a login inside the sandbox stores a real token the agent can read"

// sandboxLLM is the banner's model line for a sandbox that exists: what the
// run that created it shared (run, its record), else the provider profile
// it was created with, named by the variable a run shares for it, whose
// placeholder resolves only at the profile's hosts.
func (a *App) sandboxLLM(spec *harness.Spec, sb *sandboxapi.Sandbox, run *runLaunch) llmChoice {
	id := sb.Launch.CredentialProfile
	if run != nil {
		switch {
		case run.ModelSource != "" && id != "":
			return llmChoice{Credential: &sandboxapi.LLMCredential{Profile: id}, Source: run.ModelSource, Hosts: run.ModelHosts}
		case run.ModelNote != "" && id == "":
			return llmChoice{Note: run.ModelNote}
		}
	}
	if id == "" {
		return llmChoice{}
	}
	cp, err := spec.CredentialProfile(id, sb.Launch.BedrockRegion)
	if err != nil || len(cp.Hosts) == 0 {
		return llmChoice{Note: id}
	}
	source := strings.TrimPrefix(id, "defenseclaw-") + " credential"
	for _, c := range a.llmCandidates(spec) {
		if c.profile == id {
			source = c.source
			break
		}
	}
	return llmChoice{Credential: &sandboxapi.LLMCredential{Profile: id}, Source: source, Hosts: cp.Hosts}
}

// llmHint says how to give a run spec's model credential.
func (a *App) llmHint(spec *harness.Spec, choice string) string {
	switch harnessName := spec.Name; {
	case choice == LLMBedrock:
		return "set " + EnvBedrockToken
	case harnessName == "claudecode":
		// A Claude subscription logs in on this machine: setup-token prints
		// a token the sandbox then sees only as a placeholder. The command
		// runs the Claude Code installed here, outside the sandbox wrapper.
		if _, err := a.LookPath(spec.Command); err != nil {
			return "set ANTHROPIC_API_KEY, or use /login in the sandbox"
		}
		setup := "`claude setup-token`"
		if a.Cfg != nil && slices.Contains(a.Cfg.OpenShell.Wrappers, spec.Name) {
			setup = "`" + wrapper.EnvBypass + "=1 claude setup-token`"
		}
		return "set ANTHROPIC_API_KEY, or CLAUDE_CODE_OAUTH_TOKEN from " + setup
	case harnessName == "codex":
		return "set OPENAI_API_KEY or log in with `codex login --with-api-key`"
	case harnessName == "opencode":
		return "set ANTHROPIC_API_KEY or OPENAI_API_KEY"
	case harnessName == "copilot":
		return "set ANTHROPIC_API_KEY"
	case harnessName == "hermes", harnessName == "openhands", harnessName == "omnigent":
		return "set OPENAI_API_KEY or ANTHROPIC_API_KEY"
	case harnessName == "antigravity":
		return "set GEMINI_API_KEY"
	}
	return "set the provider's API key"
}

// codexAuthKey reads the API key a `codex login --with-api-key` stored.
// A ChatGPT login (tokens only) is not shared.
func (a *App) codexAuthKey() string {
	home, err := a.Home()
	if err != nil {
		return ""
	}
	dir := strings.TrimSpace(a.Getenv("CODEX_HOME"))
	if dir == "" || !filepath.IsAbs(dir) {
		dir = filepath.Join(home, ".codex")
	}
	data, err := readSmallFile(filepath.Join(dir, "auth.json"), 1<<20)
	if err != nil {
		return ""
	}
	var auth struct {
		Key *string `json:"OPENAI_API_KEY"`
	}
	if json.Unmarshal(data, &auth) != nil || auth.Key == nil {
		return ""
	}
	return strings.TrimSpace(*auth.Key)
}

func readSmallFile(p string, max int64) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	if info.Size() > max {
		return nil, errors.New("file too large")
	}
	return os.ReadFile(p)
}

var credentialNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ParseCredential parses --credential NAME=host[:port]. The secret is the
// value of the variable NAME in this environment.
func (a *App) ParseCredential(spec string) (sandboxapi.CredentialBinding, error) {
	name, target, ok := strings.Cut(strings.TrimSpace(spec), "=")
	if !ok || !credentialNamePattern.MatchString(name) || target == "" {
		return sandboxapi.CredentialBinding{}, fmt.Errorf("--credential %q: use NAME=host[:port]", spec)
	}
	if strings.Contains(target, "://") {
		return sandboxapi.CredentialBinding{}, fmt.Errorf("--credential %q: name a host, not a URL (like %s=api.stripe.com or %s=host:8443)", spec, name, name)
	}
	host, port := target, 0
	if h, p, err := net.SplitHostPort(target); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return sandboxapi.CredentialBinding{}, fmt.Errorf("--credential %q: invalid port", spec)
		}
		host, port = h, n
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "/*@ ") {
		return sandboxapi.CredentialBinding{}, fmt.Errorf("--credential %q: name one host, like api.stripe.com", spec)
	}
	value := a.Getenv(name)
	if value == "" {
		return sandboxapi.CredentialBinding{}, fmt.Errorf("--credential %s: the variable %s is not set in this shell", spec, name)
	}
	return sandboxapi.CredentialBinding{Name: name, Value: value, Host: host, Port: port}, nil
}

// githubToken finds the user's GitHub token for --github-write.
func (a *App) githubToken() string {
	return firstNonEmpty(a.Getenv("GH_TOKEN"), a.Getenv("GITHUB_TOKEN"))
}

// ParseEnv parses --env KEY=VALUE.
func ParseEnv(list []string) (map[string]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !credentialNamePattern.MatchString(k) {
			return nil, fmt.Errorf("--env %q: use KEY=VALUE", kv)
		}
		out[k] = v
	}
	return out, nil
}

// secretWords are the words of a variable name that say it holds a
// secret.
var secretWords = []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "CREDENTIALS"}

// secretLooking reports a variable name that says it holds a secret (an
// API key, a token, a password): KIRO_API_KEY, GITHUB_TOKEN, DB_PASSWORD.
func secretLooking(name string) bool {
	n := strings.ToUpper(name)
	if strings.HasSuffix(n, "_KEY") {
		return true
	}
	for _, w := range secretWords {
		if n == w || strings.HasSuffix(n, "_"+w) || strings.HasPrefix(n, w+"_") || strings.Contains(n, "_"+w+"_") {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
