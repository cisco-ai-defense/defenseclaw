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
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
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
	type candidate struct {
		llm, profile, envName, source string
		value                         func() string
	}
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
	var cands []candidate
	switch spec.Name {
	case "claudecode":
		cands = []candidate{
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMClaudeOAuth, profiles.ClaudeOAuthID, "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", fromEnv("CLAUDE_CODE_OAUTH_TOKEN")},
			{LLMBedrock, profiles.ClaudeBedrockMantleID, "ANTHROPIC_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "codex":
		cands = []candidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY", "CODEX_API_KEY")},
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "~/.codex/auth.json", a.codexAuthKey},
			{LLMBedrock, profiles.CodexBedrockMantleID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "opencode":
		cands = []candidate{
			{LLMAnthropic, profiles.OpenCodeAnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMOpenAI, profiles.OpenCodeOpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMBedrock, profiles.OpenCodeBedrockMantleID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "copilot":
		// Bring-your-own-provider mode: the key goes to Copilot as
		// COPILOT_PROVIDER_API_KEY. The GitHub-token profile (Copilot's own
		// models) has no --llm choice; its endpoint set is unverified.
		cands = []candidate{
			{LLMAnthropic, profiles.CopilotAnthropicID, "COPILOT_PROVIDER_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.CopilotBedrockMantleID, "COPILOT_PROVIDER_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "hermes", "openhands":
		cands = []candidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.BedrockMantleOpenAIID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	case "antigravity":
		// An API key skips the Google sign-in; without one, sign in inside
		// the sandbox.
		cands = []candidate{
			{LLMGemini, profiles.GeminiID, "GEMINI_API_KEY", "GEMINI_API_KEY", fromEnv("GEMINI_API_KEY")},
		}
	case "omnigent":
		// The sandbox agent runs on OmniGent's openai-agents harness.
		cands = []candidate{
			{LLMOpenAI, profiles.OpenAIID, "OPENAI_API_KEY", "OPENAI_API_KEY", fromEnv("OPENAI_API_KEY")},
			{LLMAnthropic, profiles.AnthropicID, "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", fromEnv("ANTHROPIC_API_KEY")},
			{LLMBedrock, profiles.BedrockMantleOpenAIID, "BEDROCK_MANTLE_API_KEY", EnvBedrockToken, fromEnv(EnvBedrockToken)},
		}
	}
	// A --credential binding of the model's own variable wins.
	for _, c := range cands {
		if reserved[c.envName] && (choice == LLMAuto || choice == LLMNone || c.llm == choice) {
			return llmChoice{Note: c.envName + " comes from --credential"}, nil
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
		return llmChoice{}, fmt.Errorf("--llm %s: no credential found (%s)", choice, llmHint(spec.Name, choice))
	}
	return llmChoice{Note: "no model credential found (" + llmHint(spec.Name, choice) + "); " + insideLoginCaveat}, nil
}

// insideLoginCaveat is what a login inside the sandbox costs: unlike a
// shared credential, which the sandbox sees only as a placeholder, the
// token it stores is real, and the agent can read it and send it out.
const insideLoginCaveat = "a login inside the sandbox stores a real token there, which the agent can read"

// sandboxLLM is the banner's model line for a sandbox that exists: the
// provider profile it was created with, whose placeholder resolves only at
// the profile's hosts.
func sandboxLLM(spec *harness.Spec, sb *sandboxapi.Sandbox) llmChoice {
	id := sb.Launch.CredentialProfile
	if id == "" {
		return llmChoice{}
	}
	cp, err := spec.CredentialProfile(id, sb.Launch.BedrockRegion)
	if err != nil || len(cp.Hosts) == 0 {
		return llmChoice{Note: id}
	}
	return llmChoice{Credential: &sandboxapi.LLMCredential{Profile: id}, Source: strings.TrimPrefix(id, "defenseclaw-") + " credential", Hosts: cp.Hosts}
}

func llmHint(harnessName, choice string) string {
	switch {
	case choice == LLMBedrock:
		return "set " + EnvBedrockToken
	case harnessName == "claudecode":
		// A Claude subscription logs in on this machine: setup-token prints
		// a token the sandbox then sees only as a placeholder.
		return "set ANTHROPIC_API_KEY, or run `claude setup-token` here and set CLAUDE_CODE_OAUTH_TOKEN to the token it prints"
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
