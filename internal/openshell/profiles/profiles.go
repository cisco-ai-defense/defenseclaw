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

// Package profiles renders the OpenShell provider profiles DefenseClaw
// imports: the hook ingress credential profile and curated harness LLM
// profiles. A provider created from a profile gives the workload an opaque,
// revision-scoped placeholder; the supervisor swaps in the real credential
// only on the profile's endpoints and only for its binaries.
//
// Profiles are gateway-global, shared by every DefenseClaw daemon (data dir)
// on the gateway, and updating one re-points every sandbox whose providers
// use it. So a profile's id names everything its endpoints depend on: the
// ingress profile is one per ingress listener (IngressProfileID) and a
// Bedrock Mantle profile one per region (BedrockProfileID); the others
// depend on their template alone. The one thing a shared LLM profile
// accumulates is binaries, and those only grow (the union over the images
// of every daemon), so an update never takes one away from a running
// sandbox.
//
// LLM profiles are pinned to the probed realpaths of the harness binaries in
// the overlay image, so a credential cannot be used by any other program in
// the sandbox. There is deliberately no egress profile: the DefenseClaw proxy
// credential travels in HTTPS_PROXY userinfo, which OpenShell cannot
// substitute on a raw TCP relay, so the relay is a policy rule instead
// (internal/openshell/policy).
package profiles

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*.yaml.tmpl
var templateFS embed.FS

// Profile template IDs (IDs lists them). The ingress and Bedrock Mantle
// templates are imported under ids naming their inputs (Profile.ID); the
// others under the template ID.
const (
	// IngressID is the template binding DEFENSECLAW_SANDBOX_TOKEN to one
	// hook ingress listener, imported as IngressProfileID(port).
	IngressID = "defenseclaw-ingress"
	// AnthropicID binds ANTHROPIC_API_KEY (x-api-key) to api.anthropic.com.
	AnthropicID = "defenseclaw-anthropic"
	// ClaudeOAuthID binds CLAUDE_CODE_OAUTH_TOKEN (bearer) to
	// api.anthropic.com.
	ClaudeOAuthID = "defenseclaw-claude-oauth"
	// ClaudeBedrockMantleID binds a Bedrock API key as x-api-key to the
	// Mantle Anthropic route (ANTHROPIC_BASE_URL=https://<host>/anthropic),
	// imported as BedrockProfileID(ClaudeBedrockMantleID, region).
	ClaudeBedrockMantleID = "defenseclaw-claude-bedrock-mantle"
	// OpenAIID binds OPENAI_API_KEY (bearer) to api.openai.com.
	OpenAIID = "defenseclaw-openai"
	// CodexBedrockMantleID binds BEDROCK_MANTLE_API_KEY (bearer) to the
	// Mantle OpenAI-compatible route for a Codex custom provider, imported
	// as BedrockProfileID(CodexBedrockMantleID, region).
	CodexBedrockMantleID = "defenseclaw-codex-bedrock-mantle"
	// OpenCodeAnthropicID binds ANTHROPIC_API_KEY (x-api-key) to
	// api.anthropic.com for OpenCode.
	OpenCodeAnthropicID = "defenseclaw-opencode-anthropic"
	// OpenCodeOpenAIID binds OPENAI_API_KEY (bearer) to api.openai.com for
	// OpenCode.
	OpenCodeOpenAIID = "defenseclaw-opencode-openai"
	// OpenCodeBedrockMantleID binds BEDROCK_MANTLE_API_KEY (x-api-key) to the
	// Mantle Anthropic route for an OpenCode custom provider.
	OpenCodeBedrockMantleID = "defenseclaw-opencode-bedrock-mantle"
	// CopilotGitHubID binds COPILOT_GITHUB_TOKEN to GitHub and the Copilot
	// API.
	CopilotGitHubID = "defenseclaw-copilot-github"
	// CopilotAnthropicID binds COPILOT_PROVIDER_API_KEY (x-api-key) to
	// api.anthropic.com for a Copilot CLI custom provider.
	CopilotAnthropicID = "defenseclaw-copilot-anthropic"
	// CopilotBedrockMantleID binds COPILOT_PROVIDER_API_KEY (x-api-key) to
	// the Mantle Anthropic route for a Copilot CLI custom provider.
	CopilotBedrockMantleID = "defenseclaw-copilot-bedrock-mantle"
	// AmpID binds AMP_API_KEY (bearer) to the Amp service.
	AmpID = "defenseclaw-amp"
)

// LegacyIngressID is the gateway-wide ingress profile of earlier releases,
// holding one daemon's ingress port. Sandboxes created then still use it;
// nothing imports or updates it any more. The Bedrock template IDs are
// likewise the ids of the single-region Mantle profiles of earlier releases.
const LegacyIngressID = IngressID

// IngressProfileID is the gateway profile of the hook ingress listening on
// port. Each listener has its own, so DefenseClaw daemons on different
// ports (a dev daemon next to the usual one, or a changed port) never
// rewrite each other's endpoint, and daemons that use one port in turn
// share an identical profile.
func IngressProfileID(port int) string {
	return IngressID + "-" + strconv.Itoa(port)
}

// BedrockProfileID is the gateway profile of a Bedrock Mantle template in
// region ("" is DefaultBedrockRegion): sandboxes using different regions
// must not share, and so rewrite, one endpoint.
func BedrockProfileID(template, region string) string {
	region = strings.TrimSpace(region)
	if region == "" {
		region = DefaultBedrockRegion
	}
	return template + "-" + region
}

var (
	ingressProfileRE = regexp.MustCompile(`^` + regexp.QuoteMeta(IngressID) + `-([1-9][0-9]{0,4})$`)
	bedrockProfileRE = regexp.MustCompile(`^(?:` + regexp.QuoteMeta(ClaudeBedrockMantleID) + `|` +
		regexp.QuoteMeta(CodexBedrockMantleID) + `)-` + regionPattern + `$`)
)

// IngressPort returns the port of an IngressProfileID, and whether id is
// one (the legacy gateway-wide profile is not).
func IngressPort(id string) (int, bool) {
	m := ingressProfileRE.FindStringSubmatch(id)
	if m == nil {
		return 0, false
	}
	port, err := strconv.Atoi(m[1])
	if err != nil || port > 65535 {
		return 0, false
	}
	return port, true
}

// IsDefenseClaw reports whether a gateway profile id is one Render
// produces, now or in an earlier release: a template ID (which covers the
// legacy ingress and single-region Mantle profiles), an ingress listener's
// profile or a regional Mantle profile. The sandbox manager's
// credential-binding profiles (dc-cred-*) are not rendered here.
func IsDefenseClaw(id string) bool {
	if _, ok := catalog[id]; ok {
		return true
	}
	if _, ok := IngressPort(id); ok {
		return true
	}
	return bedrockProfileRE.MatchString(id)
}

// DefaultBedrockRegion is used when a Mantle profile names no region.
const DefaultBedrockRegion = "us-east-1"

// profileKind says which template inputs a profile needs.
type profileKind int

const (
	kindIngress profileKind = iota
	kindHarness
	kindBedrock
)

var catalog = map[string]profileKind{
	IngressID:             kindIngress,
	AnthropicID:           kindHarness,
	ClaudeOAuthID:         kindHarness,
	ClaudeBedrockMantleID: kindBedrock,
	OpenAIID:              kindHarness,
	CodexBedrockMantleID:  kindBedrock,

	OpenCodeAnthropicID:     kindHarness,
	OpenCodeOpenAIID:        kindHarness,
	OpenCodeBedrockMantleID: kindBedrock,
	CopilotGitHubID:         kindHarness,
	CopilotAnthropicID:      kindHarness,
	CopilotBedrockMantleID:  kindBedrock,
	AmpID:                   kindHarness,
}

// IDs lists every profile template, sorted.
func IDs() []string {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Input carries the template parameters. Only the ones a profile uses are
// validated for it.
type Input struct {
	// IngressPort is the hook ingress port (IngressID).
	IngressPort int
	// Binaries are the probed in-image realpaths allowed to use an LLM
	// credential. Globs are refused.
	Binaries []string
	// BedrockRegion selects the Mantle endpoint (default us-east-1).
	BedrockRegion string
}

// Profile is one rendered provider profile.
type Profile struct {
	// ID is the gateway profile id, which the providers created from it
	// name as their type: IngressProfileID for the ingress template,
	// BedrockProfileID for the Mantle templates, the template ID otherwise.
	ID string
	// Template is the template ID it was rendered from (one of IDs()).
	Template string
	// YAML is the profile file for `openshell profile lint|import -f`, the
	// path the harness spike validated end to end.
	YAML []byte
	// Spec is the typed SDK form for ProfileInterface.Import/Lint. The SDK's
	// profile endpoint type carries host, port and protocol only; access and
	// enforcement survive only through the YAML form.
	Spec v1.ProviderProfile
}

// regionPattern is an AWS region name.
const regionPattern = `[a-z]{2}(?:-[a-z]+)+-[0-9]`

var (
	binaryRE = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]+$`)
	regionRE = regexp.MustCompile(`^` + regionPattern + `$`)
)

type templateData struct {
	ID       string
	Port     int
	Binaries []string
	Host     string
}

// Render renders the profile template with the given ID.
func Render(id string, in Input) (Profile, error) {
	kind, ok := catalog[id]
	if !ok {
		return Profile{}, fmt.Errorf("openshell profiles: unknown profile %q", id)
	}
	data := templateData{ID: id}
	switch kind {
	case kindIngress:
		if in.IngressPort < 1 || in.IngressPort > 65535 {
			return Profile{}, fmt.Errorf("openshell profiles: %s needs an ingress port, got %d", id, in.IngressPort)
		}
		data.Port = in.IngressPort
		data.ID = IngressProfileID(in.IngressPort)
	case kindHarness, kindBedrock:
		binaries, err := validateBinaries(id, in.Binaries)
		if err != nil {
			return Profile{}, err
		}
		data.Binaries = binaries
		if kind == kindBedrock {
			region := strings.TrimSpace(in.BedrockRegion)
			if region == "" {
				region = DefaultBedrockRegion
			}
			if !regionRE.MatchString(region) {
				return Profile{}, fmt.Errorf("openshell profiles: invalid Bedrock region %q", in.BedrockRegion)
			}
			data.Host = BedrockMantleHost(region)
			data.ID = BedrockProfileID(id, region)
		}
	}
	raw, err := templateFS.ReadFile("templates/" + id + ".yaml.tmpl")
	if err != nil {
		return Profile{}, fmt.Errorf("openshell profiles: read template %s: %w", id, err)
	}
	tmpl, err := template.New(id).Option("missingkey=error").Funcs(template.FuncMap{"quote": quote}).Parse(string(raw))
	if err != nil {
		return Profile{}, fmt.Errorf("openshell profiles: parse template %s: %w", id, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return Profile{}, fmt.Errorf("openshell profiles: render %s: %w", id, err)
	}
	spec, err := Parse(buf.Bytes())
	if err != nil {
		return Profile{}, fmt.Errorf("openshell profiles: rendered %s is invalid: %w", id, err)
	}
	if spec.ID != data.ID {
		return Profile{}, fmt.Errorf("openshell profiles: template %s renders id %q, want %q", id, spec.ID, data.ID)
	}
	return Profile{ID: data.ID, Template: id, YAML: buf.Bytes(), Spec: spec}, nil
}

// BedrockMantleHost is the Mantle endpoint for region.
func BedrockMantleHost(region string) string {
	return "bedrock-mantle." + region + ".api.aws"
}

func validateBinaries(id string, binaries []string) ([]string, error) {
	if len(binaries) == 0 {
		return nil, fmt.Errorf("openshell profiles: %s needs the probed harness binary realpaths", id)
	}
	out := make([]string, 0, len(binaries))
	seen := map[string]bool{}
	for _, b := range binaries {
		if !binaryRE.MatchString(b) || path.Clean(b) != b || strings.Contains(b, "*") {
			return nil, fmt.Errorf("openshell profiles: %s binary %q must be an absolute realpath without globs", id, b)
		}
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out, nil
}

// quote renders a YAML double-quoted scalar (a JSON string is one).
func quote(s string) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}

// profileDoc is the provider profile file schema as `openshell profile
// export` prints it. Parse rejects any other key.
type profileDoc struct {
	ID               string          `yaml:"id"`
	DisplayName      string          `yaml:"display_name"`
	Description      string          `yaml:"description"`
	Category         string          `yaml:"category"`
	InferenceCapable bool            `yaml:"inference_capable"`
	Credentials      []credentialDoc `yaml:"credentials"`
	Endpoints        []endpointDoc   `yaml:"endpoints"`
	Binaries         []string        `yaml:"binaries"`
}

type credentialDoc struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	EnvVars     []string `yaml:"env_vars"`
	Required    bool     `yaml:"required"`
	AuthStyle   string   `yaml:"auth_style"`
	HeaderName  string   `yaml:"header_name"`
}

type endpointDoc struct {
	Host        string `yaml:"host"`
	Port        uint32 `yaml:"port"`
	Protocol    string `yaml:"protocol"`
	Access      string `yaml:"access"`
	Enforcement string `yaml:"enforcement"`
}

var (
	idRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	envRE    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	headerRE = regexp.MustCompile(`^[a-z0-9-]+$`)

	categories = map[string]v1.ProfileCategory{
		"other":     v1.ProfileCategory("Other"),
		"inference": v1.ProfileCategory("Inference"),
	}
)

// Parse strictly decodes and validates one provider profile file and returns
// its typed SDK form.
func Parse(data []byte) (v1.ProviderProfile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc profileDoc
	if err := dec.Decode(&doc); err != nil {
		return v1.ProviderProfile{}, fmt.Errorf("decode profile: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return v1.ProviderProfile{}, fmt.Errorf("profile file holds more than one document")
	}
	if !idRE.MatchString(doc.ID) {
		return v1.ProviderProfile{}, fmt.Errorf("invalid profile id %q", doc.ID)
	}
	category, ok := categories[doc.Category]
	if !ok {
		return v1.ProviderProfile{}, fmt.Errorf("profile %s: unsupported category %q", doc.ID, doc.Category)
	}
	if strings.TrimSpace(doc.DisplayName) == "" || strings.TrimSpace(doc.Description) == "" {
		return v1.ProviderProfile{}, fmt.Errorf("profile %s: display_name and description are required", doc.ID)
	}
	if len(doc.Credentials) == 0 || len(doc.Endpoints) == 0 || len(doc.Binaries) == 0 {
		return v1.ProviderProfile{}, fmt.Errorf("profile %s: credentials, endpoints and binaries are required", doc.ID)
	}
	spec := v1.ProviderProfile{
		ID:               doc.ID,
		DisplayName:      doc.DisplayName,
		Description:      doc.Description,
		Category:         category,
		InferenceCapable: doc.InferenceCapable,
	}
	for _, c := range doc.Credentials {
		if c.Name == "" || len(c.EnvVars) == 0 || !c.Required {
			return v1.ProviderProfile{}, fmt.Errorf("profile %s: credential %q must be required and name env vars", doc.ID, c.Name)
		}
		for _, env := range c.EnvVars {
			if !envRE.MatchString(env) {
				return v1.ProviderProfile{}, fmt.Errorf("profile %s: invalid env var %q", doc.ID, env)
			}
		}
		switch c.AuthStyle {
		case "bearer":
			if c.HeaderName != "authorization" {
				return v1.ProviderProfile{}, fmt.Errorf("profile %s: bearer credentials use the authorization header", doc.ID)
			}
		case "header":
			if !headerRE.MatchString(c.HeaderName) || c.HeaderName == "authorization" {
				return v1.ProviderProfile{}, fmt.Errorf("profile %s: header credential needs a lower-case header name", doc.ID)
			}
		default:
			return v1.ProviderProfile{}, fmt.Errorf("profile %s: unsupported auth_style %q", doc.ID, c.AuthStyle)
		}
		spec.Credentials = append(spec.Credentials, v1.ProfileCredential{
			Name:        c.Name,
			Description: c.Description,
			EnvVars:     append([]string(nil), c.EnvVars...),
			Required:    c.Required,
			AuthStyle:   c.AuthStyle,
			HeaderName:  c.HeaderName,
		})
	}
	for _, ep := range doc.Endpoints {
		if !hostRE.MatchString(ep.Host) || ep.Port == 0 || ep.Port > 65535 {
			return v1.ProviderProfile{}, fmt.Errorf("profile %s: invalid endpoint %s:%d", doc.ID, ep.Host, ep.Port)
		}
		// Credential substitution needs an inspected HTTP endpoint that
		// blocks violations.
		if ep.Protocol != "rest" || ep.Access != "full" || ep.Enforcement != "enforce" {
			return v1.ProviderProfile{}, fmt.Errorf("profile %s: endpoint %s must be protocol rest, access full, enforcement enforce", doc.ID, ep.Host)
		}
		spec.Endpoints = append(spec.Endpoints, v1.NetworkEndpoint{Host: ep.Host, Port: ep.Port, Protocol: ep.Protocol})
	}
	for _, b := range doc.Binaries {
		if b != "/**" && (!binaryRE.MatchString(b) || strings.Contains(b, "*")) {
			return v1.ProviderProfile{}, fmt.Errorf("profile %s: invalid binary %q", doc.ID, b)
		}
		spec.Binaries = append(spec.Binaries, v1.NetworkBinary{Path: b})
	}
	if doc.InferenceCapable {
		for _, b := range doc.Binaries {
			if b == "/**" {
				return v1.ProviderProfile{}, fmt.Errorf("profile %s: an inference credential may not be usable by every binary", doc.ID)
			}
		}
	}
	return spec, nil
}
