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

package manager

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

const (
	maxCredentialValue = 16 << 10
	maxCredentials     = 16
	maxExtraEnv        = 64
	maxEnvValue        = 4096
)

var (
	envNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	credHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// reservedEnv are variables a request may not set: DefenseClaw's own, the
// proxy settings DefenseClaw owns, and loader or shell startup hooks.
var reservedEnv = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "NODE_USE_ENV_PROXY", "NODE_OPTIONS",
	"PATH", "HOME", "SHELL", "BASH_ENV", "ENV", "PROMPT_COMMAND", "IFS",
}

func reservedEnvName(name string) bool {
	upper := strings.ToUpper(name)
	switch {
	case strings.HasPrefix(upper, "DEFENSECLAW_"), strings.HasPrefix(upper, "OPENSHELL_"),
		strings.HasPrefix(upper, "LD_"), strings.HasPrefix(upper, "DYLD_"):
		return true
	}
	return slices.Contains(reservedEnv, upper)
}

func validSecretValue(v string) bool {
	return v != "" && len(v) <= maxCredentialValue && !strings.ContainsAny(v, "\x00\r\n")
}

// llmPlan is the harness LLM credential the user consented to share.
type llmPlan struct {
	profile     profiles.Profile
	credentials map[string]string
	cp          harness.CredentialProfile
}

// planLLM validates the requested LLM credential against the harness's
// supported profiles, pinned to the image's probed network binaries.
func planLLM(spec *harness.Spec, req *sandboxapi.LLMCredential, binaries []string) (*llmPlan, error) {
	if req == nil {
		return nil, nil
	}
	id := strings.TrimSpace(req.Profile)
	cp, err := spec.CredentialProfile(id, req.BedrockRegion)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
	}
	if len(binaries) == 0 {
		return nil, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable, "the overlay image recorded no network binaries to pin the %s credential to", id)
	}
	p, err := profiles.Render(id, profiles.Input{Binaries: binaries, BedrockRegion: req.BedrockRegion})
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
	}
	allowed := map[string]bool{}
	var required []string
	for _, c := range p.Spec.Credentials {
		for _, env := range c.EnvVars {
			allowed[env] = true
			if c.Required {
				required = append(required, env)
			}
		}
	}
	creds := map[string]string{}
	for k, v := range req.Credentials {
		if !allowed[k] {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "provider profile %s has no credential %s", id, k)
		}
		if !validSecretValue(v) {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s is empty or malformed", k)
		}
		creds[k] = v
	}
	for _, k := range required {
		if _, ok := creds[k]; !ok {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "provider profile %s needs credential %s", id, k)
		}
	}
	return &llmPlan{profile: p, credentials: creds, cp: cp}, nil
}

// credentialPlan is one validated --credential binding.
type credentialPlan struct {
	binding sandboxapi.CredentialBinding
	profile profiles.Profile
}

// planCredentials validates --credential bindings: each placeholder may
// only resolve at an endpoint the sandbox could be approved to reach
// directly, which is exactly what its provider rule opens.
func planCredentials(eff *packs.Effective, list []sandboxapi.CredentialBinding, reservedNames map[string]bool) ([]credentialPlan, error) {
	if len(list) > maxCredentials {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "at most %d credentials may be bound", maxCredentials)
	}
	seen := map[string]bool{}
	var out []credentialPlan
	for _, c := range list {
		c.Name = strings.TrimSpace(c.Name)
		c.Host = triage.NormalizeHost(c.Host)
		if c.Port == 0 {
			c.Port = 443
		}
		switch {
		case !envNamePattern.MatchString(c.Name) || reservedEnvName(c.Name) || reservedNames[c.Name]:
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential name %q is not allowed", c.Name)
		case seen[c.Name]:
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s is bound twice", c.Name)
		case !validSecretValue(c.Value):
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s is empty or malformed", c.Name)
		case !credHostPattern.MatchString(c.Host):
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s: %q is not a host name", c.Name, c.Host)
		case c.Port < 1 || c.Port > 65535:
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s: invalid port %d", c.Name, c.Port)
		}
		seen[c.Name] = true
		if triage.IsHostLocal(c.Host) && c.Host != packs.OpenShellHostAlias {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
				"credential %s: name the host as %s to bind it to a port on this machine", c.Name, packs.OpenShellHostAlias)
		}
		if err := triage.CheckApproval(eff, c.Host, c.Port, false); err != nil {
			return nil, err
		}
		if !triage.IsHostLocal(c.Host) {
			if dec := eff.DecideEgress(c.Host, 0); !dec.Allowed {
				switch dec.Rule {
				case packs.RuleAdminBlock, packs.RuleAdminAllowOnly, packs.RuleBlock, packs.RuleFeed:
					return nil, sandboxapi.Errorf(sandboxapi.CodePolicyViolation,
						"credential %s cannot be bound to %s: it is on the egress blocklist", c.Name, c.Host)
				}
			}
		}
		p, err := renderCredentialProfile(c)
		if err != nil {
			return nil, err
		}
		out = append(out, credentialPlan{binding: c, profile: p})
	}
	return out, nil
}

func renderCredentialProfile(c sandboxapi.CredentialBinding) (profiles.Profile, error) {
	id := credentialProfileID(c.Name, c.Host, c.Port)
	yaml := fmt.Sprintf(`id: %s
display_name: DefenseClaw credential %s
description: Binds %s to %s:%d only; the sandbox sees a placeholder that OpenShell substitutes in headers and query strings sent there
category: other
inference_capable: false
credentials:
  - name: value
    description: user credential bound with defenseclaw sandbox run --credential
    env_vars: [%s]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: %s
    port: %d
    protocol: rest
    access: full
    enforcement: enforce
binaries: ["/**"]
`, id, c.Name, c.Name, c.Host, c.Port, c.Name, c.Host, c.Port)
	spec, err := profiles.Parse([]byte(yaml))
	if err != nil {
		return profiles.Profile{}, sandboxapi.Errorf(sandboxapi.CodeInvalid, "credential %s: %v", c.Name, err)
	}
	return profiles.Profile{ID: id, YAML: []byte(yaml), Spec: spec}, nil
}

// validateExtraEnv checks request env: non-secret, not DefenseClaw's, not
// overriding what the harness artifacts pin.
func validateExtraEnv(extra map[string]string, pinned map[string]string) error {
	if len(extra) > maxExtraEnv {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "at most %d extra environment variables", maxExtraEnv)
	}
	for k, v := range extra {
		switch {
		case !envNamePattern.MatchString(k) || reservedEnvName(k):
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "environment variable %q may not be set", k)
		case len(v) > maxEnvValue || strings.ContainsAny(v, "\x00\r\n"):
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "environment variable %s has a malformed value", k)
		}
		if _, ok := pinned[k]; ok {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "environment variable %s is pinned by the %s sandbox image", k, "harness")
		}
	}
	return nil
}

// ensureProfile imports p when OpenShell does not have it, and replaces an
// existing profile that differs (a changed ingress port, or network
// binaries of another image, which are merged in). Every global profile
// import closes in-flight connections of running sandboxes, so an
// unchanged profile is never re-imported.
func (m *Manager) ensureProfile(ctx context.Context, gw *Gateway, p profiles.Profile, render func(binaries []string) (profiles.Profile, error)) error {
	existing, err := gw.Client.GetProfile(ctx, p.ID)
	switch {
	case openshell.IsNotFound(err):
		if m.opts.Profiles == nil {
			return sandboxapi.Errorf(sandboxapi.CodeUnavailable,
				"the OpenShell provider profile %s is not imported; run `defenseclaw sandbox setup`", p.ID)
		}
		if err := m.opts.Profiles.Import(ctx, gw.Name, p, false); err != nil {
			return &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "import provider profile " + p.ID, Detail: err.Error()}
		}
		return nil
	case err != nil:
		return upstream("get provider profile "+p.ID, err)
	}
	want := p
	if render != nil {
		merged := mergeStrings(profileBinaries(*existing), profileBinaries(p.Spec))
		if !slices.Equal(merged, profileBinaries(p.Spec)) {
			if want, err = render(merged); err != nil {
				return err
			}
		}
	}
	if sameProfile(*existing, want.Spec) {
		return nil
	}
	if m.opts.Profiles == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable,
			"the OpenShell provider profile %s is out of date; run `defenseclaw sandbox setup`", p.ID)
	}
	m.logf("updating provider profile %s (running sandboxes briefly lose open connections)", p.ID)
	if err := m.opts.Profiles.Import(ctx, gw.Name, want, true); err != nil {
		return &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "update provider profile " + p.ID, Detail: err.Error()}
	}
	return nil
}

func profileBinaries(p openshell.ProviderProfile) []string {
	out := make([]string, 0, len(p.Binaries))
	for _, b := range p.Binaries {
		out = append(out, b.Path)
	}
	sort.Strings(out)
	return out
}

func mergeStrings(a, b []string) []string {
	out := append(append([]string(nil), a...), b...)
	sort.Strings(out)
	return slices.Compact(out)
}

// sameProfile compares what matters for enforcement: endpoint hosts and
// ports, binaries and credential variables. Protocol and access are fixed
// by DefenseClaw's templates and do not survive the SDK's typed form.
func sameProfile(have, want openshell.ProviderProfile) bool {
	if !slices.Equal(profileBinaries(have), profileBinaries(want)) {
		return false
	}
	eps := func(p openshell.ProviderProfile) []string {
		var out []string
		for _, e := range p.Endpoints {
			out = append(out, fmt.Sprintf("%s:%d", strings.ToLower(e.Host), e.Port))
		}
		sort.Strings(out)
		return out
	}
	if !slices.Equal(eps(have), eps(want)) {
		return false
	}
	envs := func(p openshell.ProviderProfile) []string {
		var out []string
		for _, c := range p.Credentials {
			out = append(out, c.EnvVars...)
		}
		sort.Strings(out)
		return out
	}
	return slices.Equal(envs(have), envs(want))
}
