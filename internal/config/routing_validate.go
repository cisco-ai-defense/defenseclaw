// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	routingEnvNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	routingVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
)

const routingSupportedVersion = "0.3.0"

// Validate checks the operator-facing routing contract before the gateway
// writes a generated semantic-router config or starts a container. It is
// intentionally independent of whether routing is enabled so a disabled
// config can be prepared safely and enabled later without changing meaning.
func (r *RoutingConfig) Validate() error {
	if r == nil {
		return nil
	}
	if r.Version != "" && !routingVersionPattern.MatchString(strings.TrimSpace(r.Version)) {
		return fmt.Errorf("version %q must be a semantic version such as 0.3.0", r.Version)
	}
	if version := strings.TrimPrefix(strings.TrimSpace(r.Version), "v"); version != "" && version != routingSupportedVersion {
		return fmt.Errorf("version %q is not supported by this DefenseClaw release (supported: %s)", r.Version, routingSupportedVersion)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("port %d must be between 1 and 65535 (or 0 for the default)", r.Port)
	}
	if r.Remote.TimeoutMs < 0 {
		return fmt.Errorf("remote.timeout_ms must be positive (or 0 for the default)")
	}
	if r.Remote.TimeoutMs > 5000 {
		return fmt.Errorf("remote.timeout_ms must not exceed 5000ms")
	}
	if r.Remote.Endpoint != "" {
		if err := validateRemoteRoutingURL("remote.endpoint", r.Remote.Endpoint); err != nil {
			return err
		}
	}
	aliases := make(map[string]struct{}, len(r.Models))
	for i, model := range r.Models {
		name := strings.TrimSpace(model.Name)
		if name == "" {
			return fmt.Errorf("models[%d].name must be non-empty", i)
		}
		if name != model.Name {
			return fmt.Errorf("models[%d].name %q must not contain surrounding whitespace", i, model.Name)
		}
		if len(name) > 128 {
			return fmt.Errorf("models[%d].name must not exceed 128 bytes", i)
		}
		if _, exists := aliases[name]; exists {
			return fmt.Errorf("models[%d].name %q is duplicated", i, name)
		}
		aliases[name] = struct{}{}
		if strings.TrimSpace(model.Provider) == "" {
			return fmt.Errorf("models[%d].provider must be non-empty", i)
		}
		if strings.TrimSpace(model.Provider) != model.Provider {
			return fmt.Errorf("models[%d].provider %q must not contain surrounding whitespace", i, model.Provider)
		}
		if strings.TrimSpace(model.Model) == "" {
			return fmt.Errorf("models[%d].model must be non-empty", i)
		}
		if strings.TrimSpace(model.Model) != model.Model {
			return fmt.Errorf("models[%d].model %q must not contain surrounding whitespace", i, model.Model)
		}
		if model.BaseURL != "" {
			if err := validateRoutingURL(fmt.Sprintf("models[%d].base_url", i), model.BaseURL); err != nil {
				return err
			}
		}
		if model.APIKeyEnv != "" && !routingEnvNamePattern.MatchString(model.APIKeyEnv) {
			return fmt.Errorf("models[%d].api_key_env %q is not a valid environment variable name", i, model.APIKeyEnv)
		}
	}
	if r.Enabled && len(r.Models) == 0 {
		return fmt.Errorf("models must contain at least one backend when routing is enabled")
	}

	keywordSignals := make(map[string]struct{}, len(r.Signals.Keywords))
	for i, signal := range r.Signals.Keywords {
		name := strings.TrimSpace(signal.Name)
		if name == "" {
			return fmt.Errorf("signals.keywords[%d].name must be non-empty", i)
		}
		if len(name) > 128 {
			return fmt.Errorf("signals.keywords[%d].name must not exceed 128 bytes", i)
		}
		if _, exists := keywordSignals[name]; exists {
			return fmt.Errorf("signals.keywords[%d].name %q is duplicated", i, name)
		}
		keywordSignals[name] = struct{}{}
		if len(signal.Keywords) == 0 {
			return fmt.Errorf("signals.keywords[%d].keywords must contain at least one keyword", i)
		}
		for j, keyword := range signal.Keywords {
			if strings.TrimSpace(keyword) == "" {
				return fmt.Errorf("signals.keywords[%d].keywords[%d] must be non-empty", i, j)
			}
		}
		if operator := strings.ToUpper(strings.TrimSpace(signal.Operator)); operator != "" && operator != "AND" && operator != "OR" {
			return fmt.Errorf("signals.keywords[%d].operator %q must be AND or OR", i, signal.Operator)
		}
	}

	decisionNames := make(map[string]struct{}, len(r.Decisions))
	for i, decision := range r.Decisions {
		name := strings.TrimSpace(decision.Name)
		if name == "" {
			return fmt.Errorf("decisions[%d].name must be non-empty", i)
		}
		if len(name) > 64 {
			return fmt.Errorf("decisions[%d].name must not exceed 64 bytes", i)
		}
		if _, exists := decisionNames[name]; exists {
			return fmt.Errorf("decisions[%d].name %q is duplicated", i, name)
		}
		decisionNames[name] = struct{}{}
		if len(decision.ModelRefs) == 0 {
			return fmt.Errorf("decisions[%d].model_refs must contain at least one model alias", i)
		}
		for j, ref := range decision.ModelRefs {
			if _, exists := aliases[strings.TrimSpace(ref)]; !exists {
				return fmt.Errorf("decisions[%d].model_refs[%d] references unknown model alias %q", i, j, ref)
			}
		}
		if operator := strings.ToUpper(strings.TrimSpace(decision.Operator)); operator != "" && operator != "AND" && operator != "OR" {
			return fmt.Errorf("decisions[%d].operator %q must be AND or OR", i, decision.Operator)
		}
		for j, condition := range decision.Conditions {
			conditionType := strings.ToLower(strings.TrimSpace(condition.Type))
			if conditionType != "keyword" {
				return fmt.Errorf("decisions[%d].conditions[%d].type %q is unsupported (supported: keyword)", i, j, condition.Type)
			}
			conditionName := strings.TrimSpace(condition.Name)
			if _, exists := keywordSignals[conditionName]; !exists {
				return fmt.Errorf("decisions[%d].conditions[%d] references unknown keyword signal %q", i, j, condition.Name)
			}
		}
	}
	return nil
}

func validateRoutingURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", field)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%s must include a hostname", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain embedded credentials", field)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%s must not contain a URL query", field)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%s must not contain a URL fragment", field)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if isRoutingMetadataHost(host) {
		return fmt.Errorf("%s must not target a link-local or cloud metadata address", field)
	}
	if u.Scheme == "http" && !isRoutingLocalHost(host) {
		return fmt.Errorf("%s must use https for non-local destinations", field)
	}
	return nil
}

// validateRemoteRoutingURL applies the stricter classifier transport policy on
// top of the backend URL checks. Managed mode uses a loopback HTTP endpoint;
// every classifier outside that process-local boundary must use TLS because
// classification requests contain message roles and prompt content.
func validateRemoteRoutingURL(field, raw string) error {
	if err := validateRoutingURL(field, raw); err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimSpace(raw)) // validated above
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if u.Scheme == "http" && !isRoutingLoopbackHost(host) {
		return fmt.Errorf("%s must use https for non-loopback destinations", field)
	}
	return nil
}

func isRoutingLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func isRoutingLocalHost(host string) bool {
	switch host {
	case "localhost", "host.docker.internal", "gateway.docker.internal":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func isRoutingMetadataHost(host string) bool {
	switch host {
	case "metadata.google.internal", "metadata.goog", "instance-data.ec2.internal":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// AWS/Azure IMDS and ECS credentials endpoints, including the IPv6 IMDS
	// address. They stay forbidden even though some are syntactically local.
	for _, raw := range []string{"169.254.169.254", "169.254.170.2", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return true
		}
	}
	return false
}
