// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
)

// routeOnlyBaseURLOS lists, per route-capable connector, the OSes whose
// agent build takes a model base URL (capability routing base_url).
var routeOnlyBaseURLOS = map[string][]string{
	"claudecode": {"linux", "darwin", "windows"},
	"codex":      {"linux", "darwin", "windows"},
}

// RouteOnlyCapableOn reports whether connector has capability routing
// base_url on goos.
func RouteOnlyCapableOn(connector, goos string) bool {
	return slices.Contains(routeOnlyBaseURLOS[strings.ToLower(strings.TrimSpace(connector))], goos)
}

// validateManagedRouting checks the routing keys of a standalone config
// for goos (S1 DESIGN 15.6, 17.1, 19): secrets come from protected
// credential refs only (no *_env names, which would read the gateway
// service environment), route-only connectors need routing base_url on the
// target OS, and managed Windows route-only stays off until the Windows
// kernel peer factor works under the gateway service account and the
// Windows guardian renders route-only per user (rel-1-0-10:GAP-0012).
func validateManagedRouting(cfg *Config, goos string) error {
	r := cfg.Routing
	for i, m := range r.Models {
		if strings.TrimSpace(m.APIKeyEnv) != "" {
			// 1.0.9 managed configs may carry api_key_env models with
			// routing off (the vllm_sr era); the gateway ignores the name on
			// a managed host (credential refs only), so only a config that
			// turns routing on is refused (S1 REVIEW-code-slice4 P2-1).
			if r.Enabled {
				return fmt.Errorf("config routing.models[%d].api_key_env is not allowed on a managed host with routing.enabled: name a protected credential in routing.models[%d].credential", i, i)
			}
			fmt.Fprintf(managedRoutingWarnings, "warning: config routing.models[%d].api_key_env is ignored on a managed host; name a protected credential in routing.models[%d].credential before turning routing on\n", i, i)
		}
		if err := managedBedrockEnvRefusal(fmt.Sprintf("routing.models[%d].bedrock", i), m.Bedrock); err != nil {
			return err
		}
	}
	if r.SystemOne != nil && strings.TrimSpace(r.SystemOne.APIKeyEnv) != "" {
		return fmt.Errorf("config routing.systemone.api_key_env is not allowed on a managed host: name a protected credential in routing.systemone.credential")
	}
	names := make([]string, 0, len(r.RouteOnly.Upstreams))
	for name := range r.RouteOnly.Upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := managedBedrockEnvRefusal("routing.route_only.upstreams."+name+".bedrock", r.RouteOnly.Upstreams[name].Bedrock); err != nil {
			return err
		}
	}
	if len(r.RouteOnly.Connectors) == 0 {
		return nil
	}
	if goos == "windows" {
		return fmt.Errorf("config routing.route_only is not available on managed Windows in this release (windows_no_peer_factor): the gateway service cannot yet prove which account opened a loopback connection; route proxy traffic only, or use route-only on managed Linux and macOS")
	}
	for i, c := range r.RouteOnly.Connectors {
		if goos != "" && !RouteOnlyCapableOn(c, goos) {
			return fmt.Errorf("config routing.route_only.connectors[%d] %q has no routing base_url capability on %s", i, c, goos)
		}
	}
	return nil
}

// managedRoutingWarnings receives the notes of keys a managed host
// ignores; replaceable in tests.
var managedRoutingWarnings io.Writer = os.Stderr

// managedBedrockEnvRefusal refuses the Bedrock keys new in 1.0.10 that
// read the gateway service environment or its account files: every *_env
// name, and auth profile (a shared AWS profile of the service account;
// managed hosts use *_credential refs or instance_role, DESIGN 15.6).
func managedBedrockEnvRefusal(field string, b *RoutingBedrockAuthConfig) error {
	if b == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(b.Auth), RoutingBedrockAuthProfile) {
		return fmt.Errorf("config %s.auth profile is not allowed on a managed host: use iam_credentials with *_credential names, or instance_role", field)
	}
	for key, v := range map[string]string{"access_key_env": b.AccessKeyEnv, "secret_key_env": b.SecretKeyEnv, "session_token_env": b.SessionTokenEnv} {
		if strings.TrimSpace(v) != "" {
			return fmt.Errorf("config %s.%s is not allowed on a managed host: use the matching *_credential name", field, key)
		}
	}
	return nil
}
