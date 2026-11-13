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
	"sync"
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
// target OS. Managed Windows route-only is valid: the guardian renders it
// per enrolled user and its peer SID broker proves each caller (S1 DESIGN
// 21, rel-1-0-10:GAP-0012).
func validateManagedRouting(cfg *Config, goos string) error {
	r := cfg.Routing
	for i, m := range r.Models {
		if strings.TrimSpace(m.APIKeyEnv) != "" && strings.TrimSpace(m.Credential) == "" {
			// 1.0.9 and 1.0.8 managed configs carry api_key_env models (the
			// vllm_sr era), with routing on or off. They keep their meaning
			// after the upgrade (owner rule: the upgrade must work): the
			// gateway still reads the named variable when no credential is
			// set, and doctor asks for a protected credential instead.
			warnManagedRoutingOnce(fmt.Sprintf("warning: config routing.models[%d].api_key_env reads the gateway service environment on a managed host; store the key with enterprise secret set and name it in routing.models[%d].credential\n", i, i))
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
	// Managed Windows: the guardian peer SID broker proves the account of
	// each loopback caller (S1 Q7); the gateway refuses every route-only
	// caller while the broker does not answer (doctor: Route-only peer
	// broker), so the config itself is valid there.
	for i, c := range r.RouteOnly.Connectors {
		if goos != "" && !RouteOnlyCapableOn(c, goos) {
			return fmt.Errorf("config routing.route_only.connectors[%d] %q has no routing base_url capability on %s", i, c, goos)
		}
	}
	return nil
}

// managedRoutingWarnings receives the managed routing notes; replaceable in
// tests.
var managedRoutingWarnings io.Writer = os.Stderr

var (
	managedRoutingWarnedMu sync.Mutex
	managedRoutingWarned   = map[string]bool{}
)

// warnManagedRoutingOnce prints a note once per process (validation runs on
// every ensure and reload); doctor keeps reporting it.
func warnManagedRoutingOnce(msg string) {
	managedRoutingWarnedMu.Lock()
	defer managedRoutingWarnedMu.Unlock()
	if managedRoutingWarned[msg] && managedRoutingWarnings == os.Stderr {
		return
	}
	managedRoutingWarned[msg] = true
	fmt.Fprint(managedRoutingWarnings, msg)
}

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
