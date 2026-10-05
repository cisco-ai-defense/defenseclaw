// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// applyStandaloneEgress routes a standalone gateway process through the
// administrator's enterprise.network proxy before it builds any outbound
// client. The gateway's own clients (Bifrost LLM calls, the passthrough,
// webhooks, the remote model router and the telemetry exporters) build
// their connections themselves and take the proxy from
// gateway.SetEnterpriseEgress; the AI Defense client uses
// EgressProxy().Transport(); clients on Go's default transport (and the
// Bedrock SDK transport) take it from the process environment.
//
// In every profile the instance-metadata endpoints are added to NO_PROXY
// when a proxy variable is set, so a Bedrock instance-role credential lookup
// never goes through the proxy (GAP-1655), and the telemetry exporters take
// HTTPS_PROXY/NO_PROXY from the environment when no enterprise proxy is set
// (GAP-1465).
func applyStandaloneEgress(cfg *config.Config) error {
	if err := applyStandaloneEgressEnvironment(cfg, os.Setenv); err != nil {
		return err
	}
	if err := netguard.ExemptInstanceMetadataFromProxy(os.Getenv, os.Setenv); err != nil {
		return err
	}
	return gateway.SetEnterpriseEgress(cfg)
}

// applyStandaloneEgressEnvironment puts the administrator's enterprise.network
// proxy into a standalone gateway's process environment for the clients
// that select their proxy with http.ProxyFromEnvironment. The Unix
// lifecycles put the same variables into the gateway unit and plist, but the
// Windows service environment does not carry them, so the gateway sets them
// itself before it builds any client (http.ProxyFromEnvironment reads the
// environment once per process). Only the variables the config names are
// set, and nothing changes outside the standalone profile.
func applyStandaloneEgressEnvironment(cfg *config.Config, setenv func(key, value string) error) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	proxy := cfg.Enterprise.EgressProxy()
	if proxy.HTTPSProxy != "" {
		if _, err := netguard.ParseEgressProxyURL(proxy.HTTPSProxy); err != nil {
			return fmt.Errorf("enterprise.network.https_proxy: %w", err)
		}
	}
	env := proxy.Environment()
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := setenv(key, env[key]); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}
