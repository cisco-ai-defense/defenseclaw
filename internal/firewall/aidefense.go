// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"net/url"
	"strings"
)

// aiDefenseDefaultHost is the origin the inspection client itself falls back
// to when no endpoint is configured. The allowlist names the same host so a
// default deployment cannot block its own inspection traffic.
const aiDefenseDefaultHost = "us.api.inspect.aidefense.security.cisco.com"

// AIDefenseAllowlistHost reports the host an egress allowlist has to carry for
// a configured Cisco AI Defense endpoint. Deployments on a non-US region or on
// the preview tenant inspect through a different host, so a fixed entry would
// deny exactly the traffic those deployments depend on.
func AIDefenseAllowlistHost(endpoint string) string {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return aiDefenseDefaultHost
	}
	if !strings.Contains(trimmed, "://") {
		// A scheme-less value still names the host the operator meant.
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Hostname() == "" {
		return aiDefenseDefaultHost
	}
	return parsed.Hostname()
}

// MergeAIDefenseEndpoint adds the configured inspection host to the allowlist.
// Callers that hold the deployment config use this so the firewall follows the
// endpoint instead of assuming the default region.
func (c *FirewallConfig) MergeAIDefenseEndpoint(endpoint string) *FirewallConfig {
	return c.MergeAllowedHosts([]string{AIDefenseAllowlistHost(endpoint)})
}
