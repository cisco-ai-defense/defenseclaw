// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

// r103.GAP-0088: a refused enterprise.network.https_proxy says that the
// proxy takes http:// or https:// and never repeats the configured URL.
func TestEnterpriseProxyRefusalStatesTheSchemeRule(t *testing.T) {
	for _, proxy := range []string{"socks5://proxy.example.test:1080", "proxy.example.test:3128", "http://user:hunter2@proxy.example.test:3128", "http://[proxy.example.test"} {
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone",
			Network: EnterpriseNetworkConfig{HTTPSProxy: proxy}}}
		err := validateEnterpriseConfig(&cfg)
		var semantic *V8SemanticError
		if !errors.As(err, &semantic) || semantic.Path != "$.enterprise.network.https_proxy" {
			t.Fatalf("%s: error = %v, want a semantic error at $.enterprise.network.https_proxy", proxy, err)
		}
		text := semantic.Summary + " " + semantic.Action
		if !strings.Contains(text, "http://") || !strings.Contains(text, "https://") {
			t.Fatalf("%s: refusal %q does not state the scheme rule", proxy, text)
		}
		// The parse error says what is wrong and the Action says what to
		// write, so the joined refusal gives the advice once, in whichever
		// spelling names it (GAP-0114).
		if n := strings.Count(err.Error(), "http://host"); n != 1 {
			t.Fatalf("%s: refusal gives the advice %d times, want once: %v", proxy, n, err)
		}
		if strings.Contains(err.Error(), "proxy.example.test") || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("%s: refusal repeats the configured URL: %v", proxy, err)
		}
	}
}
