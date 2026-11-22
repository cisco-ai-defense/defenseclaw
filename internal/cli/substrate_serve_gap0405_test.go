// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0405: a secret bound to a host that echoes requests (httpbin on E4)
// hands the real value back to the agent; the gateway says so at start,
// once per secret, naming the echo hosts and never a value or source.
func TestSubstrateEchoHostWarningsGAP0405(t *testing.T) {
	secret := func(name string, hosts ...string) config.SubstrateSecret {
		return config.SubstrateSecret{Name: name, Source: "ate-secret://k8s.io/default/ns/tok-" + name,
			Inject: config.SubstrateSecretInject{Hosts: hosts, Header: "Authorization", Prefix: "Bearer "}}
	}
	lines := substrateEchoHostWarnings([]config.SubstrateSecret{
		secret("github", "api.github.com"),
		secret("j45", "httpbin.org", "eu.httpbin.org", "httpbin.org"),
		secret("hooks", "*.pipedream.net"),
	})
	if len(lines) != 2 {
		t.Fatalf("%d warnings, want 2 (j45, hooks): %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "secret j45 is injected on httpbin.org, *.httpbin.org,") ||
		!strings.Contains(lines[0], "comes back to the agent") || strings.Contains(lines[0], "ate-secret://") {
		t.Errorf("j45 warning %q", lines[0])
	}
	if !strings.Contains(lines[1], "secret hooks is injected on *.pipedream.net") {
		t.Errorf("hooks warning %q", lines[1])
	}
	if got := substrateEchoHostWarnings(nil); got != nil {
		t.Errorf("warnings with no secrets: %q", got)
	}
}
