// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"embed"
	"strings"
	"testing"
)

// GAP-1190: every hook and shim request to the loopback gateway runs curl with
// --noproxy '*', so an HTTP_PROXY/HTTPS_PROXY in the agent's environment can
// neither break enforcement nor receive the bearer token and tool payload.
func TestHookAndShimGatewayCallsBypassProxy(t *testing.T) {
	for _, set := range []struct {
		fs  embed.FS
		dir string
	}{{hookFS, "hooks"}, {shimFS, "shims"}} {
		entries, err := set.fs.ReadDir(set.dir)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".sh") {
				continue
			}
			body, err := set.fs.ReadFile(set.dir + "/" + entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if set.dir == "shims" {
				if !strings.Contains(string(body), `_dc_shim_post "`) || strings.Contains(string(body), `http://${_DC_SHIM_ADDR}`) {
					t.Errorf("%s/%s bypasses the account-bound native gateway transport", set.dir, entry.Name())
				}
				calls++
				continue
			}
			for n, line := range strings.Split(string(body), "\n") {
				// The native helper parses the URL to obtain a path, then
				// proves the connected socket before sending any HTTP bytes.
				if strings.Contains(line, `_dc_post_prefix="http://${API_ADDR}"`) {
					if !strings.Contains(string(body), `hook-post --api-addr "$API_ADDR"`) {
						t.Errorf("%s/%s has no connected-peer native post", set.dir, entry.Name())
					}
					continue
				}
				if strings.HasPrefix(strings.TrimSpace(line), "#") ||
					(!strings.Contains(line, "http://${API_ADDR}") && !strings.Contains(line, "http://${_DC_SHIM_ADDR}")) {
					continue
				}
				calls++
				// defenseclaw_gateway_post (_hardening.sh, checked below)
				// runs curl with --noproxy '*' for every hook request.
				if !strings.Contains(line, "--noproxy '*'") && !strings.Contains(line, `defenseclaw_gateway_post "http://${API_ADDR}`) {
					t.Errorf("%s/%s:%d sends a gateway request without --noproxy '*': %s", set.dir, entry.Name(), n+1, strings.TrimSpace(line))
				}
			}
		}
		if calls == 0 {
			t.Fatalf("no gateway requests found under %s", set.dir)
		}
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hardening), `curl -q -s --noproxy '*' -w '\n%{http_code}' -X POST "$_dc_post_url"`) {
		t.Fatal("defenseclaw_gateway_post sends hook requests without -q first and --noproxy '*'")
	}
}
