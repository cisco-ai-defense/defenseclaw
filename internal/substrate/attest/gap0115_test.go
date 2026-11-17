// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0355 (was GAP-0115's deny list): the image environment check is an
// allowlist. Variables that load code are refused, the four the review ran
// code through among them, and so is any name the list does not know; the
// kit's own variables pass, with the kit's value where it fixes one.
func TestEnvCheckIsAnAllowlist(t *testing.T) {
	for _, c := range []struct {
		k, v string
		ok   bool
	}{
		{"GIT_CONFIG_COUNT", "1", false}, {"GIT_CONFIG_KEY_0", "core.fsmonitor", false}, {"GIT_CONFIG_PARAMETERS", "x", false},
		{"GIT_SSH_COMMAND", "x", false}, {"BASH_FUNC_ls%%", "() { :; }", false}, {"NODE_PATH", "/x", false}, {"PERL5DB", "x", false},
		{"PROMPT_COMMAND", "x", false}, {"ZDOTDIR", "/x", false}, {"LD_PRELOAD", "/x.so", false}, {"ld_preload", "/x.so", false},
		{"SHELLOPTS", "xtrace", false}, {"PS4", "$(id)", false}, {"PERLLIB", "/x", false}, {"GIT_DIR", "/x", false},
		{"XDG_CONFIG_HOME", "/tmp/xdg", false}, {"EDITOR", "vi", false}, {"PAGER", "less", false}, {"MY_SETTING", "1", false},
		{"LC_ALL_X%", "1", false}, {"x_VERSION", "1", false},
		{"PATH", "/usr/bin", true}, {"HOME", "/sandbox", true}, {"LANG", "C.UTF-8", true}, {"LC_ALL", "C.UTF-8", true},
		{"NODE_VERSION", "22.1.0", true}, {"YARN_VERSION", "1.22", true}, {"TERM", "xterm", true}, {"NODE_ENV", "production", true},
		{"PYTHONUNBUFFERED", "1", true}, {"GIT_AUTHOR_NAME", "x", true},
		// The kit's variables, with the kit's fixed value only.
		{"XDG_CONFIG_HOME", kit.XDGConfigHome, true}, {"DISABLE_TELEMETRY", "1", true}, {"DISABLE_TELEMETRY", "0", false},
		{"SSL_CERT_FILE", kit.TrustBundle, true}, {"SSL_CERT_FILE", "/tmp/ca.pem", false},
		{"ANTHROPIC_BASE_URL", "https://gw.example/llm/anthropic", true}, {"ANTHROPIC_API_KEY", kit.PlaceholderSecret, true},
		{"ANTHROPIC_API_KEY", "sk-real", false}, {"npm_config_fund", "false", true},
	} {
		bad := CheckEnv(map[string]string{c.k: c.v})
		if (len(bad) == 0) != c.ok {
			t.Errorf("%s=%s: permitted=%v, want %v (%v)", c.k, c.v, len(bad) == 0, c.ok, bad)
		}
	}
	got := CheckEnv(map[string]string{"GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_COUNT": "1", "PATH": "/bin", "SSL_CERT_FILE": "/x"})
	if s := FormatEnvRefusals(got); s != `GIT_CONFIG_COUNT (not on the allowlist), GIT_CONFIG_KEY_0 (not on the allowlist), SSL_CERT_FILE (the kit sets it to "/run/ate/trust-bundle.pem" only)` {
		t.Fatalf("refusals: %s", s)
	}
	// A refusal never echoes the value it refused.
	if s := FormatEnvRefusals(CheckEnv(map[string]string{"ANTHROPIC_API_KEY": "sk-secret-value"})); strings.Contains(s, "sk-secret") {
		t.Fatalf("the refusal shows the value: %s", s)
	}
}

// GAP-0115: Authorization goes to exactly the first request's scheme, host
// and port; Go would keep it on a subdomain or another port.
func TestRedirectDropsAuthorizationOffTheFirstHost(t *testing.T) {
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "registry.example.com"}}}
	for _, c := range []struct {
		to   string
		keep bool
	}{{"https://registry.example.com/v2/blob", true}, {"https://REGISTRY.example.com/v2/blob", true},
		{"https://registry.example.com:8443/v2/blob", false}, {"https://cdn.registry.example.com/blob", false},
		{"https://storage.example.net/blob", false}} {
		u, _ := url.Parse(c.to)
		req := &http.Request{URL: u, Header: http.Header{"Authorization": {"Bearer secret"}}}
		if err := refuseUnsafeRedirect(req, via); err != nil {
			t.Fatalf("%s: %v", c.to, err)
		}
		if kept := req.Header.Get("Authorization") != ""; kept != c.keep {
			t.Errorf("redirect to %s: Authorization kept=%v, want %v", c.to, kept, c.keep)
		}
	}
}

// GAP-0115: a registry reached over https cannot send the token request to
// a plain-HTTP realm (a loopback service); a plain-HTTP registry still can.
func TestHTTPSRegistryCannotUseAPlainHTTPRealm(t *testing.T) {
	var hits int
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"token":"tok"}`))
	}))
	defer local.Close()
	reg := NewRegistry(RegistryOptions{HTTPClient: local.Client()})
	_, err := reg.fetchToken(context.Background(), "registry.example.com", `Bearer realm="`+local.URL+`/token",service="s"`, "repository:a/b:pull")
	if err == nil || hits != 0 {
		t.Fatalf("an https registry's plain-HTTP realm was asked (hits %d, err %v)", hits, err)
	}
	host := strings.TrimPrefix(local.URL, "http://")
	tok, err := reg.fetchToken(context.Background(), host, `Bearer realm="`+local.URL+`/token"`, "repository:a/b:pull")
	if err != nil || tok != "tok" || hits != 1 {
		t.Fatalf("a loopback registry's own realm: %q %v (hits %d)", tok, err, hits)
	}
}

// GAP-0115: the verifier checks the image environment again with its own
// list, so a template signed when the list was shorter is refused when its
// image sets a variable added since.
func TestVerifyRechecksTheImageEnvironment(t *testing.T) {
	f := newFixture(t)
	saved := envCheck
	envCheck = func(map[string]string) []EnvRefusal { return nil } // the build of an older DefenseClaw
	res, err := f.build(t, func(o *BuildOptions) {
		o.Kit.Env["GIT_CONFIG_COUNT"] = "1"
		o.Kit.Env["GIT_CONFIG_KEY_0"] = "core.fsmonitor"
	})
	envCheck = saved
	if err != nil {
		t.Fatalf("build with the older check: %v", err)
	}
	v, err := f.verifier(nil).Verify(context.Background(), f.m.host()+"/tmpl/claude@"+res.Digest)
	wantCode(t, err, CodeEnvNotPermitted)
	// The refusal is the allowlist's, and the rest of the verdict comes
	// with it: the controller keeps actors admitted before the upgrade.
	if r, _ := AsRejection(err); !r.Allowlist || v == nil || v.Digest != res.Digest || !strings.Contains(r.Detail, "GIT_CONFIG_COUNT (not on the allowlist)") {
		t.Fatalf("allowlist refusal: %+v %+v", r, v)
	}
}
