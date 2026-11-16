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
)

// GAP-0115: variables that make git, a shell or an interpreter load code
// fail the environment check; ordinary settings do not.
func TestEnvCheckCatchesCodeLoadingVariables(t *testing.T) {
	for _, k := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS",
		"GIT_SSH_COMMAND", "BASH_FUNC_ls%%", "NODE_PATH", "PERL5DB", "PROMPT_COMMAND", "ZDOTDIR", "PYTHONUSERBASE",
		"GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "LD_PRELOAD", "git_config_count"} {
		if !envLoadsCode(k) {
			t.Errorf("%s passes the environment check", k)
		}
	}
	for _, k := range []string{"PATH", "HOME", "LANG", "EDITOR", "PAGER", "GIT_EDITOR", "NODE_ENV", "GIT_AUTHOR_NAME", "PYTHONUNBUFFERED", "TERM"} {
		if envLoadsCode(k) {
			t.Errorf("%s is refused, but it loads no code", k)
		}
	}
	got := unsafeEnvOf(map[string]string{"GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_COUNT": "1", "PATH": "/bin"})
	if strings.Join(got, ",") != "GIT_CONFIG_COUNT,GIT_CONFIG_KEY_0" {
		t.Fatalf("unsafeEnvOf: %v", got)
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
	saved := unsafeEnvPrefixes
	unsafeEnvPrefixes = nil // the build of an older DefenseClaw
	res, err := f.build(t, func(o *BuildOptions) {
		o.Kit.Env["GIT_CONFIG_COUNT_X"] = "1"
		o.Kit.Env["GIT_CONFIG_KEY_0"] = "core.fsmonitor"
	})
	unsafeEnvPrefixes = saved
	if err != nil {
		t.Fatalf("build with the older list: %v", err)
	}
	_, err = f.verifier(nil).Verify(context.Background(), f.m.host()+"/tmpl/claude@"+res.Digest)
	wantCode(t, err, CodeEnvUnsafe)
}
