// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net/http"
	"net/url"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

// GAP-1655: with a proxy set, the instance-metadata endpoints join NO_PROXY
// (keeping what is there), so an AWS credential lookup never goes through
// the proxy; nothing changes without a proxy or with NO_PROXY=*.
func TestExemptInstanceMetadataFromProxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want map[string]string
	}{
		{
			name: "no proxy",
			env:  map[string]string{"NO_PROXY": "corp.example"},
			want: map[string]string{"NO_PROXY": "corp.example"},
		},
		{
			name: "proxy without exclusions",
			env:  map[string]string{"HTTPS_PROXY": "http://127.0.0.1:3128"},
			want: map[string]string{
				"HTTPS_PROXY": "http://127.0.0.1:3128",
				"NO_PROXY":    "169.254.169.254,169.254.170.2,fd00:ec2::254",
				"no_proxy":    "169.254.169.254,169.254.170.2,fd00:ec2::254",
			},
		},
		{
			name: "lower-case exclusions are kept",
			env:  map[string]string{"http_proxy": "http://p:1", "no_proxy": "corp.example,169.254.169.254"},
			want: map[string]string{
				"http_proxy": "http://p:1",
				"NO_PROXY":   "corp.example,169.254.169.254,169.254.170.2,fd00:ec2::254",
				"no_proxy":   "corp.example,169.254.169.254,169.254.170.2,fd00:ec2::254",
			},
		},
		{
			name: "everything already direct",
			env:  map[string]string{"HTTPS_PROXY": "http://p:1", "NO_PROXY": "*", "no_proxy": "*"},
			want: map[string]string{"HTTPS_PROXY": "http://p:1", "NO_PROXY": "*", "no_proxy": "*"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range tc.env {
				env[k] = v
			}
			err := ExemptInstanceMetadataFromProxy(
				func(key string) string { return env[key] },
				func(key, value string) error { env[key] = value; return nil },
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(env) != len(tc.want) {
				t.Fatalf("env = %v, want %v", env, tc.want)
			}
			for k, v := range tc.want {
				if env[k] != v {
					t.Fatalf("%s = %q, want %q (env %v)", k, env[k], v, env)
				}
			}
			if (env["HTTPS_PROXY"] == "" && env["http_proxy"] == "") || env["NO_PROXY"] == "*" {
				return
			}
			selector := (&httpproxy.Config{
				HTTPProxy: "http://p:1", HTTPSProxy: "http://p:1", NoProxy: env["NO_PROXY"],
			}).ProxyFunc()
			for _, raw := range []string{"http://169.254.169.254/latest/api/token", "http://[fd00:ec2::254]/latest/api/token", "http://169.254.170.2/v2/credentials"} {
				target, _ := url.Parse(raw)
				if proxy, _ := selector(target); proxy != nil {
					t.Fatalf("%s goes through %s, want direct", raw, proxy)
				}
			}
			request, _ := http.NewRequest(http.MethodGet, "https://bedrock-runtime.us-east-1.amazonaws.com/", nil)
			if proxy, _ := selector(request.URL); proxy == nil {
				t.Fatal("other destinations must still use the proxy")
			}
		})
	}
}
