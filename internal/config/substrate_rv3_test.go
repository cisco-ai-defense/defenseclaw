// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestB1TemplateEmptyHostsSurviveSaveRV3P23: an explicit hosts: [] (no host
// without an administrator) is kept through a load and a save; an unset
// list stays unset, so a built-in template keeps its hosts.
func TestB1TemplateEmptyHostsSurviveSaveRV3P23(t *testing.T) {
	body := "config_version: 9\nsubstrate:\n  secret_templates:\n  - name: github\n    hosts: []\n  - name: gitlab\n"
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	check := func(stage string, ts []SubstrateSecretTemplate) {
		t.Helper()
		if len(ts) != 2 || ts[0].Hosts == nil || len(ts[0].Hosts) != 0 || ts[1].Hosts != nil {
			t.Fatalf("%s: %#v", stage, ts)
		}
	}
	check("load", cfg.Substrate.SecretTemplates)
	out, err := yaml.Marshal(cfg.Substrate.SecretTemplates)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "hosts: []") || strings.Count(string(out), "hosts") != 1 {
		t.Fatalf("saved:\n%s", out)
	}
	var back []SubstrateSecretTemplate
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	check("yaml round trip", back)
	full, err := yaml.Marshal(map[string]any{"config_version": 9,
		"substrate": map[string]any{"secret_templates": cfg.Substrate.SecretTemplates}})
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadRuntimeV8FromBytes("config.yaml", full)
	if err != nil {
		t.Fatalf("reload saved config: %v", err)
	}
	check("save and reload", again.Substrate.SecretTemplates)
}

// TestB1SelfServiceNamespaceAndBasicUserRV3: the self-service namespace is
// never a Kubernetes system namespace (P3-5), and a template basic_user
// follows the rule every add checks (P3-7).
func TestB1SelfServiceNamespaceAndBasicUserRV3(t *testing.T) {
	for _, ns := range []string{"default", "kube-system", "kube-public", "kube-node-lease"} {
		s := validSubstrate()
		s.SelfServiceSecrets.Namespace = ns
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "self_service_secrets.namespace") {
			t.Errorf("namespace %s: %v", ns, err)
		}
	}
	for user, ok := range map[string]bool{"x-token-auth": true, "a b": false, "a:b": false, strings.Repeat("u", 129): false} {
		s := validSubstrate()
		s.SecretTemplates = []SubstrateSecretTemplate{{Name: "bb", Form: "basic", BasicUser: user}}
		err := s.Validate()
		if ok != (err == nil) || (!ok && !strings.Contains(err.Error(), "secret_templates[0].basic_user")) {
			t.Errorf("basic_user %q: %v", user, err)
		}
	}
}

// TestRV4F7SelfServiceNamespaceNotALauncherAtespace (RV4 F7).
func TestRV4F7SelfServiceNamespaceNotALauncherAtespace(t *testing.T) {
	s := validSubstrate()
	s.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}}
	s.SelfServiceSecrets.Namespace = "eng-web"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "self_service_secrets.namespace") {
		t.Errorf("a launcher atespace as the self-service namespace: %v", err)
	}
}
