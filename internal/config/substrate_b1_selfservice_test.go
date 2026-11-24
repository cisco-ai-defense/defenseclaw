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
	"time"
)

func TestB1SelfServiceSecretsValidate(t *testing.T) {
	ok := validSubstrate()
	ok.SelfServiceSecrets = SubstrateSelfServiceSecretsConfig{Mode: SelfServiceValuesOnly, Namespace: "team-secrets",
		Provider: "k8s-credential-provider", MaxPerPerson: 200, OutsideTemplates: "refuse", AskTimeout: "168h"}
	ok.SecretTemplates = []SubstrateSecretTemplate{{Name: "gitlab", Hosts: []string{"*.corp.example"}},
		{Name: "jira", Hosts: []string{"jira.corp.example"}, Form: "raw", Header: "X-Api-Key", Profiles: []string{"eng-*"}, Registry: "none"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid self-service config refused: %v", err)
	}
	cases := map[string]func(*SubstrateConfig){
		"self_service_secrets.mode":              func(s *SubstrateConfig) { s.SelfServiceSecrets.Mode = "on" },
		"self_service_secrets.namespace":         func(s *SubstrateConfig) { s.SelfServiceSecrets.Namespace = "Team_Secrets" },
		"self_service_secrets.provider":          func(s *SubstrateConfig) { s.SelfServiceSecrets.Provider = "bad provider" },
		"self_service_secrets.max_per_person":    func(s *SubstrateConfig) { s.SelfServiceSecrets.MaxPerPerson = 201 },
		"self_service_secrets.outside_templates": func(s *SubstrateConfig) { s.SelfServiceSecrets.OutsideTemplates = "allow" },
		"self_service_secrets.ask_timeout":       func(s *SubstrateConfig) { s.SelfServiceSecrets.AskTimeout = "169h" },
		"secret_templates[1].name":               func(s *SubstrateConfig) { s.SecretTemplates[1].Name = "gitlab" },
		"secret_templates[0].form":               func(s *SubstrateConfig) { s.SecretTemplates[0].Form = "digest" },
		"secret_templates[0].registry":           func(s *SubstrateConfig) { s.SecretTemplates[0].Registry = "maven" },
		"secret_templates[0].header":             func(s *SubstrateConfig) { s.SecretTemplates[0].Header = "Bad Header" },
		"secret_templates[0].hosts":              func(s *SubstrateConfig) { s.SecretTemplates[0].Hosts = []string{"http://x"} },
		"secret_templates[1].profiles[0]":        func(s *SubstrateConfig) { s.SecretTemplates[1].Profiles = []string{"eng-["} },
	}
	for want, edit := range cases {
		s := ok
		s.SelfServiceSecrets = ok.SelfServiceSecrets
		s.SecretTemplates = append([]SubstrateSecretTemplate(nil), ok.SecretTemplates...)
		edit(&s)
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

func TestB1SelfServiceSecretsDefaults(t *testing.T) {
	var ss SubstrateSelfServiceSecretsConfig
	if ss.EffectiveMode() != SelfServiceBindings || ss.EffectiveNamespace() != "defenseclaw-user-secrets" ||
		ss.EffectiveMaxPerPerson() != 20 || ss.EffectiveOutsideTemplates() != "ask" || ss.EffectiveAskTimeout() <= 0 ||
		ss.EffectiveAskTimeout() > 168*time.Hour {
		t.Fatalf("defaults: mode %s ns %s max %d outside %s timeout %s", ss.EffectiveMode(), ss.EffectiveNamespace(),
			ss.EffectiveMaxPerPerson(), ss.EffectiveOutsideTemplates(), ss.EffectiveAskTimeout())
	}
}
