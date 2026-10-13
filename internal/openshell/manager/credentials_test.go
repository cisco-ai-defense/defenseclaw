// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestCredentialRefusalProviderGrammar(t *testing.T) {
	for _, c := range []struct{ provider, noun string }{
		{"openai", "an openai credential"}, {"anthropic", "an anthropic credential"}, {"amp", "an amp credential"},
		{"echo", "an echo credential"}, {"iris", "an iris credential"}, {"umbrella", "an umbrella credential"},
		{"bedrock", "a bedrock credential"}, {"github", "a github credential"}, {"claude-oauth", "a claude-oauth credential"},
		{"cursor", "a cursor credential"}, {"kiro", "a kiro credential"}, {"gemini", "a gemini credential"},
		{"credential", "a custom credential"},
	} {
		custom := c.provider == credentialProviderCustom
		profile := "defenseclaw-" + c.provider
		if custom {
			profile = ""
		}
		v := credentialsRefusal(config.OpenShellAdminConfig{AllowedCredentials: []string{"allowed-provider"}}, profile, custom)
		if v == nil || !strings.Contains(v.Detail, "delivers "+c.noun+",") {
			t.Errorf("%s: refusal = %+v, want %q", c.provider, v, c.noun)
		}
	}
}
