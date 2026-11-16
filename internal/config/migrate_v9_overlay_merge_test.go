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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// GAP-0709: a provider that the legacy custom-providers.json names twice
// becomes one entry with the 0.8.x overlay merge rules (configs.ApplyOverlay:
// the lists are unioned and the later entry's values win); one that
// llm_providers.custom already has takes the overlay's other items and the
// fields config leaves unset (config's values were the ones in use, GAP-0163;
// a field both set differently is refused, see
// TestMigrateV9KeepsAConflictingOverlayOutOfAV8Migration). The migration
// skipped the second entry, so its domains, env keys and settings were lost
// when the overlay was retired.
func TestMigrateV9MergesSameNameOverlayProviders(t *testing.T) {
	type tlsBlock struct {
		CACertFile string `yaml:"ca_cert_file"`
	}
	type provider struct {
		Name                 string            `yaml:"name"`
		Domains              []string          `yaml:"domains"`
		EnvKeys              []string          `yaml:"env_keys"`
		BaseURL              string            `yaml:"base_url"`
		AllowedRequests      []string          `yaml:"allowed_requests"`
		AvailableModels      []string          `yaml:"available_models"`
		RequestPathOverrides map[string]string `yaml:"request_path_overrides"`
		ExtraHeaders         map[string]string `yaml:"extra_headers"`
		TLS                  *tlsBlock         `yaml:"tls"`
	}
	cases := []struct {
		name    string
		config  string // the llm_providers block of the v8 source
		overlay string
		want    provider
		ca      string // the CA file the entry pins, "" for none
	}{
		{
			name: "named twice in the overlay",
			overlay: `{"providers":[
  {"name":"acme","domains":["llm.acme.internal"],"env_keys":["ACME_KEY"],"base_url":"https://llm.acme.internal/v1",
   "available_models":["acme-small"],"request_path_overrides":{"chat":"/v1/chat"}},
  {"name":"ACME","domains":["llm.acme.internal","eu.llm.acme.internal"],"env_keys":["ACME_EU_KEY"],
   "base_url":"https://eu.llm.acme.internal/v1","allowed_requests":["chat"],
   "request_path_overrides":{"chat":"/eu/chat","embed":"/v1/embed"},"extra_headers":{"x-team":"sec"}}
 ]}`,
			want: provider{
				Name: "acme", Domains: []string{"llm.acme.internal", "eu.llm.acme.internal"},
				EnvKeys: []string{"ACME_KEY", "ACME_EU_KEY"}, BaseURL: "https://eu.llm.acme.internal/v1",
				AllowedRequests: []string{"chat"}, AvailableModels: []string{"acme-small"},
				RequestPathOverrides: map[string]string{"chat": "/eu/chat", "embed": "/v1/embed"},
				ExtraHeaders:         map[string]string{"x-team": "sec"},
			},
		},
		{
			name: "already in llm_providers.custom",
			config: "llm_providers:\n  custom:\n  - name: acme\n    domains: [llm.acme.internal]\n    env_keys: [ACME_KEY]\n" +
				"    base_url: https://llm.acme.internal/v1\n    available_models: [acme-small]\n",
			overlay: `{"providers":[{"name":"Acme","domains":["eu.llm.acme.internal"],"env_keys":["ACME_EU_KEY"],
   "base_url":"https://llm.acme.internal/v1","allowed_requests":["chat"],"extra_headers":{"x-team":"sec"}}]}`,
			want: provider{
				Name: "acme", Domains: []string{"llm.acme.internal", "eu.llm.acme.internal"},
				EnvKeys: []string{"ACME_KEY", "ACME_EU_KEY"}, BaseURL: "https://llm.acme.internal/v1",
				ExtraHeaders:    map[string]string{"x-team": "sec"},
				AllowedRequests: []string{"chat"}, AvailableModels: []string{"acme-small"},
			},
		},
		{
			name: "the later tls replaces the earlier CA",
			overlay: `{"providers":[
  {"name":"acme","domains":["llm.acme.internal"],"tls":{"ca_cert_pem":"first certificate"}},
  {"name":"acme","env_keys":["ACME_KEY"],"tls":{"ca_cert_pem":"second certificate"}}
 ]}`,
			want: provider{Name: "acme", Domains: []string{"llm.acme.internal"}, EnvKeys: []string{"ACME_KEY"}},
			ca:   "second certificate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			configPath := filepath.Join(dir, "config.yaml")
			source := "config_version: 8\ndata_dir: " + dir + "\n" + tc.config + "observability: {}\n"
			if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(dir, ProvidersOverlayFile)
			if err := os.WriteFile(overlay, []byte(tc.overlay), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("MigrateV9: %v", err)
			}
			var got struct {
				LLMProviders struct {
					Custom []provider `yaml:"custom"`
				} `yaml:"llm_providers"`
			}
			if err := yaml.Unmarshal(result.Migrated, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.LLMProviders.Custom) != 1 {
				t.Fatalf("llm_providers.custom has %d entries, want one merged entry:\n%s", len(got.LLMProviders.Custom), result.Migrated)
			}
			entry := got.LLMProviders.Custom[0]
			tls := entry.TLS
			entry.TLS = nil
			if !reflect.DeepEqual(entry, tc.want) {
				t.Errorf("merged provider =\n  %+v\nwant\n  %+v", entry, tc.want)
			}
			if tc.ca == "" {
				if tls != nil && tls.CACertFile != "" {
					t.Errorf("provider pins CA %s, want none", tls.CACertFile)
				}
			} else if tls == nil || tls.CACertFile == "" {
				t.Errorf("provider pins no CA, want %q", tc.ca)
			} else if raw, err := os.ReadFile(tls.CACertFile); err != nil || string(raw) != tc.ca {
				t.Errorf("CA %s = %q (%v), want %q", tls.CACertFile, raw, err, tc.ca)
			}
			if _, err := os.Stat(overlay); !os.IsNotExist(err) {
				t.Errorf("the legacy overlay is still a live input: %v", err)
			}
		})
	}
}

// #1099: every field a legacy overlay entry can set reaches the migrated
// llm_providers.custom entry when the overlay names the provider twice; the
// migrated config reads back field by field.
func TestMigrateV9SameNameOverlayKeepsEveryField(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\ndata_dir: "+dir+"\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := `{"providers":[
  {"name":"acme","domains":["llm.acme.internal"],"profile_id":"acme-team","env_keys":["ACME_KEY"],
   "base_provider_type":"openai","base_url":"https://llm.acme.internal/v1","allowed_requests":["chat"],
   "available_models":["acme-small"],"request_path_overrides":{"chat":"/v1/chat"},"extra_headers":{"X-Team":"sec"},
   "bedrock":{"region":"us-east-1","auth_mode":"iam_credentials","access_key_env":"AK","secret_key_env":"SK","session_token_env":"ST",
     "profile_name":"lab","inference_profile":"us","deployment_aliases":{"small":"model-small"}}},
  {"name":"ACME","env_keys":["ACME_EU_KEY"],"available_models":["acme-large"],"extra_headers":{"X-Route":"eu"},
   "tls":{"insecure_skip_verify":true},
   "vertex":{"project_id":"lab-project","region":"us-central1","auth_mode":"adc","service_account_json_env":"SA_JSON"},
   "azure":{"endpoint":"https://acme.openai.azure.example","api_version":"2026-01-01","auth_mode":"api_key",
     "deployment_aliases":{"gpt":"acme-gpt"}}}
 ]}`
	if err := os.WriteFile(filepath.Join(dir, ProvidersOverlayFile), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	cfg, err := LoadRuntimeV8FromBytes(configPath, result.Migrated)
	if err != nil {
		t.Fatalf("load the migrated config: %v\n%s", err, result.Migrated)
	}
	want := []LLMCustomProvider{{
		Name: "acme", Domains: []string{"llm.acme.internal"}, ProfileID: "acme-team", EnvKeys: []string{"ACME_KEY", "ACME_EU_KEY"},
		BaseProviderType: "openai", BaseURL: "https://llm.acme.internal/v1", AllowedRequests: []string{"chat"},
		AvailableModels: []string{"acme-small", "acme-large"}, RequestPathOverrides: map[string]string{"chat": "/v1/chat"},
		TLS: &LLMCustomProviderTLS{InsecureSkipVerify: true},
		Bedrock: &BedrockKeyConfig{Region: "us-east-1", AuthMode: "iam_credentials", AccessKeyEnv: "AK", SecretKeyEnv: "SK", SessionTokenEnv: "ST",
			ProfileName: "lab", InferenceProfile: "us", DeploymentAliases: map[string]string{"small": "model-small"}},
		Vertex: &VertexKeyConfig{ProjectID: "lab-project", Region: "us-central1", AuthMode: "adc", ServiceAccountJSONEnv: "SA_JSON"},
		Azure: &AzureKeyConfig{Endpoint: "https://acme.openai.azure.example", APIVersion: "2026-01-01", AuthMode: "api_key",
			DeploymentAliases: map[string]string{"gpt": "acme-gpt"}},
		ExtraHeaders: map[string]string{"X-Team": "sec", "X-Route": "eu"},
	}}
	if got := cfg.LLMProviders.Custom; !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated llm_providers.custom =\n  %+v\nwant\n  %+v\n%s", got, want, result.Migrated)
	}
}
