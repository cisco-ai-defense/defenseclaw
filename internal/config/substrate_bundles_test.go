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
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSubstrateBundlesConfigMatchesTheClosedSchema(t *testing.T) {
	got := yamlFieldNames(reflect.TypeOf(SubstrateBundlesConfig{}))
	if want := schemaObjectProperties(t, "substrate", "bundles"); !reflect.DeepEqual(got, want) {
		t.Fatalf("SubstrateBundlesConfig yaml keys = %v, schema = %v", got, want)
	}
}

const substrateBundlesExample = `config_version: 9
substrate:
  bundles:
    enabled: true
    anchors_file: /etc/defenseclaw-substrate/bundle-anchors/bundle-anchors.json
    inbox: team-bundles
    refresh_interval: 30s
`

func TestSubstrateBundlesExampleValidates(t *testing.T) {
	if err := ValidateV8SchemaBytes("substrate.yaml", []byte(substrateBundlesExample)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	b := SubstrateBundlesConfig{Enabled: true, Inbox: "team-bundles", RefreshInterval: "30s"}
	s := SubstrateConfig{Bundles: b}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if b.EffectiveInbox() != "team-bundles" || b.EffectiveRefreshInterval() != 30*time.Second ||
		b.EffectiveAnchorsFile() != DefaultSubstrateBundleAnchors {
		t.Fatalf("effective values: %q %v %q", b.EffectiveInbox(), b.EffectiveRefreshInterval(), b.EffectiveAnchorsFile())
	}
	var zero SubstrateBundlesConfig
	if zero.EffectiveInbox() != DefaultSubstrateBundleInbox || zero.EffectiveRefreshInterval() != DefaultSubstrateBundleRefresh {
		t.Fatal("defaults")
	}
}

func TestSubstrateBundlesValidateNamesTheKey(t *testing.T) {
	for name, tc := range map[string]struct {
		b   SubstrateBundlesConfig
		key string
	}{
		"relative anchors": {SubstrateBundlesConfig{AnchorsFile: "anchors.json"}, "bundles.anchors_file"},
		"bad inbox":        {SubstrateBundlesConfig{Inbox: "Team_Bundles"}, "bundles.inbox"},
		"bad interval":     {SubstrateBundlesConfig{RefreshInterval: "soon"}, "bundles.refresh_interval"},
		"too fast":         {SubstrateBundlesConfig{RefreshInterval: "100ms"}, "bundles.refresh_interval"},
	} {
		s := SubstrateConfig{Bundles: tc.b}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: err = %v, want one naming %s", name, err, tc.key)
		}
	}
}

// GAP-0437: substrate.bundles.oci is closed like its parent, refuses tags
// and relative files, and is off unless it names a stage.
func TestGAP0437SubstrateBundlesOCIValidate(t *testing.T) {
	if got, want := yamlFieldNames(reflect.TypeOf(SubstrateBundleOCIConfig{})), schemaObjectProperties(t, "substrate", "bundles", "oci"); !reflect.DeepEqual(got, want) {
		t.Fatalf("SubstrateBundleOCIConfig yaml keys = %v, schema = %v", got, want)
	}
	ref := "registry.example.com/policy/prod@sha256:" + strings.Repeat("ab", 32)
	good := SubstrateBundleOCIConfig{Enabled: true, CAFile: filepath.Join(t.TempDir(), "ca.pem"), Timeout: "45s",
		Stages: []SubstrateBundleOCIStage{{Stage: "prod", Ref: ref, Atespaces: []string{"team-a"}}}}
	s := SubstrateConfig{Bundles: SubstrateBundlesConfig{OCI: good}}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if good.EffectiveTimeout() != 45*time.Second || (SubstrateBundleOCIConfig{}).EffectiveTimeout() != DefaultSubstrateBundleOCITimeout {
		t.Fatal("timeout")
	}
	for name, tc := range map[string]struct {
		o   SubstrateBundleOCIConfig
		key string
	}{
		"tag ref":          {SubstrateBundleOCIConfig{Stages: []SubstrateBundleOCIStage{{Stage: "prod", Ref: "registry.example.com/policy/prod:v7"}}}, "bundles.oci.stages[0].ref"},
		"no host":          {SubstrateBundleOCIConfig{Stages: []SubstrateBundleOCIStage{{Stage: "prod", Ref: "policy/prod@sha256:" + strings.Repeat("ab", 32)}}}, "bundles.oci.stages[0].ref"},
		"duplicate stage":  {SubstrateBundleOCIConfig{Stages: []SubstrateBundleOCIStage{{Stage: "prod", Ref: ref}, {Stage: "prod", Ref: ref}}}, "bundles.oci.stages[1].stage"},
		"relative ca":      {SubstrateBundleOCIConfig{CAFile: "ca.pem"}, "bundles.oci.ca_file"},
		"relative creds":   {SubstrateBundleOCIConfig{CredentialsFile: "config.json"}, "bundles.oci.credentials_file"},
		"auth host url":    {SubstrateBundleOCIConfig{AuthHosts: []string{"https://auth.docker.io/token"}}, "bundles.oci.auth_hosts[0]"},
		"timeout too long": {SubstrateBundleOCIConfig{Timeout: "10m"}, "bundles.oci.timeout"},
		"on, no stage":     {SubstrateBundleOCIConfig{Enabled: true}, "bundles.oci.stages"},
	} {
		s := SubstrateConfig{Bundles: SubstrateBundlesConfig{OCI: tc.o}}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: err = %v, want one naming %s", name, err, tc.key)
		}
	}
}
