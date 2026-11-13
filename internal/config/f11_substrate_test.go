// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseECRRegistryHost(t *testing.T) {
	for host, want := range map[string][3]string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com":         {"123456789012", "us-east-1", ""},
		"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com": {"123456789012", "us-gov-west-1", "fips"},
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn":     {"123456789012", "cn-north-1", ""},
	} {
		acct, region, fips, ok := ParseECRRegistryHost(host)
		if !ok || acct != want[0] || region != want[1] || fips != (want[2] == "fips") {
			t.Errorf("%s = %s %s %v %v", host, acct, region, fips, ok)
		}
	}
	for _, host := range []string{"", "ghcr.io", "123.dkr.ecr.us-east-1.amazonaws.com",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com:443", "123456789012.dkr.ecr.us-east-1.amazonaws.com.evil.example",
		"public.ecr.aws", "x123456789012.dkr.ecr.us-east-1.amazonaws.com"} {
		if _, _, _, ok := ParseECRRegistryHost(host); ok {
			t.Errorf("%q is not an ECR registry host", host)
		}
	}
}

// GAP-0190 (registry_auth) and GAP-0191 (admin_groups): the new keys load
// from YAML and are validated.
func TestSubstrateRegistryAuthAndAdminGroupsKeys(t *testing.T) {
	var s SubstrateConfig
	if err := yaml.Unmarshal([]byte(`
identity:
  oidc: {issuer: https://sso.example.com, client_id: dc}
  admin_groups: [dc-admins, platform]
templates:
  registry_auth:
    docker_config: /etc/defenseclaw/substrate/registry-auth/config.json
    ecr_hosts: [123456789012.dkr.ecr.us-east-1.amazonaws.com]
`), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Identity.AdminGroups) != 2 ||
		s.Templates.RegistryAuth.DockerConfig == "" || len(s.Templates.RegistryAuth.ECRHosts) != 1 {
		t.Fatalf("loaded %+v %+v", s.Identity, s.Templates.RegistryAuth)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid keys refused: %v", err)
	}

	for key, mut := range map[string]func(*SubstrateConfig){
		"templates.registry_auth.docker_config": func(c *SubstrateConfig) { c.Templates.RegistryAuth.DockerConfig = "config.json" },
		"templates.registry_auth.ecr_hosts[0]":  func(c *SubstrateConfig) { c.Templates.RegistryAuth.ECRHosts = []string{"ghcr.io"} },
		"identity.admin_groups[1]":              func(c *SubstrateConfig) { c.Identity.AdminGroups = []string{"ok", " "} },
	} {
		c := s
		c.Templates.RegistryAuth.ECRHosts = append([]string(nil), s.Templates.RegistryAuth.ECRHosts...)
		mut(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: want a refusal naming the key, got %v", key, err)
		}
	}
}

func TestSubstrateRegistryAuthMatchesTheClosedSchema(t *testing.T) {
	got := yamlFieldNames(reflect.TypeOf(SubstrateRegistryAuthConfig{}))
	if want := schemaObjectProperties(t, "substrate", "templates", "registry_auth"); !reflect.DeepEqual(got, want) {
		t.Errorf("registry_auth yaml keys = %v, schema = %v", got, want)
	}
}
