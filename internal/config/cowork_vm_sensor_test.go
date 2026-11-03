// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func goodCoworkVMSensor() EnterpriseCoworkVMSensorConfig {
	return EnterpriseCoworkVMSensorConfig{
		Mode: "on", Tenant: "tenant_1", Device: "mac-42", Collector: "edr.example.com:443",
		Vendor: "cisco", SourceDir: "/opt/cisco/defenseclaw/share/cowork", PackageSHA256: strings.Repeat("a", 64),
	}
}

func TestCoworkVMSensorArgumentsAndValidation(t *testing.T) {
	good := goodCoworkVMSensor()
	if err := validateCoworkVMSensor(good); err != nil {
		t.Fatal(err)
	}
	got, err := good.InstallArguments()
	if err != nil || got != "tenant=tenant_1,device=mac-42,collector=edr.example.com:443" {
		t.Fatalf("arguments = %q, %v", got, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*EnterpriseCoworkVMSensorConfig)
	}{
		{"unknown mode", func(c *EnterpriseCoworkVMSensorConfig) { c.Mode = "enabled" }},
		{"missing tenant", func(c *EnterpriseCoworkVMSensorConfig) { c.Tenant = "" }},
		{"missing device", func(c *EnterpriseCoworkVMSensorConfig) { c.Device = "" }},
		{"space in tenant", func(c *EnterpriseCoworkVMSensorConfig) { c.Tenant = "x y" }},
		{"argument injection", func(c *EnterpriseCoworkVMSensorConfig) { c.Tenant = "x,device=other" }},
		{"newline", func(c *EnterpriseCoworkVMSensorConfig) { c.Device = "x\n" }},
		{"BOM", func(c *EnterpriseCoworkVMSensorConfig) { c.Device = "\ufeffx" }},
		{"non ASCII", func(c *EnterpriseCoworkVMSensorConfig) { c.Device = "café" }},
		{"bad collector", func(c *EnterpriseCoworkVMSensorConfig) { c.Collector = "https://edr.example.com" }},
		{"bad port", func(c *EnterpriseCoworkVMSensorConfig) { c.Collector = "edr.example.com:65536" }},
		{"zero port", func(c *EnterpriseCoworkVMSensorConfig) { c.Collector = "edr.example.com:0" }},
		{"uppercase vendor", func(c *EnterpriseCoworkVMSensorConfig) { c.Vendor = "Cisco" }},
		{"relative source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "cowork" }},
		{"drive-relative source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:cowork` }},
		{"UNC source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `\\server\cowork` }},
		{"quoted source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `"C:\cowork"` }},
		{"NUL source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "/cowork\x00" }},
		{"Unix dot source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "/cowork/./source" }},
		{"Unix dotdot source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "/symlink/../cowork" }},
		{"Unix duplicate slash", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "/cowork//source" }},
		{"Unix trailing slash", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = "/cowork/" }},
		{"Windows dotdot source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:\symlink\..\cowork` }},
		{"Windows dot source", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:\cowork\.\source` }},
		{"Windows duplicate slash", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:\cowork\\source` }},
		{"Windows trailing slash", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:\cowork\` }},
		{"Windows trimmed component", func(c *EnterpriseCoworkVMSensorConfig) { c.SourceDir = `C:\cowork.\source` }},
		{"too long ID", func(c *EnterpriseCoworkVMSensorConfig) { c.Device = strings.Repeat("d", 129) }},
		{"missing package pin", func(c *EnterpriseCoworkVMSensorConfig) { c.PackageSHA256 = "" }},
		{"uppercase pin", func(c *EnterpriseCoworkVMSensorConfig) { c.PackageSHA256 = strings.Repeat("A", 64) }},
		{"bad signature pin", func(c *EnterpriseCoworkVMSensorConfig) { c.SignatureSHA256 = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.edit(&c)
			if err := validateCoworkVMSensor(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, c := range []EnterpriseCoworkVMSensorConfig{{}, {Mode: "off"}} {
		if err := validateCoworkVMSensor(c); err != nil || c.EffectiveMode() != "off" {
			t.Fatalf("absent/off must be off without inputs: %+v, %v", c, err)
		}
	}
	if enterpriseBlockEmpty(EnterpriseConfig{CoworkVMSensor: good}) {
		t.Fatal("Secure Client must reject the Cowork block")
	}
	good.SourceDir = `C:\Program Files\Cisco\DefenseClaw\cowork-source`
	good.SignatureSHA256 = strings.Repeat("b", 64)
	if err := validateCoworkVMSensor(good); err != nil {
		t.Fatalf("Windows deployment candidate: %v", err)
	}
}

func TestCoworkVMSensorArgumentsBoundary(t *testing.T) {
	c := goodCoworkVMSensor()
	c.Tenant, c.Device = strings.Repeat("t", 128), ""
	base := "tenant=" + c.Tenant + ",device=,collector=" + c.Collector
	c.Device = strings.Repeat("d", 256-len(base))
	value, err := c.InstallArguments()
	if err != nil || len(value) != 256 || strings.ContainsAny(value, "\r\n\ufeff ") {
		t.Fatalf("exact 256 ASCII bytes = %d, %v", len(value), err)
	}
	c.Device += "d"
	if _, err := c.InstallArguments(); err == nil {
		t.Fatal("257-byte arguments accepted")
	}
}

func coworkVMSensorSource(block string) []byte {
	return []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n  cowork_vm_sensor: " + block + "\n")
}

func TestCoworkVMSensorClosedSchemaAndProfile(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	for _, block := range []string{"{}", "{mode: off}"} {
		if err := ValidateV8SchemaBytes("config.yaml", coworkVMSensorSource(block)); err != nil {
			t.Fatalf("standalone %s: %v", block, err)
		}
		for _, prefix := range []string{
			"config_version: 9\nenterprise:\n  cowork_vm_sensor: ",
			"config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\n  cowork_vm_sensor: ",
			"config_version: 9\ndeployment_mode: unmanaged_byod\nenterprise:\n  profile: standalone\n  cowork_vm_sensor: ",
		} {
			if err := ValidateV8SchemaBytes("config.yaml", []byte(prefix+block+"\n")); err == nil {
				t.Errorf("Cowork block accepted outside standalone: %s%s", prefix, block)
			}
			if _, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(prefix+block+"\n")); err == nil {
				t.Errorf("runtime loader accepted Cowork outside standalone: %s%s", prefix, block)
			}
		}
	}
	for _, block := range []string{
		"{mode: true}", "{mode: enabled}", "{mode: on}", "{unexpected: value}", "[]", "null",
		"{tenant: 123}", "{device: [x]}", "{collector: true}", "{vendor: Cisco}",
		"{source_dir: 123}", "{package_sha256: abc}", "{signature_sha256: abc}",
	} {
		if err := ValidateV8SchemaBytes("config.yaml", coworkVMSensorSource(block)); err == nil {
			t.Errorf("invalid block accepted: %s", block)
		}
		if _, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), coworkVMSensorSource(block)); err == nil {
			t.Errorf("runtime loader accepted invalid block: %s", block)
		}
	}
}

func TestCoworkVMSensorFullRuntimeLoad(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	block := fmt.Sprintf("{mode: on, tenant: tenant_1, device: mac-42, collector: 'edr.example.com:443', vendor: cisco, source_dir: '/opt/cisco/defenseclaw/share/cowork', package_sha256: '%s'}", strings.Repeat("a", 64))
	source := coworkVMSensorSource(block)
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(path, source)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.StandaloneEnterprise() || cfg.Enterprise.CoworkVMSensor != goodCoworkVMSensor() {
		t.Fatalf("loaded block: %+v", cfg.Enterprise.CoworkVMSensor)
	}
	for _, block := range []string{"{}", "{mode: off}"} {
		cfg, err = LoadRuntimeV8InspectionCandidateFromBytes(path, coworkVMSensorSource(block))
		if err != nil || cfg.Enterprise.CoworkVMSensor.EffectiveMode() != "off" {
			t.Fatalf("off runtime load: %+v, %v", cfg, err)
		}
	}
}
