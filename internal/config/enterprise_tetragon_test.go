// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const tetragonAck = "sha256:3f9c2a7d41b0"

// enterprise.tetragon: an absent block means consume with a 168h burn-in,
// and every value has one canonical form.
func TestEnterpriseTetragonEffectiveDefaults(t *testing.T) {
	for _, tc := range []struct {
		in, want EnterpriseTetragonConfig
	}{
		{EnterpriseTetragonConfig{}, EnterpriseTetragonConfig{Mode: "consume", BurnIn: "168h"}},
		{EnterpriseTetragonConfig{Mode: " Observe "}, EnterpriseTetragonConfig{Mode: "observe", BurnIn: "168h"}},
		{EnterpriseTetragonConfig{Mode: "enforce", BurnIn: "0", EnforceAck: " " + tetragonAck + " "}, EnterpriseTetragonConfig{Mode: "enforce", BurnIn: "0", EnforceAck: tetragonAck}},
		{EnterpriseTetragonConfig{BurnIn: "0h"}, EnterpriseTetragonConfig{Mode: "consume", BurnIn: "0"}},
		{EnterpriseTetragonConfig{BurnIn: "0168h"}, EnterpriseTetragonConfig{Mode: "consume", BurnIn: "168h"}},
		{EnterpriseTetragonConfig{BurnIn: "2160h"}, EnterpriseTetragonConfig{Mode: "consume", BurnIn: "2160h"}},
		// Malformed values (only an unvalidated Config can carry them) fall
		// back to the defaults rather than to anything wider.
		{EnterpriseTetragonConfig{Mode: "audit", BurnIn: "12h"}, EnterpriseTetragonConfig{Mode: "consume", BurnIn: "168h"}},
	} {
		if got := tc.in.Effective(); got != tc.want {
			t.Errorf("Effective(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	for block, want := range map[EnterpriseTetragonConfig]bool{
		{}:                                  true,
		{Mode: "consume", BurnIn: "168h"}:   true,
		{Mode: "observe"}:                   false,
		{BurnIn: "24h"}:                     false,
		{EnforceAck: tetragonAck}:           false,
		{Mode: "off", BurnIn: "0"}:          false,
		{Mode: "CONSUME", BurnIn: "0168h"}:  true,
		{Mode: "enforce", BurnIn: "168h"}:   false,
		{Mode: "consume", EnforceAck: "  "}: true,
	} {
		if got := block.IsDefault(); got != want {
			t.Errorf("IsDefault(%+v) = %v, want %v", block, got, want)
		}
	}
	for value, want := range map[string]time.Duration{"": DefaultTetragonBurnIn, "0": 0, "24h": 24 * time.Hour, "2160h": MaxTetragonBurnIn} {
		if got := (EnterpriseTetragonConfig{BurnIn: value}).BurnInDuration(); got != want {
			t.Errorf("BurnInDuration(%q) = %s, want %s", value, got, want)
		}
	}
}

func managedTetragonConfig(profile string, block EnterpriseTetragonConfig) Config {
	return Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: profile, Tetragon: block}}
}

// The loader checks only the format of enterprise.tetragon; every semantic
// condition is a cap, so a config that cannot run as written still loads.
func TestEnterpriseTetragonValidation(t *testing.T) {
	accepted := []EnterpriseTetragonConfig{
		{Mode: "off"}, {Mode: "consume"}, {Mode: "observe"}, {Mode: "enforce"},
		{BurnIn: "0"}, {BurnIn: "0h"}, {BurnIn: "24h"}, {BurnIn: "168h"}, {BurnIn: "2160h"},
		{EnforceAck: tetragonAck},
		// Caps, not rejections: enforce without an ack, and an ack with a
		// mode that never reads it.
		{Mode: "enforce"},
		{Mode: "observe", EnforceAck: tetragonAck},
	}
	for _, block := range accepted {
		cfg := managedTetragonConfig("", block)
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err != nil {
			t.Errorf("linux standalone rejected %+v: %v", block, err)
		}
	}
	// A config one administrator serves to Linux, macOS and Windows standalone
	// hosts loads everywhere; the other OSes ignore the block.
	for _, goos := range []string{"darwin", "windows"} {
		cfg := managedTetragonConfig("standalone", EnterpriseTetragonConfig{Mode: "enforce", EnforceAck: tetragonAck})
		if err := resolveEnterpriseConfig(&cfg, goos, ""); err != nil {
			t.Errorf("%s standalone rejected enterprise.tetragon: %v", goos, err)
		}
	}
	rejected := []struct {
		key   string
		block EnterpriseTetragonConfig
	}{
		{"enterprise.tetragon.mode", EnterpriseTetragonConfig{Mode: "audit"}},
		{"enterprise.tetragon.burn_in", EnterpriseTetragonConfig{BurnIn: "12h"}},
		{"enterprise.tetragon.burn_in", EnterpriseTetragonConfig{BurnIn: "2161h"}},
		{"enterprise.tetragon.burn_in", EnterpriseTetragonConfig{BurnIn: "7d"}},
		{"enterprise.tetragon.burn_in", EnterpriseTetragonConfig{BurnIn: "168"}},
		{"enterprise.tetragon.enforce_ack", EnterpriseTetragonConfig{EnforceAck: "sha256:3F9C2A7D41B0"}},
		{"enterprise.tetragon.enforce_ack", EnterpriseTetragonConfig{EnforceAck: "sha256:" + strings.Repeat("a", 64)}},
		{"enterprise.tetragon.enforce_ack", EnterpriseTetragonConfig{EnforceAck: "3f9c2a7d41b0"}},
	}
	for _, tc := range rejected {
		cfg := managedTetragonConfig("", tc.block)
		err := resolveEnterpriseConfig(&cfg, "linux", "")
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%+v: error = %v, want one naming %s", tc.block, err, tc.key)
		}
	}
}

// enterprise.tetragon is a standalone knob: an unmanaged config and a Secure
// Client config carrying only it are refused with the existing messages.
func TestEnterpriseTetragonRefusedOutsideStandalone(t *testing.T) {
	block := EnterpriseTetragonConfig{Mode: "observe"}
	unmanaged := Config{Enterprise: EnterpriseConfig{Tetragon: block}}
	if err := resolveEnterpriseConfig(&unmanaged, "linux", ""); err == nil || !strings.Contains(err.Error(), "the enterprise block requires deployment_mode managed_enterprise") {
		t.Fatalf("an unmanaged config accepted enterprise.tetragon: %v", err)
	}
	for _, goos := range []string{"darwin", "windows"} {
		secureClient := managedTetragonConfig("secure_client", block)
		if err := resolveEnterpriseConfig(&secureClient, goos, ""); err == nil || !strings.Contains(err.Error(), "enterprise settings other than profile apply only to the standalone profile") {
			t.Fatalf("a %s Secure Client config accepted enterprise.tetragon: %v", goos, err)
		}
	}
}

func TestEnterpriseTetragonSchema(t *testing.T) {
	if got, want := yamlFieldNames(reflect.TypeOf(EnterpriseTetragonConfig{})), schemaObjectProperties(t, "enterprise", "tetragon"); !reflect.DeepEqual(got, want) {
		t.Fatalf("EnterpriseTetragonConfig yaml keys = %v, schema enterprise.tetragon = %v", got, want)
	}
	validate := func(name, doc string) error {
		document, err := ParseV8YAML(name, []byte(doc))
		if err != nil {
			return err
		}
		return validateV8Schema(name, document)
	}
	const head = "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n  tetragon:\n"
	for name, body := range map[string]string{
		"observe":            "    mode: observe\n",
		"enforce with ack":   "    mode: enforce\n    burn_in: 168h\n    enforce_ack: " + tetragonAck + "\n",
		"burn-in skipped":    "    mode: enforce\n    burn_in: \"0\"\n",
		"burn-in integer 0":  "    burn_in: 0\n",
		"empty ack":          "    enforce_ack: \"\"\n",
		"off":                "    mode: \"off\"\n",
		"empty block":        "    {}\n",
		"long burn-in":       "    burn_in: 2160h\n",
		"burn-in out of the": "    burn_in: 12h\n", // the range is the loader's check
	} {
		if err := validate(name+".yaml", head+body); err != nil {
			t.Errorf("v8 schema rejected %s: %v", name, err)
		}
	}
	for name, body := range map[string]string{
		"unknown mode":      "    mode: audit\n",
		"unknown key":       "    socket: /var/run/tetragon/tetragon.sock\n",
		"duration in days":  "    burn_in: 7d\n",
		"bare hours":        "    burn_in: 168\n",
		"minutes":           "    burn_in: 90m\n",
		"full digest ack":   "    enforce_ack: sha256:" + strings.Repeat("a", 64) + "\n",
		"uppercase ack":     "    enforce_ack: sha256:3F9C2A7D41B0\n",
		"ack without label": "    enforce_ack: 3f9c2a7d41b0\n",
		"scalar block":      "    observe\n",
	} {
		if err := validate(name+".yaml", head+body); err == nil {
			t.Errorf("v8 schema accepted %s", name)
		}
	}
}

// burn_in: 0 is an integer in YAML; the loader decodes it like "0".
func TestEnterpriseTetragonDecodesYAMLValues(t *testing.T) {
	for doc, want := range map[string]EnterpriseTetragonConfig{
		"enterprise:\n  tetragon:\n    burn_in: 0\n":                       {BurnIn: "0"},
		"enterprise:\n  tetragon:\n    mode: enforce\n    burn_in: 168h\n": {Mode: "enforce", BurnIn: "168h"},
		"enterprise:\n  tetragon:\n    enforce_ack: " + tetragonAck + "\n": {EnforceAck: tetragonAck},
		"enterprise:\n  tetragon:\n    mode: \"off\"\n":                    {Mode: "off"},
		"enterprise:\n  profile: standalone\n":                             {},
	} {
		v := viper.New()
		v.SetConfigType("yaml")
		if err := v.ReadConfig(bytes.NewReader([]byte(doc))); err != nil {
			t.Fatalf("%q: %v", doc, err)
		}
		var cfg Config
		if err := v.Unmarshal(&cfg); err != nil {
			t.Fatalf("%q: %v", doc, err)
		}
		if cfg.Enterprise.Tetragon != want {
			t.Errorf("%q decoded to %+v, want %+v", doc, cfg.Enterprise.Tetragon, want)
		}
	}
}

// TetragonMode applies the caps the lifecycle renders into the helper's
// drop-in: only a managed Linux standalone host with Plane C selected runs
// the configured mode.
func TestTetragonModeCaps(t *testing.T) {
	planeC := AIRuntimeConfig{Enabled: true, EnableHostPlane: true}
	build := func(mode string, runtime AIRuntimeConfig) *Config {
		cfg := managedTetragonConfig("standalone", EnterpriseTetragonConfig{Mode: mode})
		cfg.AIDiscovery.Runtime = runtime
		return &cfg
	}
	for _, tc := range []struct {
		name       string
		cfg        *Config
		goos       string
		mode, code string
	}{
		{"nil config", nil, "linux", "off", ""},
		{"absent block runs the default", build("", planeC), "linux", "consume", ""},
		{"observe", build("observe", planeC), "linux", "observe", ""},
		{"enforce", build("enforce", planeC), "linux", "enforce", ""},
		{"written off", build("off", planeC), "linux", "off", ""},
		{"plane c not opted in", build("observe", AIRuntimeConfig{Enabled: true}), "linux", "off", TetragonReasonPlaneCOff},
		{"plane c listed without the opt-in", build("enforce", AIRuntimeConfig{Enabled: true, Planes: []string{"a", "c"}}), "linux", "off", TetragonReasonPlaneCOff},
		{"plane c deselected", build("observe", AIRuntimeConfig{Enabled: true, EnableHostPlane: true, Planes: []string{"a", "b"}}), "linux", "off", TetragonReasonPlaneCOff},
		{"runtime planes disabled", build("observe", AIRuntimeConfig{EnableHostPlane: true}), "linux", "off", TetragonReasonPlaneCOff},
		{"default mode with plane c off is no news", build("", AIRuntimeConfig{Enabled: true}), "linux", "off", ""},
		{"written off with plane c off", build("off", AIRuntimeConfig{}), "linux", "off", ""},
		{"macos ignores it", build("observe", planeC), "darwin", "off", TetragonReasonNotApplicable},
		{"windows ignores it", build("off", planeC), "windows", "off", TetragonReasonNotApplicable},
		{"macos without the block says nothing", build("", planeC), "darwin", "off", ""},
		{"unmanaged", &Config{AIDiscovery: AIDiscoveryConfig{Runtime: planeC}}, "linux", "off", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cfg != nil && tc.cfg.DeploymentMode != "" {
				if err := resolveEnterpriseConfig(tc.cfg, tc.goos, ""); err != nil {
					t.Fatal(err)
				}
			}
			mode, code := tc.cfg.TetragonMode(tc.goos)
			if mode != tc.mode || code != tc.code {
				t.Fatalf("TetragonMode(%s) = %q, %q; want %q, %q", tc.goos, mode, code, tc.mode, tc.code)
			}
		})
	}
}
