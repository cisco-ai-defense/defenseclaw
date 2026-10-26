// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This env is the operator collector recorded on a published 1.0.2 upgrade
// subject. The 1.0.3 settings use the same supported native OTLP shape.
func TestClaudeReleasedOperatorCollectorUpgradeKeepsSignalSettings(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "claudecode_operator_1.0.2_1.0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var operator map[string]string
	if err := json.Unmarshal(fixture, &operator); err != nil {
		t.Fatal(err)
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, shape := range []string{"generic", "logs", "metrics", "traces", "mixed"} {
				t.Run(release+"/"+goos+"/"+shape, func(t *testing.T) {
					dir := t.TempDir()
					settingsPath := filepath.Join(dir, "settings.json")
					prior := ClaudeCodeSettingsPathOverride
					ClaudeCodeSettingsPathOverride = settingsPath
					t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
					c := NewClaudeCodeConnector()
					earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", GOOS: goos, sandboxNativeOTLP: true}
					if err := c.Setup(context.Background(), earlier); err != nil {
						t.Fatalf("seed released native setup: %v", err)
					}
					data, err := os.ReadFile(settingsPath)
					if err != nil {
						t.Fatal(err)
					}
					var settings map[string]interface{}
					if err := json.Unmarshal(data, &settings); err != nil {
						t.Fatal(err)
					}
					want := make(map[string]string, len(operator)+2)
					for key, value := range operator {
						want[key] = value
					}
					if shape != "generic" {
						signal := shape
						if shape == "mixed" {
							signal = "traces"
						}
						want["OTEL_EXPORTER_OTLP_"+strings.ToUpper(signal)+"_ENDPOINT"] = want["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/" + signal
						want["OTEL_EXPORTER_OTLP_"+strings.ToUpper(signal)+"_PROTOCOL"] = "http/protobuf"
						delete(want, "OTEL_EXPORTER_OTLP_ENDPOINT")
						delete(want, "OTEL_LOGS_EXPORTER")
						delete(want, "OTEL_METRICS_EXPORTER")
						want["OTEL_"+strings.ToUpper(signal)+"_EXPORTER"] = "otlp"
					}
					if shape == "mixed" {
						mixed := settings["env"].(map[string]interface{})
						for key, value := range want {
							mixed[key] = value
						}
						mixed["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = "x-operator=traces"
						want["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = "x-operator=traces"
						settings["env"] = mixed
					} else {
						settings["env"] = want
					}
					data, err = json.Marshal(settings)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
						t.Fatal(err)
					}
					upgrade := earlier
					upgrade.sandboxNativeOTLP = false
					upgrade.APIAddr = "127.0.0.1:19082"
					if err := c.Setup(context.Background(), upgrade); err != nil {
						t.Fatalf("upgrade: %v", err)
					}
					data, err = os.ReadFile(settingsPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &settings); err != nil {
						t.Fatal(err)
					}
					got := settings["env"].(map[string]interface{})
					for key, value := range want {
						if got[key] != value {
							t.Errorf("operator %s = %v, want %q", key, got[key], value)
						}
					}
					if shape == "mixed" {
						if _, present := got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; present || got["OTEL_LOGS_EXPORTER"] != "none" {
							t.Fatal("product logs endpoint or export gate survived beside operator traces")
						}
					}
				})
			}
		}
	}
}
