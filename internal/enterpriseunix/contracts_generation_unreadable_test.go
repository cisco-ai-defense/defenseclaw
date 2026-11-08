// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A completed scan cannot establish coverage when its installed config
// generation is no longer readable. The valid record is the control.
func TestUnprotectedScanRequiresReadableConfigGeneration(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, damage := range []string{"missing", "malformed", "zero"} {
			t.Run(platform+"/"+damage, func(t *testing.T) {
				h := newTestHost(t, platform)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				writeFreshLedger(t, h)
				configPath := h.env.P(h.env.Layout.ConfigPath)
				current, err := configwrite.ReadGenerationState(configPath)
				if err != nil || current.Generation == 0 {
					t.Fatalf("read installed config generation: %+v, %v", current, err)
				}
				recordPath := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
				scan, err := enterprisehooks.MarshalUnprotectedAgents(nil)
				if err != nil {
					t.Fatal(err)
				}
				var record map[string]any
				if err := json.Unmarshal(scan, &record); err != nil {
					t.Fatal(err)
				}
				record["config_generation"] = current.Generation
				record["config_sha256"] = current.ConfigSHA256
				scan, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(recordPath, scan, 0o600); err != nil {
					t.Fatal(err)
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					if !result.CoverageComplete || messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" ||
						messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" {
						t.Fatalf("%s with matching scan: coverage=%t warnings=%+v errors=%+v", action, result.CoverageComplete, result.Warnings, result.Errors)
					}
				}
				generationPath := h.env.P(configwrite.GenerationPath(h.env.Layout.ConfigPath))
				switch damage {
				case "missing":
					err = os.Remove(generationPath)
				case "malformed":
					current.Generation++
					var raw []byte
					raw, err = json.Marshal(current)
					if err == nil {
						err = os.WriteFile(generationPath, append(raw, ','), 0o640)
					}
				case "zero":
					current.Generation = 0
					var raw []byte
					raw, err = json.Marshal(current)
					if err == nil {
						err = os.WriteFile(generationPath, raw, 0o640)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					var message string
					if action == ActionVerify {
						message = messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					} else {
						message = messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					}
					if result.CoverageComplete || result.SecurityComplete || !strings.Contains(message, "NOT COVERED (scan pending)") ||
						!strings.Contains(message, "installed config generation") {
						t.Fatalf("%s with %s generation: coverage=%t security=%t warnings=%+v errors=%+v", action, damage,
							result.CoverageComplete, result.SecurityComplete, result.Warnings, result.Errors)
					}
				}
			})
		}
	}
}
