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

// A completed scan proves coverage only for the installed config bytes that
// its generation record identifies. A matching generation number alone is
// insufficient when the record or config changes independently of the scan.
func TestUnprotectedScanRequiresGenerationBoundToInstalledConfig(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, variant := range []string{"matching", "restored_record", "missing_digest_after_ensure", "edited_config"} {
			t.Run(platform+"/"+variant, func(t *testing.T) {
				h := newTestHost(t, platform)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				writeFreshLedger(t, h)
				configPath := h.env.P(h.env.Layout.ConfigPath)
				generationPath := h.env.P(configwrite.GenerationPath(h.env.Layout.ConfigPath))
				state, err := configwrite.ReadGenerationState(configPath)
				if err != nil || state.Generation == 0 || state.ConfigSHA256 == "" {
					t.Fatalf("read installed config generation: %+v, %v", state, err)
				}
				switch variant {
				case "restored_record":
					previous, err := os.ReadFile(generationPath)
					if err != nil {
						t.Fatal(err)
					}
					requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: machinePolicyConfig(t, h, "opencode")}))
					if installed := h.read(h.env.Layout.ConfigPath); sha256Bytes([]byte(installed)) == state.ConfigSHA256 {
						t.Fatal("the connector config did not change")
					}
					if err := os.WriteFile(generationPath, previous, 0o640); err != nil {
						t.Fatal(err)
					}
				case "missing_digest_after_ensure":
					state.ConfigSHA256 = ""
					data, err := json.Marshal(state)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(generationPath, data, 0o640); err != nil {
						t.Fatal(err)
					}
					_ = h.run(Options{Action: ActionEnsure, Reason: "path"})
				case "edited_config":
					before := h.read(h.env.Layout.ConfigPath)
					after := strings.Replace(before, "  rule_pack: default\n", "  rule_pack: default\n  connectors:\n    opencode: {}\n", 1)
					if after == before {
						t.Fatal("the config edit did not apply")
					}
					if err := os.WriteFile(configPath, []byte(after), 0o640); err != nil {
						t.Fatal(err)
					}
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					warning := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					errorMessage := messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					if variant == "matching" {
						if !result.CoverageComplete || warning != "" || errorMessage != "" {
							t.Fatalf("%s with matching config and scan: coverage=%t warnings=%+v errors=%+v", action, result.CoverageComplete, result.Warnings, result.Errors)
						}
						continue
					}
					message := warning
					if action == ActionVerify {
						message = errorMessage
					}
					if result.CoverageComplete || result.SecurityComplete || !strings.Contains(message, "installed config generation") {
						t.Fatalf("%s with %s: coverage=%t security=%t warnings=%+v errors=%+v", action, variant,
							result.CoverageComplete, result.SecurityComplete, result.Warnings, result.Errors)
					}
				}
			})
		}
	}
}

// A rebuilt generation record restarts its counter, so the number alone can
// repeat for different config bytes. The scan names the digest it read; a
// reset that reuses its number does not make the old scan cover the new
// config.
func TestUnprotectedScanIsNotReusedAfterGenerationReset(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, damage := range []string{"missing", "malformed"} {
			t.Run(platform+"/"+damage, func(t *testing.T) {
				h := newTestHost(t, platform)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				writeFreshLedger(t, h)
				configPath := h.env.P(h.env.Layout.ConfigPath)
				generationPath := h.env.P(configwrite.GenerationPath(h.env.Layout.ConfigPath))
				scanned, err := configwrite.ReadGenerationState(configPath)
				if err != nil || scanned.Generation == 0 || scanned.ConfigSHA256 == "" {
					t.Fatalf("read scanned config generation: %+v, %v", scanned, err)
				}
				if damage == "missing" {
					err = os.Remove(generationPath)
				} else {
					err = os.WriteFile(generationPath, []byte("{"), 0o640)
				}
				if err != nil {
					t.Fatal(err)
				}
				requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: machinePolicyConfig(t, h, "opencode")}))
				now, err := configwrite.ReadGenerationState(configPath)
				if err != nil || now.ConfigSHA256 == scanned.ConfigSHA256 || sha256Bytes([]byte(h.read(h.env.Layout.ConfigPath))) != now.ConfigSHA256 {
					t.Fatalf("the connector config did not change: scanned=%+v now=%+v, %v", scanned, now, err)
				}
				if now.Generation != scanned.Generation {
					t.Fatalf("the reset did not reuse the scan generation: scanned=%d now=%d", scanned.Generation, now.Generation)
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					message := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					if result.CoverageComplete || result.SecurityComplete || !strings.Contains(message, "scan") {
						t.Fatalf("%s after generation reset: coverage=%t security=%t warnings=%+v errors=%+v", action,
							result.CoverageComplete, result.SecurityComplete, result.Warnings, result.Errors)
					}
				}
				// The next scan reads the new config and covers it again.
				scan, err := h.marshalCompletedScan(nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), scan, 0o600); err != nil {
					t.Fatal(err)
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					if messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" ||
						messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" {
						t.Fatalf("%s after a current scan: warnings=%+v errors=%+v", action, result.Warnings, result.Errors)
					}
				}
			})
		}
	}
}
