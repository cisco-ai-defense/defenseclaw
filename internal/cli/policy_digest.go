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

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func init() {
	policyCmd.AddCommand(policyDigestCmd)
	policyDigestCmd.Flags().Bool("json", false, "Print the digest, its components and config_generation as JSON")
	policyDigestCmd.Flags().Bool("check-gateway", false, "Also read the effective policy digest the running gateway reports on /health (JSON: gateway_reported_digest)")
}

// policyDigestReport is the --json output: the computed policy and, with
// --check-gateway, what the running gateway reports. When the installed
// config's policy cannot be built (a rule pack that no longer matches its
// pin, for example) Error says why and the policy fields are empty, so the
// lifecycle still learns what the gateway reports.
type policyDigestReport struct {
	gateway.EffectivePolicy
	GatewayReportedDigest           string `json:"gateway_reported_digest,omitempty"`
	GatewayReportedConfigGeneration uint64 `json:"gateway_reported_config_generation,omitempty"`
	GatewayReportedBundleID         string `json:"gateway_reported_bundle_id,omitempty"`
	GatewayReportedBundleVersion    uint64 `json:"gateway_reported_bundle_version,omitempty"`
	GatewayLastReloadError          string `json:"gateway_last_reload_error,omitempty"`
	Error                           string `json:"error,omitempty"`
	// ConfigRecordedAsHandEdit is set on a standalone host whose config
	// generation records config.yaml with a hand-edit actor: the hook guardian
	// recorded a content write the lifecycle did not make (GAP-0617).
	ConfigRecordedAsHandEdit bool `json:"config_recorded_as_hand_edit,omitempty"`
}

// configRecordedAsHandEdit reports whether the managed config's generation
// record names a hand edit as its writer.
func configRecordedAsHandEdit(c *config.Config) bool {
	if c == nil || !c.StandaloneEnterprise() || strings.TrimSpace(c.ConfigFilePath) == "" {
		return false
	}
	state, err := configwrite.ReadGenerationState(c.ConfigFilePath)
	return err == nil && configwrite.IsHandEditActor(state.Actor)
}

// gatewayReportedPolicy is the policy object of the gateway's /health: zero
// when it does not answer or does not publish one. A standalone gateway
// publishes it only to an administrator (GAP-0481), so the request carries
// the gateway token when this config resolves one: the Windows lifecycle
// reads it here.
func gatewayReportedPolicy(c *config.Config) gateway.PolicyHealth {
	req, err := http.NewRequest(http.MethodGet, sidecarHealthURL(c), nil)
	if err != nil {
		return gateway.PolicyHealth{}
	}
	if c != nil {
		if token := strings.TrimSpace(c.Gateway.ResolvedToken()); token != "" {
			req.Header.Set("X-DefenseClaw-Token", token)
		}
	}
	client, err := gatewayPeerClientForURL(c, req.URL.String(), 5*time.Second)
	if err != nil {
		return gateway.PolicyHealth{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return gateway.PolicyHealth{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gateway.PolicyHealth{}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gatewayHealthDocumentMaxBytes+1))
	if err != nil || len(body) > gatewayHealthDocumentMaxBytes {
		return gateway.PolicyHealth{}
	}
	var health struct {
		Policy *gateway.PolicyHealth `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return gateway.PolicyHealth{}
	}
	return *health.Policy
}

// applyEnterprisePolicyReport turns `policy digest --json --check-gateway`
// output into the lifecycle result's policy block and its warnings, and
// returns the block (nil when the output carries none). change is true for
// a changing action: only it warns when the gateway has not applied the
// config yet. A reload the gateway rejected and a config.yaml edited
// outside the lifecycle are reported for every action, so status and
// verify do not read green over them.
func applyEnterprisePolicyReport(result *enterprisestatus.Result, out []byte, change bool) *enterprisestatus.PolicyState {
	var report policyDigestReport
	if json.Unmarshal(out, &report) != nil {
		return nil
	}
	reload := boundedPolicyMessage(report.GatewayLastReloadError)
	if report.Digest == "" {
		if report.Error != "" {
			result.AddWarning("policy_not_buildable", fmt.Sprintf(
				"the policy the installed config and its assets describe cannot be built (%s); the gateway keeps enforcing effective policy %s",
				boundedPolicyMessage(report.Error), shortPolicyDigest(report.GatewayReportedDigest)))
		}
		return nil
	}
	state := &enterprisestatus.PolicyState{
		EffectiveDigest:       report.Digest,
		ConfigGeneration:      report.ConfigGeneration,
		Applied:               report.Digest == report.GatewayReportedDigest && reload == "",
		GatewayReportedDigest: report.GatewayReportedDigest,
		LastReloadError:       reload,
		// A hand edit the hook guardian recorded advances the generation but
		// is still a config change outside the lifecycle (GAP-0617).
		ConfigUnrecorded: (report.ConfigGeneration > 0 || result.Platform == "windows") && (!report.ConfigGenerationRecorded || report.ConfigRecordedAsHandEdit),
	}
	handEdit := report.ConfigGenerationRecorded && report.ConfigRecordedAsHandEdit
	result.Policy = state
	switch {
	case reload != "":
		result.AddWarning("policy_reload_rejected", "the gateway reports a policy error and keeps enforcing the policy it last built: "+reload+
			"; fix the asset or the config it names, and the gateway clears this when the next reload succeeds")
	case !state.Applied && change:
		result.AddWarning("policy_not_applied", fmt.Sprintf(
			"the gateway reports effective policy %s but the installed config computes to %s; it applies the config on its next reload",
			shortPolicyDigest(state.GatewayReportedDigest), shortPolicyDigest(state.EffectiveDigest)))
	}
	switch {
	case handEdit:
		result.AddWarning("config_edited_outside_lifecycle", fmt.Sprintf(
			"config.yaml was changed outside the DefenseClaw lifecycle (config generation %d records it as a hand edit) and the gateway enforces it; run ensure with the intended config to put the managed config back",
			state.ConfigGeneration))
	case state.ConfigUnrecorded:
		result.AddWarning("config_edited_outside_lifecycle", fmt.Sprintf(
			"config.yaml was changed outside the DefenseClaw lifecycle (config generation %d does not record it) and the gateway may already enforce it; run ensure with the intended config to put the managed config back",
			state.ConfigGeneration))
	}
	return state
}

// boundedPolicyMessage keeps a gateway or build error to one short line.
func boundedPolicyMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 300 {
		message = message[:300] + "..."
	}
	return message
}

// shortPolicyDigest is "sha256:" and the first 12 hex digits, or "none".
func shortPolicyDigest(digest string) string { return enterprisestatus.ShortDigest(digest) }

// policyDigestCmd computes the effective policy digest from config.yaml and
// the assets it references, the way the gateway does when it builds a
// configuration generation. doctor and the enterprise lifecycle compare it
// with the digest the running gateway reports on /health to tell whether
// the gateway applied the config on disk.
var policyDigestCmd = &cobra.Command{
	Use:   "digest",
	Short: "Compute the effective policy digest of config.yaml",
	Long: `Compute effective_policy_digest from config.yaml and the policy assets it
references (rule packs, Rego modules, signature packs, scanner policies), as
the gateway does when it applies a configuration. Compare it with
"policy.effective_digest" on the gateway's /health to see whether the running
gateway applied this configuration.`,
	Args:              cobra.NoArgs,
	PersistentPreRunE: policyConfigOnlyPreRunE,
	PersistentPostRun: policyConfigOnlyPostRun,
	Annotations:       map[string]string{secureClientAbsentAnnotation: "true"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		if cfg != nil && cfg.SecureClientIntegration() {
			// main has no policy digest: Secure Client answers as it did
			// (issue #1092).
			return usageError(policyCmd, fmt.Errorf("unknown command %q for %q", "digest", policyCmd.CommandPath()))
		}
		out := cmd.OutOrStdout()
		asJSON, _ := cmd.Flags().GetBool("json")
		check, _ := cmd.Flags().GetBool("check-gateway")
		report := policyDigestReport{}
		if asJSON && check {
			reported := gatewayReportedPolicy(cfg)
			report.GatewayReportedDigest = reported.EffectiveDigest
			report.GatewayReportedConfigGeneration = reported.ConfigGeneration
			report.GatewayReportedBundleID = reported.BundleID
			report.GatewayReportedBundleVersion = reported.BundleVersion
			report.GatewayLastReloadError = reported.LastReloadError
			report.ConfigRecordedAsHandEdit = configRecordedAsHandEdit(cfg)
		}
		policy, err := gateway.ComputeEffectivePolicy(cmd.Context(), cfg)
		if err != nil {
			if asJSON && check {
				// What the gateway reports still goes to the lifecycle.
				report.Error = err.Error()
				_ = json.NewEncoder(out).Encode(report)
			}
			return fmt.Errorf("policy digest: %w", err)
		}
		if asJSON {
			report.EffectivePolicy = policy
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
		fmt.Fprintf(out, "Effective policy: %s\n", policy.Digest)
		switch {
		case policy.ConfigGeneration == 0:
			fmt.Fprintln(out, "Config generation: none recorded yet")
		case policy.ConfigGenerationRecorded:
			fmt.Fprintf(out, "Config generation: %d\n", policy.ConfigGeneration)
		default:
			fmt.Fprintf(out, "Config generation: %d, but config.yaml changed outside the DefenseClaw writer since\n", policy.ConfigGeneration)
		}
		keys := make([]string, 0, len(policy.Components))
		for key := range policy.Components {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(out, "  %-32s %s\n", key, policy.Components[key])
		}
		return nil
	},
}
