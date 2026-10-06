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
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func init() {
	policyCmd.AddCommand(policyDigestCmd)
	policyDigestCmd.Flags().Bool("json", false, "Print the digest, its components and config_generation as JSON")
	policyDigestCmd.Flags().Bool("check-gateway", false, "Also read the effective policy digest the running gateway reports on /health (JSON: gateway_reported_digest)")
}

// policyDigestReport is the --json output: the computed policy and, with
// --check-gateway, the digest the running gateway reports.
type policyDigestReport struct {
	gateway.EffectivePolicy
	GatewayReportedDigest string `json:"gateway_reported_digest,omitempty"`
}

// gatewayReportedPolicyDigest is policy.effective_digest from the gateway's
// /health, "" when it does not answer or does not publish one.
func gatewayReportedPolicyDigest(c *config.Config) string {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(sidecarHealthURL(c))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gatewayHealthDocumentMaxBytes+1))
	if err != nil || len(body) > gatewayHealthDocumentMaxBytes {
		return ""
	}
	var health struct {
		Policy *gateway.PolicyHealth `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return ""
	}
	return health.Policy.EffectiveDigest
}

// enterprisePolicyFromDigest turns `policy digest --json --check-gateway`
// output into the lifecycle result's policy block; ok is false when the
// output carries no digest (an earlier release, or unreadable inputs).
func enterprisePolicyFromDigest(out []byte) (*enterprisestatus.PolicyState, bool) {
	var report policyDigestReport
	if json.Unmarshal(out, &report) != nil || report.Digest == "" {
		return nil, false
	}
	return &enterprisestatus.PolicyState{
		EffectiveDigest:       report.Digest,
		ConfigGeneration:      report.ConfigGeneration,
		Applied:               report.Digest == report.GatewayReportedDigest,
		GatewayReportedDigest: report.GatewayReportedDigest,
	}, true
}

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
	Args: cobra.NoArgs,
	// Only the strict runtime config is needed; the audit store stays closed
	// so this short-lived process never becomes a second SQLite owner.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
		return loadGatewayCommandConfigFor(cmd)
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	RunE: func(cmd *cobra.Command, _ []string) error {
		policy, err := gateway.ComputeEffectivePolicy(cmd.Context(), cfg)
		if err != nil {
			return fmt.Errorf("policy digest: %w", err)
		}
		out := cmd.OutOrStdout()
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			report := policyDigestReport{EffectivePolicy: policy}
			if check, _ := cmd.Flags().GetBool("check-gateway"); check {
				report.GatewayReportedDigest = gatewayReportedPolicyDigest(cfg)
			}
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
