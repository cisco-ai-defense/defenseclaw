package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var policyDiffCmd = &cobra.Command{
	Use:   "policy diff",
	Short: "Compare active sandbox policy against configured endpoints",
	Long: `Check which endpoints required by OpenClaw's configured channels and
providers are covered by the active OpenShell sandbox network policy.

Reads openclaw.json to discover required endpoints, then checks each one
against the active policy YAML. Reports missing entries.`,
	RunE: runPolicyDiff,
}

func init() {
	sandboxCmd.AddCommand(policyDiffCmd)
}

func runPolicyDiff(_ *cobra.Command, _ []string) error {
	if !cfg.OpenShell.IsStandalone() {
		return fmt.Errorf("policy diff: openshell.mode is not 'standalone'")
	}

	// Load active policy
	policyPath := filepath.Join(cfg.DataDir, "openshell-policy.yaml")
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("policy diff: read policy: %w", err)
	}

	policy, err := sandbox.ParseOpenShellPolicy(policyData)
	if err != nil {
		return fmt.Errorf("policy diff: parse policy: %w", err)
	}

	// Load openclaw.json to discover required endpoints
	clawHome := cfg.ClawHomeDir()
	ocConfigPath := filepath.Join(clawHome, "openclaw.json")
	required := discoverRequiredEndpoints(ocConfigPath)

	if len(required) == 0 {
		fmt.Println("No required endpoints discovered from openclaw.json.")
		return nil
	}

	fmt.Println("Policy coverage:")

	missing := 0
	for _, ep := range required {
		covered := policy.HasEndpointForHost(ep.Host)
		if covered {
			fmt.Printf("  + %-35s (covered)\n", fmt.Sprintf("%s:%d", ep.Host, ep.Port))
		} else {
			fmt.Printf("  - %-35s (MISSING)\n", fmt.Sprintf("%s:%d", ep.Host, ep.Port))
			missing++
		}
	}

	fmt.Println()
	if missing > 0 {
		fmt.Printf("%d endpoint(s) missing from active policy.\n", missing)
		fmt.Printf("Edit %s and run:\n", policyPath)
		fmt.Println("  sudo systemctl restart openshell-sandbox.service")
	} else {
		fmt.Println("All discovered endpoints are covered by the active policy.")
	}

	return nil
}

type requiredEndpoint struct {
	Host   string
	Port   int
	Source string
}

func discoverRequiredEndpoints(ocConfigPath string) []requiredEndpoint {
	data, err := os.ReadFile(ocConfigPath)
	if err != nil {
		return nil
	}

	var oc map[string]interface{}
	if err := json.Unmarshal(data, &oc); err != nil {
		return nil
	}

	var eps []requiredEndpoint

	// Discover channels
	channels, _ := oc["channels"].(map[string]interface{})
	for chName := range channels {
		chLower := strings.ToLower(chName)
		if known, ok := sandbox.KnownChannelEndpoints[chLower]; ok {
			for _, ep := range known {
				eps = append(eps, requiredEndpoint{Host: ep.Host, Port: ep.Port, Source: "channel:" + chName})
			}
		}
	}

	// Discover model providers
	models, _ := oc["models"].(map[string]interface{})
	providers, _ := models["providers"].(map[string]interface{})
	for provName, provCfg := range providers {
		if provName == "litellm" {
			continue
		}
		provMap, _ := provCfg.(map[string]interface{})
		if baseURL, ok := provMap["baseUrl"].(string); ok {
			host, port, skip := sandbox.ParseMCPEndpoint(baseURL)
			if !skip && host != "" {
				eps = append(eps, requiredEndpoint{Host: host, Port: port, Source: "provider:" + provName})
			}
		}
	}

	return eps
}
