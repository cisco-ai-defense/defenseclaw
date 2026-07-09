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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var setupRoutingCmd = &cobra.Command{
	Use:   "setup-routing",
	Short: "Configure semantic model routing",
	Long: `Enable or disable the semantic model router.

When enabled, DefenseClaw downloads and manages the vLLM Semantic Router
as a local subprocess. All routing configuration is in config.yaml under
the 'routing:' section.

Examples:
  defenseclaw setup-routing --enable
  defenseclaw setup-routing --disable
  defenseclaw setup-routing --status`,
	RunE: runSetupRouting,
}

var (
	routingEnable  bool
	routingDisable bool
	routingStatus  bool
)

func init() {
	setupRoutingCmd.Flags().BoolVar(&routingEnable, "enable", false, "Enable semantic routing")
	setupRoutingCmd.Flags().BoolVar(&routingDisable, "disable", false, "Disable semantic routing")
	setupRoutingCmd.Flags().BoolVar(&routingStatus, "status", false, "Show routing status")
	rootCmd.AddCommand(setupRoutingCmd)
}

func runSetupRouting(_ *cobra.Command, _ []string) error {
	if routingStatus || (!routingEnable && !routingDisable) {
		printRoutingStatus(cfg)
		return nil
	}

	if routingEnable && routingDisable {
		return fmt.Errorf("cannot use --enable and --disable together")
	}

	if routingEnable {
		cfg.Routing.Enabled = true
		fmt.Println("✓ Semantic routing enabled")
		fmt.Println("  The router will start automatically with the gateway.")
		if cfg.Routing.Version == "" {
			cfg.Routing.Version = "0.3.0"
			fmt.Printf("  Version: %s (default)\n", cfg.Routing.Version)
		}
		if cfg.Routing.Port == 0 {
			cfg.Routing.Port = 8080
		}
		fmt.Printf("  Port: %d\n", cfg.Routing.Port)
		if len(cfg.Routing.Models) == 0 {
			fmt.Println("\n  ⚠ No models configured. Add models to config.yaml under routing.models[]")
		}
	}

	if routingDisable {
		cfg.Routing.Enabled = false
		fmt.Println("✓ Semantic routing disabled")
		fmt.Println("  All requests will use the default provider.")
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	configPath := cfg.ConfigFilePath
	if configPath == "" {
		configPath = "config.yaml"
	}
	fmt.Printf("\n  Config saved to %s\n", configPath)
	return nil
}

func printRoutingStatus(c *config.Config) {
	fmt.Println("\nSemantic Router Status")
	fmt.Println("══════════════════════")
	if !c.Routing.Enabled {
		fmt.Println("  Status:    disabled")
		fmt.Println("  Enable with: defenseclaw setup-routing --enable")
		return
	}
	fmt.Println("  Status:    enabled")
	version := c.Routing.Version
	if version == "" {
		version = "0.3.0 (default)"
	}
	fmt.Printf("  Version:   %s\n", version)
	port := c.Routing.Port
	if port == 0 {
		port = 8080
	}
	fmt.Printf("  Port:      %d\n", port)
	if c.Routing.Remote.Endpoint != "" {
		fmt.Printf("  Mode:      remote (%s)\n", c.Routing.Remote.Endpoint)
	} else {
		fmt.Println("  Mode:      managed (local subprocess)")
	}
	algorithm := c.Routing.Algorithm
	if algorithm == "" {
		algorithm = "default"
	}
	fmt.Printf("  Algorithm: %s\n", algorithm)
	fmt.Printf("  Models:    %d configured\n", len(c.Routing.Models))
	for _, m := range c.Routing.Models {
		fmt.Printf("    • %s (%s/%s)\n", m.Name, m.Provider, m.Model)
	}
	fmt.Printf("  Decisions: %d rules\n", len(c.Routing.Decisions))
}
