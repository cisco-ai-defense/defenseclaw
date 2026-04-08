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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func init() {
	rootCmd.AddCommand(capabilityCmd)
	capabilityCmd.AddCommand(capListCmd)
	capabilityCmd.AddCommand(capShowCmd)
	capabilityCmd.AddCommand(capEvaluateCmd)
	capabilityCmd.AddCommand(capValidateCmd)

	capEvaluateCmd.Flags().StringSlice("param", nil, "Parameters as key=value pairs")
	capEvaluateCmd.Flags().String("env", "", "Environment label")
}

var capabilityCmd = &cobra.Command{
	Use:   "capability",
	Short: "Manage agent capability policies",
	Long:  "List, inspect, evaluate, and validate agent capability policies.",
}

// ---------------------------------------------------------------------------
// capability list
// ---------------------------------------------------------------------------

var capListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded agent capability policies",
	RunE: func(_ *cobra.Command, _ []string) error {
		dir := cfg.CapabilityPolicyDir
		policies, errs := capability.LoadAllPolicies(context.Background(), dir)

		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}

		if len(policies) == 0 {
			fmt.Printf("No capability policies found in %s\n", dir)
			return nil
		}

		fmt.Printf("Agent Capability Policies (%s)\n", dir)
		fmt.Println(strings.Repeat("─", 60))

		for name, pol := range policies {
			fmt.Printf("  %-20s %d capabilities, %d restrictions\n",
				name, len(pol.Capabilities), len(pol.Restrictions))
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability show <agent>
// ---------------------------------------------------------------------------

var capShowCmd = &cobra.Command{
	Use:   "show <agent>",
	Short: "Display an agent's capabilities, restrictions, and conditions",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		dir := cfg.CapabilityPolicyDir
		policies, _ := capability.LoadAllPolicies(context.Background(), dir)

		pol, ok := policies[args[0]]
		if !ok {
			return fmt.Errorf("agent %q not found in %s", args[0], dir)
		}

		out, err := json.MarshalIndent(pol, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability evaluate <agent> <resource>
// ---------------------------------------------------------------------------

var capEvaluateCmd = &cobra.Command{
	Use:   "evaluate <agent> <resource>",
	Short: "Dry-run a capability evaluation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := cfg.CapabilityPolicyDir
		eval, err := capability.NewEvaluator(context.Background(), dir, auditStore)
		if err != nil {
			return err
		}

		params := make(map[string]any)
		paramPairs, _ := cmd.Flags().GetStringSlice("param")
		for _, pair := range paramPairs {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				return fmt.Errorf("invalid param format %q (expected key=value)", pair)
			}
			params[k] = v
		}

		env, _ := cmd.Flags().GetString("env")

		req := capability.EvalRequest{
			Agent:       args[0],
			Resource:    args[1],
			Params:      params,
			Environment: env,
			Timestamp:   time.Now().UTC(),
		}

		dec := eval.Evaluate(context.Background(), req)

		out, _ := json.MarshalIndent(dec, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability validate <path>
// ---------------------------------------------------------------------------

var capValidateCmd = &cobra.Command{
	Use:   "validate <path>",
	Short: "Validate a .capability.yaml file",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		pol, err := capability.LoadPolicy(args[0])
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		fmt.Printf("Valid: agent=%q, %d capabilities, %d restrictions\n",
			pol.Agent, len(pol.Capabilities), len(pol.Restrictions))
		return nil
	},
}
