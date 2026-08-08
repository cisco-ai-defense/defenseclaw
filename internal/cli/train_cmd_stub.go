//go:build !cgo || !grpo_engine

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	trainCmd := &cobra.Command{
		Use:   "train",
		Short: "Train a model using GRPO (requires CGO build)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("training not available: rebuild with CGO_ENABLED=1 -tags grpo_engine\n\nRequires: brew install llama.cpp")
		},
	}
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate text from a model (requires CGO build)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("generation not available: rebuild with CGO_ENABLED=1 -tags grpo_engine")
		},
	}
	dashboardCmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the training metrics dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("dashboard not available: rebuild with CGO_ENABLED=1 -tags grpo_engine")
		},
	}
	rootCmd.AddCommand(trainCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(dashboardCmd)
}
