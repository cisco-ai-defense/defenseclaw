// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/dashboard"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Open the DefenseClaw web dashboard in your default browser",
	Long: `Opens the embedded web dashboard in your default browser.

The dashboard is served by the running sidecar's REST API on the same port
(default 18970). The sidecar must be running first.`,
	RunE: runDashboard,
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(_ *cobra.Command, _ []string) error {
	bind := "127.0.0.1"
	if cfg.Gateway.APIBind != "" {
		bind = cfg.Gateway.APIBind
	}
	base := fmt.Sprintf("http://%s:%d", bind, cfg.Gateway.APIPort)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/health")
	if err != nil {
		fmt.Printf("Could not reach the sidecar at %s\n", base)
		fmt.Println("Start it first with: defenseclaw-gateway start")
		return nil
	}
	resp.Body.Close()

	fmt.Printf("Opening %s/ in your browser...\n", base)
	if err := dashboard.OpenBrowser(base + "/"); err != nil {
		return fmt.Errorf("dashboard: open browser: %w", err)
	}
	return nil
}
