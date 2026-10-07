// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// scan skill|mcp|plugin run the gateway's scanners through its API: on a
// managed Windows computer, where the per-user Python CLI is not installed,
// they are how an administrator scans with the scanners, policy and judge
// the admin config sets (GAP-0132).
var (
	scanGatewayJSON bool

	scanSkillCmd = &cobra.Command{
		Use:   "skill <path>",
		Short: "Scan a skill folder with the gateway's skill scanner",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runGatewayScan(cmd, "skill", args[0]) },
	}
	scanMCPCmd = &cobra.Command{
		Use:   "mcp <url>",
		Short: "Scan a remote MCP server with the gateway's MCP scanner",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runGatewayScan(cmd, "mcp", args[0]) },
	}
	scanPluginCmd = &cobra.Command{
		Use:   "plugin <path>",
		Short: "Scan a plugin folder with the gateway's plugin scanner",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runGatewayScan(cmd, "plugin", args[0]) },
	}
)

func init() {
	for _, command := range []*cobra.Command{scanSkillCmd, scanMCPCmd, scanPluginCmd} {
		command.Flags().BoolVar(&scanGatewayJSON, "json", false, "Print the gateway's scan response as JSON")
		// A managed computer has no per-user config for the bootstrap to
		// load: the managed gateway's endpoint comes from its layout, and
		// any other host loads its config in scanGatewayEndpoint.
		command.Annotations = map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"}
		scanCmd.AddCommand(command)
	}
}

// scanGatewayEndpoint returns the gateway API base URL and token for the
// scan commands; replaced on a managed Windows computer and in tests.
var scanGatewayEndpoint = func() (string, string, error) {
	if base, token, ok, err := managedScanGatewayEndpoint(); ok || err != nil {
		return base, token, err
	}
	if cfg == nil {
		if err := loadGatewayCommandConfigOnly(); err != nil {
			return "", "", err
		}
	}
	if cfg == nil {
		return "", "", errors.New("no DefenseClaw config is loaded")
	}
	bind := strings.TrimSpace(cfg.Gateway.APIBind)
	if bind == "" {
		bind = "127.0.0.1"
	}
	token := strings.TrimSpace(cfg.Gateway.ResolvedToken())
	if token == "" {
		return "", "", errors.New("no gateway token is configured")
	}
	return fmt.Sprintf("http://%s:%d", bind, cfg.Gateway.APIPort), token, nil
}

type gatewayScanResponse struct {
	Verdict  string         `json:"verdict"`
	BySev    map[string]int `json:"findings_count_by_severity"`
	Settings map[string]any `json:"scanner_settings"`
	Result   struct {
		Target   string `json:"target"`
		Duration int64  `json:"duration"`
		Findings []struct {
			Severity string `json:"severity"`
			Title    string `json:"title"`
			RuleID   string `json:"rule_id"`
			Location string `json:"location"`
			Scanner  string `json:"scanner"`
		} `json:"findings"`
	} `json:"result"`
	Error string `json:"error"`
}

func runGatewayScan(cmd *cobra.Command, kind, target string) error {
	if kind != "mcp" {
		absolute, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", target, err)
		}
		target = absolute
	}
	base, token, err := scanGatewayEndpoint()
	if err != nil {
		return fmt.Errorf("scan %s: %w", kind, err)
	}
	body, _ := json.Marshal(map[string]string{"target": target})
	request, err := http.NewRequest(http.MethodPost, base+"/v1/"+kind+"/scan", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "cli")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-DefenseClaw-Token", token)
	response, err := (&http.Client{Timeout: 5 * time.Minute}).Do(request)
	if err != nil {
		return fmt.Errorf("scan %s: the gateway at %s did not answer: %w", kind, base, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	out := cmd.OutOrStdout()
	if scanGatewayJSON {
		_, err := out.Write(append(bytes.TrimSpace(raw), '\n'))
		if response.StatusCode != http.StatusOK && err == nil {
			err = fmt.Errorf("scan %s failed (HTTP %d)", kind, response.StatusCode)
		}
		return err
	}
	var parsed gatewayScanResponse
	_ = json.Unmarshal(raw, &parsed)
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(parsed.Error)
		if message == "" {
			message = strings.TrimSpace(string(raw))
		}
		if message == "" {
			return fmt.Errorf("scan %s failed (HTTP %d)", kind, response.StatusCode)
		}
		return fmt.Errorf("scan %s: %s", kind, message)
	}
	fmt.Fprintf(out, "Scan %s: %s\n", kind, target)
	keys := make([]string, 0, len(parsed.Settings))
	for key := range parsed.Settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := fmt.Sprint(parsed.Settings[key])
		if value == "" {
			value = "(none)"
		}
		fmt.Fprintf(out, "  %-12s %s\n", strings.ReplaceAll(key, "_", " ")+":", value)
	}
	verdict := parsed.Verdict
	if len(parsed.Result.Findings) == 0 {
		verdict = "clean"
	}
	fmt.Fprintf(out, "  %-12s %s (%d findings)\n", "verdict:", verdict, len(parsed.Result.Findings))
	for _, finding := range parsed.Result.Findings {
		label := finding.RuleID
		if label == "" {
			label = finding.Scanner
		}
		fmt.Fprintf(out, "    [%s] %s: %s\n", finding.Severity, label, finding.Title)
	}
	return nil
}
