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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// hiltPreviewWireVersion is the version of the JSON hilt-preview prints;
// defenseclaw guardrail hilt (cli/defenseclaw/config_inspect.py) checks it.
const hiltPreviewWireVersion = 1

var connectorHILTPreviewCmd = &cobra.Command{
	Use:   "hilt-preview",
	Short: "Print what a connector HILT block would do (run by defenseclaw guardrail hilt)",
	Long: `Load config.yaml as the gateway does and print, as JSON, the hook mode and
HILT block the gateway would give the connector's calls once the given HILT
block is saved for it: for accounts no guardrail profile matches, then for
each guardrail profile. 'defenseclaw guardrail hilt on|off --connector'
prints its preview from this answer. Nothing is changed.`,
	Hidden: true,
	Args:   cobra.NoArgs,
	// It reads the config only: no audit store, no PID registration.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	Annotations:       map[string]string{auditOptionalAnnotation: "true"},
	RunE:              runConnectorHILTPreview,
}

var (
	hiltPreviewEnabled     bool
	hiltPreviewMinSeverity string
	hiltPreviewConfigPath  string
)

func init() {
	connectorHILTPreviewCmd.Flags().BoolVar(&hiltPreviewEnabled, "enabled", false,
		"the HILT block's enabled value")
	connectorHILTPreviewCmd.Flags().StringVar(&hiltPreviewMinSeverity, "min-severity", "HIGH",
		"the HILT block's min_severity (LOW, MEDIUM, HIGH or CRITICAL)")
	connectorHILTPreviewCmd.Flags().StringVar(&hiltPreviewConfigPath, "config", "",
		"config.yaml to read (default: the gateway's)")
	connectorCmd.AddCommand(connectorHILTPreviewCmd)
}

type hiltPreviewWireHILT struct {
	Enabled     bool   `json:"enabled"`
	MinSeverity string `json:"min_severity"`
}

type hiltPreviewWireScope struct {
	Profile              string              `json:"profile,omitempty"`
	Mode                 string              `json:"mode"`
	HILT                 hiltPreviewWireHILT `json:"hilt"`
	FollowsConnectorHILT bool                `json:"follows_connector_hilt"`
}

type hiltPreviewWire struct {
	WireVersion int                    `json:"wire_version"`
	Connector   string                 `json:"connector"`
	Base        hiltPreviewWireScope   `json:"base"`
	Profiles    []hiltPreviewWireScope `json:"profiles"`
}

func hiltPreviewScopeWire(scope config.HILTPreviewScope) hiltPreviewWireScope {
	return hiltPreviewWireScope{
		Profile: scope.Profile,
		Mode:    scope.Mode,
		HILT:    hiltPreviewWireHILT{Enabled: scope.HILT.Enabled, MinSeverity: scope.HILT.MinSeverity},
		// The profile's own HILT block replaces the connector's when false.
		FollowsConnectorHILT: scope.FollowsConnectorHILT,
	}
}

func runConnectorHILTPreview(cmd *cobra.Command, _ []string) error {
	name := config.NormalizeConnectorName(connectorFlagName)
	if name == "" {
		return errors.New("connector hilt-preview: --connector is required")
	}
	severity := strings.ToUpper(strings.TrimSpace(hiltPreviewMinSeverity))
	switch severity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return fmt.Errorf("connector hilt-preview: --min-severity %q is not LOW, MEDIUM, HIGH or CRITICAL", hiltPreviewMinSeverity)
	}
	path := strings.TrimSpace(hiltPreviewConfigPath)
	if path == "" {
		path = config.ConfigPath()
	}
	loaded, _, err := loadGatewayConfigV8(path)
	if err != nil {
		return fmt.Errorf("connector hilt-preview: %w", err)
	}
	preview, err := loaded.PreviewConnectorHILT(name, config.HILTConfig{Enabled: hiltPreviewEnabled, MinSeverity: severity})
	if err != nil {
		return fmt.Errorf("connector hilt-preview: %w", err)
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetEscapeHTML(false)
	wire := hiltPreviewWire{
		WireVersion: hiltPreviewWireVersion,
		Connector:   preview.Connector,
		Base:        hiltPreviewScopeWire(preview.Base),
		Profiles:    make([]hiltPreviewWireScope, 0, len(preview.Profiles)),
	}
	for _, scope := range preview.Profiles {
		wire.Profiles = append(wire.Profiles, hiltPreviewScopeWire(scope))
	}
	return encoder.Encode(wire)
}
