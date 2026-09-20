// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

func TestManagedInventoryStructuredEncodersEnforceExactBounds(t *testing.T) {
	connectorItems := make([]TelemetryStructuredDefenseClawInventoryConnectorIdentifier, 128)
	for index := range connectorItems {
		connectorItems[index].Name = "connector"
	}
	if _, err := encodeTelemetryStructuredDefenseClawInventoryConnectorIdentifiers(
		TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
		TelemetryStructuredDefenseClawInventoryConnectorIdentifiers{Items: connectorItems},
		true,
	); err != nil {
		t.Fatalf("exact connector bound rejected: %v", err)
	}
	connectorItems = append(connectorItems, TelemetryStructuredDefenseClawInventoryConnectorIdentifier{Name: "overflow"})
	if _, err := encodeTelemetryStructuredDefenseClawInventoryConnectorIdentifiers(
		TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
		TelemetryStructuredDefenseClawInventoryConnectorIdentifiers{Items: connectorItems},
		true,
	); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("connector max+1 error=%v", err)
	}

	mcpItems := make([]TelemetryStructuredDefenseClawInventoryMcpIdentifier, 256)
	for index := range mcpItems {
		mcpItems[index].Name = "mcp"
	}
	if _, err := encodeTelemetryStructuredDefenseClawInventoryMcpIdentifiers(
		TelemetryAttributeDefenseClawInventoryMcpIdentifiers,
		TelemetryStructuredDefenseClawInventoryMcpIdentifiers{Items: mcpItems},
		true,
	); err != nil {
		t.Fatalf("exact MCP bound rejected: %v", err)
	}
	mcpItems = append(mcpItems, TelemetryStructuredDefenseClawInventoryMcpIdentifier{Name: "overflow"})
	if _, err := encodeTelemetryStructuredDefenseClawInventoryMcpIdentifiers(
		TelemetryAttributeDefenseClawInventoryMcpIdentifiers,
		TelemetryStructuredDefenseClawInventoryMcpIdentifiers{Items: mcpItems},
		true,
	); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("MCP max+1 error=%v", err)
	}

	agentItems := make([]TelemetryStructuredDefenseClawInventoryAgentIdentifier, 65)
	for index := range agentItems {
		agentItems[index].Name = "codex"
	}
	if _, err := encodeTelemetryStructuredDefenseClawInventoryAgentIdentifiers(
		TelemetryAttributeDefenseClawInventoryAgentIdentifiers,
		TelemetryStructuredDefenseClawInventoryAgentIdentifiers{Items: agentItems},
		true,
	); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("agent max+1 error=%v", err)
	}
}

func TestManagedInventoryStructuredEncodersRejectInvalidLeafSemantics(t *testing.T) {
	tests := []struct {
		name   string
		encode func() error
	}{
		{
			name: "connector slash name",
			encode: func() error {
				_, err := encodeTelemetryStructuredDefenseClawInventoryConnectorIdentifiers(
					TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
					TelemetryStructuredDefenseClawInventoryConnectorIdentifiers{Items: []TelemetryStructuredDefenseClawInventoryConnectorIdentifier{{Name: "plugin/name"}}},
					true,
				)
				return err
			},
		},
		{
			name: "connector source enum",
			encode: func() error {
				_, err := encodeTelemetryStructuredDefenseClawInventoryConnectorMetadata(
					TelemetryAttributeDefenseClawInventoryConnectorMetadata,
					TelemetryStructuredDefenseClawInventoryConnectorMetadata{Items: []TelemetryStructuredDefenseClawInventoryConnectorMetadataItem{{
						Source: "remote", ToolInspectionMode: "both", SubprocessPolicy: "none",
					}}},
					true,
				)
				return err
			},
		},
		{
			name: "MCP URL host credentials",
			encode: func() error {
				_, err := encodeTelemetryStructuredDefenseClawInventoryMcpIdentifiers(
					TelemetryAttributeDefenseClawInventoryMcpIdentifiers,
					TelemetryStructuredDefenseClawInventoryMcpIdentifiers{Items: []TelemetryStructuredDefenseClawInventoryMcpIdentifier{{
						Name: "mcp", URLHost: Present("user:password@example.test"),
					}}},
					true,
				)
				return err
			},
		},
		{
			name: "agent path hash",
			encode: func() error {
				_, err := encodeTelemetryStructuredDefenseClawInventoryAgentIdentifiers(
					TelemetryAttributeDefenseClawInventoryAgentIdentifiers,
					TelemetryStructuredDefenseClawInventoryAgentIdentifiers{Items: []TelemetryStructuredDefenseClawInventoryAgentIdentifier{{
						Name: "codex", ConfigPathHash: Present("sha256:not-a-digest"),
					}}},
					true,
				)
				return err
			},
		},
		{
			name: "agent probe status",
			encode: func() error {
				_, err := encodeTelemetryStructuredDefenseClawInventoryAgentMetadata(
					TelemetryAttributeDefenseClawInventoryAgentMetadata,
					TelemetryStructuredDefenseClawInventoryAgentMetadata{Items: []TelemetryStructuredDefenseClawInventoryAgentMetadataItem{{
						Installed: true, HasConfig: false, HasBinary: false, ProbeStatus: "invented",
					}}},
					true,
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.encode(); !IsFamilyBuildError(err, FamilyBuildConstraint) {
				t.Fatalf("invalid managed inventory leaf error=%v", err)
			}
		})
	}
}
