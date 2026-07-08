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

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	agentControlDataFilename = "data-agent-control.json"
	maxAgentControlDataBytes = 64 * 1024
)

// AgentControlPolicyStatus describes the exact supplemental artifact loaded
// into the active OPA store. It deliberately contains no policy values.
type AgentControlPolicyStatus struct {
	Present        bool   `json:"present"`
	Enabled        bool   `json:"enabled"`
	SchemaVersion  int    `json:"schema_version"`
	SourceDigest   string `json:"source_digest,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
}

// EngineStatus is swapped atomically with the OPA store on every successful
// reload, allowing callers to prove which Agent Control artifact is active.
type EngineStatus struct {
	Generation   uint64                   `json:"generation"`
	AgentControl AgentControlPolicyStatus `json:"agent_control"`
}

type agentControlDocument struct {
	AgentControl *agentControlData `json:"agent_control"`
}

type agentControlData struct {
	SchemaVersion *int                   `json:"schema_version"`
	Enabled       *bool                  `json:"enabled"`
	Precedence    string                 `json:"precedence"`
	SourceDigest  string                 `json:"source_digest,omitempty"`
	Guardrail     *agentControlGuardrail `json:"guardrail,omitempty"`
}

type agentControlGuardrail struct {
	BlockThreshold  *int   `json:"block_threshold"`
	AlertThreshold  *int   `json:"alert_threshold"`
	CiscoTrustLevel string `json:"cisco_trust_level"`
}

func disabledAgentControlData() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": 1,
		"enabled":        false,
		"precedence":     "stricter",
	}
}

// loadAgentControlData reserves data.agent_control and strictly validates the
// dedicated supplemental document. Missing data is a valid disabled overlay;
// malformed or unreadable data is an error so Reload retains the previous
// in-memory store.
func loadAgentControlData(regoDir string, data map[string]interface{}) (AgentControlPolicyStatus, error) {
	if _, exists := data["agent_control"]; exists {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: data.agent_control is reserved for %s", agentControlDataFilename)
	}

	path := filepath.Join(regoDir, agentControlDataFilename)
	raw, err := safefile.ReadRegular(path, maxAgentControlDataBytes)
	if errors.Is(err, os.ErrNotExist) {
		data["agent_control"] = disabledAgentControlData()
		return AgentControlPolicyStatus{Enabled: false, SchemaVersion: 1}, nil
	}
	if err != nil {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: read %s: %w", agentControlDataFilename, err)
	}
	var doc agentControlDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: parse %s: %w", agentControlDataFilename, err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: parse %s: %w", agentControlDataFilename, err)
	}
	if doc.AgentControl == nil {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: %s: agent_control is required", agentControlDataFilename)
	}

	normalized, status, err := validateAgentControlData(doc.AgentControl)
	if err != nil {
		return AgentControlPolicyStatus{}, fmt.Errorf("policy: %s: %w", agentControlDataFilename, err)
	}
	sum := sha256.Sum256(raw)
	status.Present = true
	status.ArtifactDigest = "sha256:" + hex.EncodeToString(sum[:])
	data["agent_control"] = normalized
	return status, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values are not allowed")
	}
	return err
}

func validateAgentControlData(in *agentControlData) (map[string]interface{}, AgentControlPolicyStatus, error) {
	if in.SchemaVersion == nil || *in.SchemaVersion != 1 {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("schema_version must be 1")
	}
	if in.Enabled == nil {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("enabled is required")
	}
	if in.Precedence != "stricter" && in.Precedence != "remote" {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("precedence must be stricter or remote")
	}

	status := AgentControlPolicyStatus{Enabled: *in.Enabled, SchemaVersion: 1}
	normalized := map[string]interface{}{
		"schema_version": 1,
		"enabled":        *in.Enabled,
		"precedence":     in.Precedence,
	}
	if !*in.Enabled {
		if in.SourceDigest != "" || in.Guardrail != nil {
			return nil, AgentControlPolicyStatus{}, fmt.Errorf("disabled overlay cannot contain source_digest or guardrail")
		}
		return normalized, status, nil
	}

	if !validSHA256Digest(in.SourceDigest) {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("source_digest must be sha256 followed by 64 lowercase hexadecimal characters")
	}
	if in.Guardrail == nil {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("guardrail is required when enabled")
	}
	if in.Guardrail.BlockThreshold == nil || *in.Guardrail.BlockThreshold < 1 || *in.Guardrail.BlockThreshold > 4 {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("guardrail.block_threshold must be between 1 and 4")
	}
	if in.Guardrail.AlertThreshold == nil || *in.Guardrail.AlertThreshold < 1 || *in.Guardrail.AlertThreshold > 4 {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("guardrail.alert_threshold must be between 1 and 4")
	}
	if *in.Guardrail.AlertThreshold > *in.Guardrail.BlockThreshold {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("guardrail.alert_threshold cannot exceed block_threshold")
	}
	if !validCiscoTrustLevel(in.Guardrail.CiscoTrustLevel) {
		return nil, AgentControlPolicyStatus{}, fmt.Errorf("guardrail.cisco_trust_level must be full, advisory, or none")
	}

	status.SourceDigest = in.SourceDigest
	normalized["source_digest"] = in.SourceDigest
	normalized["guardrail"] = map[string]interface{}{
		"block_threshold":   *in.Guardrail.BlockThreshold,
		"alert_threshold":   *in.Guardrail.AlertThreshold,
		"cisco_trust_level": in.Guardrail.CiscoTrustLevel,
	}
	return normalized, status, nil
}

func validSHA256Digest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	hexPart := strings.TrimPrefix(value, prefix)
	if hexPart != strings.ToLower(hexPart) {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func validCiscoTrustLevel(value string) bool {
	switch value {
	case "full", "advisory", "none":
		return true
	default:
		return false
	}
}
