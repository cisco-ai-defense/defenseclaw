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

// Package decisionevidence defines a compact evidence envelope for runtime
// governance decisions. It is intentionally policy-engine agnostic so local
// scanners, OPA, Galileo Agent Control, catalog enrichment, and future risk
// signals can all contribute fields without changing enforcement semantics.
package decisionevidence

import (
	"encoding/json"
	"sort"
	"strings"
)

const SchemaVersion = "defenseclaw.runtime_decision_evidence.v0.1"

// CatalogResource captures resource metadata attached to a decision.
type CatalogResource struct {
	ResourceID        string            `json:"resource_id,omitempty"`
	ResourceType      string            `json:"resource_type,omitempty"`
	ResourcePath      string            `json:"resource_path,omitempty"`
	Owner             string            `json:"owner,omitempty"`
	SensitivityDomain string            `json:"sensitivity_domain,omitempty"`
	PIIFields         []string          `json:"pii_fields,omitempty"`
	AllowedAgents     []string          `json:"allowed_agents,omitempty"`
	AllowedScopes     []string          `json:"allowed_scopes,omitempty"`
	RequiresApproval  bool              `json:"requires_approval,omitempty"`
	Registered        bool              `json:"registered"`
	Source            string            `json:"source,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// Record is emitted in responses and audit details for runtime decisions.
type Record struct {
	SchemaVersion string           `json:"schema_version"`
	RequestID     string           `json:"request_id,omitempty"`
	SessionID     string           `json:"session_id,omitempty"`
	TraceID       string           `json:"trace_id,omitempty"`
	AgentID       string           `json:"agent_id,omitempty"`
	Stage         string           `json:"stage,omitempty"`
	Tool          string           `json:"tool,omitempty"`
	Decision      string           `json:"decision,omitempty"`
	RawDecision   string           `json:"raw_decision,omitempty"`
	Severity      string           `json:"severity,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	Sources       []string         `json:"sources,omitempty"`
	Findings      []string         `json:"findings,omitempty"`
	Catalog       *CatalogResource `json:"catalog,omitempty"`
	LatencyMs     int64            `json:"latency_ms,omitempty"`
}

// Normalize returns a copy with defaults and deterministic ordering.
func (r Record) Normalize() Record {
	if strings.TrimSpace(r.SchemaVersion) == "" {
		r.SchemaVersion = SchemaVersion
	}
	r.Sources = normalizeStrings(r.Sources)
	r.Findings = normalizeStrings(r.Findings)
	return r
}

// AuditString renders the evidence as compact JSON for audit details.
func (r Record) AuditString() string {
	r = r.Normalize()
	data, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// ContextMap converts catalog metadata to a map that can be sent to external
// runtime-control engines such as Galileo Agent Control.
func (c CatalogResource) ContextMap() map[string]any {
	out := map[string]any{
		"registered":         c.Registered,
		"resource_id":        c.ResourceID,
		"resource_type":      c.ResourceType,
		"resource_path":      c.ResourcePath,
		"owner":              c.Owner,
		"sensitivity_domain": c.SensitivityDomain,
		"pii_fields":         c.PIIFields,
		"allowed_agents":     c.AllowedAgents,
		"allowed_scopes":     c.AllowedScopes,
		"requires_approval":  c.RequiresApproval,
		"source":             c.Source,
	}
	if len(c.Tags) > 0 {
		out["tags"] = c.Tags
	}
	return out
}

func normalizeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
