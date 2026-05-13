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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/decisionevidence"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/runtimecatalog"
)

const (
	runtimeCatalogFileEnv      = "DEFENSECLAW_RUNTIME_CATALOG_FILE"
	runtimeCatalogURLEnv       = "DEFENSECLAW_RUNTIME_CATALOG_URL"
	decisionEvidenceEnabledEnv = "DEFENSECLAW_DECISION_EVIDENCE"
)

// DecisionEvidence normalizes the governance/audit evidence emitted by the
// inspect path regardless of whether the signal originated in local scanners,
// catalog metadata, or Agent Control.
type DecisionEvidence = decisionevidence.Record

type runtimeCatalogState struct {
	catalog runtimecatalog.Catalog
	source  string
	err     error
}

var (
	runtimeCatalogMu          sync.Mutex
	runtimeCatalogOnce        sync.Once
	runtimeCatalogGlobalState runtimeCatalogState
)

func runtimeCatalogForRequest() runtimeCatalogState {
	runtimeCatalogOnce.Do(func() {
		runtimeCatalogGlobalState = loadRuntimeCatalogFromEnv()
	})
	return runtimeCatalogGlobalState
}

func loadRuntimeCatalogFromEnv() runtimeCatalogState {
	if path := strings.TrimSpace(os.Getenv(runtimeCatalogFileEnv)); path != "" {
		cat, err := runtimecatalog.LoadStaticCatalogFile(path)
		return runtimeCatalogState{catalog: cat, source: "file:" + path, err: err}
	}
	if u := strings.TrimSpace(os.Getenv(runtimeCatalogURLEnv)); u != "" {
		return runtimeCatalogState{catalog: runtimecatalog.NewHTTPClient(u), source: "http:" + u}
	}
	return runtimeCatalogState{}
}

// setRuntimeCatalogForTesting overrides the process-wide catalog until the
// returned cleanup function is called. It is package-private so production code
// cannot accidentally replace the catalog at runtime.
func setRuntimeCatalogForTesting(c runtimecatalog.Catalog, source string) func() {
	runtimeCatalogMu.Lock()
	defer runtimeCatalogMu.Unlock()
	prevState := runtimeCatalogGlobalState
	prevOnce := runtimeCatalogOnce
	runtimeCatalogGlobalState = runtimeCatalogState{catalog: c, source: source}
	runtimeCatalogOnce = sync.Once{}
	runtimeCatalogOnce.Do(func() {})
	return func() {
		runtimeCatalogMu.Lock()
		defer runtimeCatalogMu.Unlock()
		runtimeCatalogGlobalState = prevState
		runtimeCatalogOnce = prevOnce
	}
}

func agentControlRuntimeCatalogContext(ctx context.Context, tool string, input any, extra map[string]any) map[string]any {
	out := copyContextMap(extra)
	catalog := runtimeCatalogEvidence(ctx, tool, input)
	if catalog == nil {
		return out
	}
	out["runtime_catalog"] = catalog.ContextMap()
	out["runtime_resource_id"] = catalog.ResourceID
	out["runtime_resource_type"] = catalog.ResourceType
	out["runtime_resource_path"] = catalog.ResourcePath
	out["runtime_sensitivity_domain"] = catalog.SensitivityDomain
	out["runtime_requires_approval"] = catalog.RequiresApproval
	return out
}

func runtimeCatalogEvidence(ctx context.Context, tool string, input any) *decisionevidence.CatalogResource {
	ref := runtimecatalog.InferResource(tool, input)
	if ref.ID == "" {
		return nil
	}
	state := runtimeCatalogForRequest()
	if state.err != nil || state.catalog == nil {
		if !decisionEvidenceEnabled() {
			return nil
		}
		return &decisionevidence.CatalogResource{
			ResourceID:   ref.ID,
			ResourceType: ref.Type,
			ResourcePath: ref.Path,
			Registered:   false,
			Source:       state.source,
		}
	}
	entry, err := state.catalog.Lookup(ctx, ref.Type, ref.Path)
	if err != nil {
		if !decisionEvidenceEnabled() && !errors.Is(err, runtimecatalog.ErrNotFound) {
			return nil
		}
		return &decisionevidence.CatalogResource{
			ResourceID:   ref.ID,
			ResourceType: ref.Type,
			ResourcePath: ref.Path,
			Registered:   false,
			Source:       state.source,
		}
	}
	return &decisionevidence.CatalogResource{
		ResourceID:        entry.ResourceID,
		ResourceType:      entry.ResourceType,
		ResourcePath:      entry.ResourcePath,
		Owner:             entry.Owner,
		SensitivityDomain: entry.SensitivityDomain,
		PIIFields:         append([]string(nil), entry.PIIFields...),
		AllowedAgents:     append([]string(nil), entry.AllowedAgents...),
		AllowedScopes:     append([]string(nil), entry.AllowedScopes...),
		RequiresApproval:  entry.RequiresApproval,
		Tags:              entry.Tags,
		Registered:        true,
		Source:            state.source,
	}
}

func buildRuntimeDecisionEvidence(ctx context.Context, stage string, req *ToolInspectRequest, verdict *ToolInspectVerdict, elapsed time.Duration) *DecisionEvidence {
	if req == nil || verdict == nil {
		return nil
	}
	input := agentControlRawJSONValue(req.Args)
	catalog := runtimeCatalogEvidence(ctx, req.Tool, input)
	if catalog == nil && !decisionEvidenceEnabled() {
		return nil
	}
	id := AgentIdentityFromContext(ctx)
	rec := decisionevidence.Record{
		RequestID:   RequestIDFromContext(ctx),
		SessionID:   firstNonEmpty(req.SessionID, SessionIDFromContext(ctx)),
		TraceID:     TraceIDFromContext(ctx),
		AgentID:     id.AgentID,
		Stage:       stage,
		Tool:        req.Tool,
		Decision:    verdict.Action,
		RawDecision: verdict.RawAction,
		Severity:    verdict.Severity,
		Reason:      redaction.ForSinkReason(verdict.Reason),
		Sources:     evidenceSources(verdict),
		Findings:    append([]string(nil), verdict.Findings...),
		Catalog:     catalog,
		LatencyMs:   elapsed.Milliseconds(),
	}.Normalize()
	return &rec
}

func appendRuntimeDecisionEvidenceAudit(details string, evidence *DecisionEvidence) string {
	if evidence == nil {
		return details
	}
	encoded := evidence.AuditString()
	if encoded == "{}" || encoded == "" {
		return details
	}
	return details + " decision_evidence=" + encoded
}

func evidenceSources(verdict *ToolInspectVerdict) []string {
	if verdict == nil {
		return nil
	}
	sources := []string{}
	for _, finding := range verdict.Findings {
		prefix := finding
		if idx := strings.Index(prefix, ":"); idx >= 0 {
			prefix = prefix[:idx]
		}
		switch prefix {
		case "agent-control":
			sources = append(sources, "agent-control")
		case "codeguard":
			sources = append(sources, "codeguard")
		case "behavioral":
			sources = append(sources, "behavioral")
		case "response-protection":
			sources = append(sources, "response-protection")
		default:
			if prefix != "" {
				sources = append(sources, "local-policy")
			}
		}
	}
	if len(sources) == 0 {
		sources = append(sources, "local-policy")
	}
	return sources
}

func decisionEvidenceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(decisionEvidenceEnabledEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func copyContextMap(extra map[string]any) map[string]any {
	out := make(map[string]any, len(extra)+8)
	for k, v := range extra {
		if v != nil {
			out[k] = v
		}
	}
	return out
}

func runtimeEvidenceJSON(e *DecisionEvidence) string {
	if e == nil {
		return ""
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("{\"error\":%q}", err.Error())
	}
	return string(data)
}
