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

package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// restrictionRules maps known restriction names to resource prefix patterns.
// A restriction blocks any resource that matches one of its patterns.
var restrictionRules = map[string][]string{
	"no_external_http": {"http.", "external_http."},
	"no_bulk_export":   {"*.export_all", "*.bulk_export"},
	"no_write":         {"*.create_*", "*.update_*", "*.set_*", "*.add_*", "*.post_*"},
	"no_delete":        {"*.delete_*", "*.remove_*"},
}

// Evaluator evaluates capability-based access control decisions.
type Evaluator struct {
	policies  map[string]*AgentPolicy
	store     *audit.Store
	policyDir string
}

// NewEvaluator loads all capability manifests from policyDir.
func NewEvaluator(ctx context.Context, policyDir string, store *audit.Store) (*Evaluator, error) {
	policies, errs := LoadAllPolicies(ctx, policyDir)
	for _, err := range errs {
		fmt.Printf("warning: %v\n", err)
	}

	return &Evaluator{
		policies:  policies,
		store:     store,
		policyDir: policyDir,
	}, nil
}

// Evaluate runs the capability evaluation pipeline for a request.
func (e *Evaluator) Evaluate(ctx context.Context, req EvalRequest) Decision {
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}

	dec := e.evaluate(ctx, req)

	// Log decision to audit store
	if e.store != nil {
		paramsJSON := ""
		if req.Params != nil {
			if data, err := json.Marshal(req.Params); err == nil {
				paramsJSON = string(data)
			}
		}
		_ = e.store.LogCapabilityDecision(req.Agent, req.Resource, paramsJSON, dec.Allowed, dec.Reason, dec.Capability)

		// Record call for rate limiting if allowed
		if dec.Allowed {
			_ = e.store.RecordCapabilityCall(req.Agent, req.Resource, req.Timestamp)
		}
	}

	return dec
}

func (e *Evaluator) evaluate(_ context.Context, req EvalRequest) Decision {
	// Step 1: Load agent policy
	pol, ok := e.policies[req.Agent]
	if !ok {
		return Deny("unknown agent")
	}

	// Step 2: Check restrictions
	if reason := checkRestrictions(pol.Restrictions, req.Resource); reason != "" {
		return Deny("restricted: " + reason)
	}

	// Step 3: Check conditions
	if reason := e.checkConditions(pol, req); reason != "" {
		return Deny("condition: " + reason)
	}

	// Step 4+5: Match capabilities and evaluate constraints
	for _, cap := range pol.Capabilities {
		if !matchResource(cap.Resource, req.Resource) {
			continue
		}
		if MatchConstraints(cap.Constraints, req.Params) {
			return Allow(cap.Name)
		}
	}

	// No capability matched
	if hasResourceMatch(pol.Capabilities, req.Resource) {
		return Deny("constraint mismatch")
	}
	return Deny("no capability for resource")
}

// Reload reloads all capability manifests from the policy directory.
func (e *Evaluator) Reload(ctx context.Context, policyDir string) error {
	if policyDir != "" {
		e.policyDir = policyDir
	}
	policies, errs := LoadAllPolicies(ctx, e.policyDir)
	for _, err := range errs {
		fmt.Printf("warning: %v\n", err)
	}
	e.policies = policies
	return nil
}

// Policies returns the loaded agent policies (for CLI/TUI display).
func (e *Evaluator) Policies() map[string]*AgentPolicy {
	return e.policies
}

func checkRestrictions(restrictions []string, resource string) string {
	for _, r := range restrictions {
		patterns, ok := restrictionRules[r]
		if !ok {
			continue
		}
		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, resource)
			if err == nil && matched {
				return r
			}
		}
	}
	return ""
}

func (e *Evaluator) checkConditions(pol *AgentPolicy, req EvalRequest) string {
	cond := pol.Conditions

	// Time window check
	if cond.TimeWindow != "" {
		if reason := checkTimeWindow(cond.TimeWindow, req.Timestamp); reason != "" {
			return reason
		}
	}

	// Environment check
	if len(cond.Environments) > 0 && req.Environment != "" {
		found := false
		for _, env := range cond.Environments {
			if env == req.Environment {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("environment %q not allowed", req.Environment)
		}
	}

	// Rate limit check
	if cond.RateLimit != nil && e.store != nil {
		rl := cond.RateLimit
		windowStart := req.Timestamp.Add(-time.Duration(rl.WindowSeconds) * time.Second)
		count, err := e.store.CountCapabilityCalls(req.Agent, windowStart, req.Timestamp)
		if err != nil {
			return "rate limit check failed"
		}
		if count >= rl.MaxCalls {
			return "rate limit exceeded"
		}
	}

	return ""
}

func checkTimeWindow(window string, ts time.Time) string {
	parts := strings.SplitN(window, "-", 2)
	if len(parts) != 2 {
		return ""
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	start, err := time.Parse("15:04", startStr)
	if err != nil {
		return ""
	}
	end, err := time.Parse("15:04", endStr)
	if err != nil {
		return ""
	}

	current := time.Date(0, 1, 1, ts.Hour(), ts.Minute(), 0, 0, time.UTC)
	startTime := time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
	endTime := time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)

	if startTime.Before(endTime) {
		// Normal window: 09:00-18:00
		if current.Before(startTime) || !current.Before(endTime) {
			return fmt.Sprintf("outside time window %s", window)
		}
	} else {
		// Midnight-crossing window: 22:00-06:00
		if current.Before(startTime) && !current.Before(endTime) {
			return fmt.Sprintf("outside time window %s", window)
		}
	}

	return ""
}

// matchResource checks if a capability's resource pattern matches a request resource.
// Supports exact match and glob patterns (e.g., "jira.*" matches "jira.get_issue").
func matchResource(pattern, resource string) bool {
	if pattern == resource {
		return true
	}
	matched, err := filepath.Match(pattern, resource)
	if err != nil {
		return false
	}
	return matched
}

func hasResourceMatch(caps []Capability, resource string) bool {
	for _, cap := range caps {
		if matchResource(cap.Resource, resource) {
			return true
		}
	}
	return false
}
