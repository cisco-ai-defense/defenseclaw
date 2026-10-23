// Optional local content inspection for tool responses.
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"context"
	"errors"
	"math"
	"strings"
)

// LocalToolResponseScanner is inactive until explicitly attached by an embedder.
// Implementations load once before serving and own bounded admission and deadlines.
type LocalToolResponseScanner interface {
	Scan(context.Context, string) (float64, error)
}

// Bound the number of sequential scans, including replayed tool history.
// With the maximum 5-second per-scan budget, this caps local scanning at 80s
// (or the earlier caller deadline). The default budget caps it at 8s.
const maxLocalToolMessages = 16

type localContentBinding struct {
	scanner   LocalToolResponseScanner
	threshold float64
}

func localBinding(scanner LocalToolResponseScanner, threshold float64) (*localContentBinding, error) {
	if scanner == nil {
		return nil, nil
	}
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0 || threshold >= 1 {
		return nil, errors.New("invalid local scanner threshold")
	}
	return &localContentBinding{scanner, threshold}, nil
}

// SetLocalToolResponseScanner attaches a preloaded local scanner.
func (a *APIServer) SetLocalToolResponseScanner(scanner LocalToolResponseScanner, threshold float64) error {
	b, err := localBinding(scanner, threshold)
	if err == nil {
		a.localContent.Store(b)
	}
	return err
}
func (g *GuardrailInspector) SetLocalToolResponseScanner(scanner LocalToolResponseScanner, threshold float64) error {
	b, err := localBinding(scanner, threshold)
	if err == nil {
		g.localContent.Store(b)
	}
	return err
}

func localContentVerdict(ctx context.Context, b *localContentBinding, text string) *ScanVerdict {
	if b == nil {
		return nil
	}
	score, err := b.scanner.Scan(ctx, text)
	if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "local-model:scan-unavailable", Findings: []string{"local-model:scan-unavailable"}, Scanner: "local-model"}
	}
	if score < b.threshold {
		return nil
	}
	return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "local-model:prompt-injection", Findings: []string{"local-model:prompt-injection"}, Scanner: "local-model"}
}

func (a *APIServer) inspectLocalToolResponse(ctx context.Context, text string) *ScanVerdict {
	if a.managedAIDOnly() || (a.decisionConfig(ctx) != nil && a.decisionConfig(ctx).StandaloneEnterprise()) {
		return nil
	}
	return localContentVerdict(ctx, a.localContent.Load(), text)
}

// Only the explicit OpenAI-compatible role=tool boundary is covered by this integration.
// Do not guess provenance from ordinary user text or scan trusted system prompts.
func (g *GuardrailInspector) inspectLocalToolMessages(ctx context.Context, messages []ChatMessage) *ScanVerdict {
	b := g.localContent.Load()
	if b == nil || g.managedMode || secureClientGeneration() {
		return nil
	}
	// Preflight the entire history before scanning: a limit refusal must not
	// spend model budget or poison an otherwise healthy worker.
	count := 0
	for _, m := range messages {
		if strings.EqualFold(m.Role, "tool") {
			count++
		}
		if count > maxLocalToolMessages {
			return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "local-model:tool-message-limit", Findings: []string{"local-model:tool-message-limit"}, Scanner: "local-model"}
		}
	}
	// Worker.Scan owns a fresh per-call timeout; retain the caller context so
	// cancellation still applies, without consuming later scans' budgets.
	for _, m := range messages {
		if !strings.EqualFold(m.Role, "tool") {
			continue
		}
		text := m.Content
		if text == "" && len(m.RawContent) > 0 {
			text = string(m.RawContent)
		}
		if v := localContentVerdict(ctx, b, text); v != nil {
			return v
		}
	}
	return nil
}

// Local scanning must not inherit the prompt heartbeat/startup bypass.
func (p *GuardrailProxy) requiresLocalToolInspection(messages []ChatMessage) bool {
	g, ok := p.inspector.(*GuardrailInspector)
	if !ok || g.localContent.Load() == nil || g.managedMode || secureClientGeneration() {
		return false
	}
	for _, m := range messages {
		if strings.EqualFold(m.Role, "tool") {
			return true
		}
	}
	return false
}
