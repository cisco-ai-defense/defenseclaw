// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const openclawUsageExportInterval = 5 * time.Minute

type openclawUsageTotals struct {
	Input              int64   `json:"input"`
	Output             int64   `json:"output"`
	CacheRead          int64   `json:"cacheRead"`
	CacheWrite         int64   `json:"cacheWrite"`
	TotalTokens        int64   `json:"totalTokens"`
	InputCost          float64 `json:"inputCost"`
	OutputCost         float64 `json:"outputCost"`
	CacheReadCost      float64 `json:"cacheReadCost"`
	CacheWriteCost     float64 `json:"cacheWriteCost"`
	TotalCost          float64 `json:"totalCost"`
	MissingCostEntries int64   `json:"missingCostEntries"`
}

type openclawUsageResponse struct {
	Aggregates struct {
		ByModel []struct {
			Provider string              `json:"provider"`
			Model    string              `json:"model"`
			Count    int64               `json:"count"`
			Totals   openclawUsageTotals `json:"totals"`
		} `json:"byModel"`
		Messages struct {
			Assistant   int64 `json:"assistant"`
			Errors      int64 `json:"errors"`
			ToolCalls   int64 `json:"toolCalls"`
			ToolResults int64 `json:"toolResults"`
			Total       int64 `json:"total"`
			User        int64 `json:"user"`
		} `json:"messages"`
		Tools struct {
			TotalCalls  int64 `json:"totalCalls"`
			UniqueTools int64 `json:"uniqueTools"`
			Tools       []struct {
				Name  string `json:"name"`
				Count int64  `json:"count"`
			} `json:"tools"`
		} `json:"tools"`
		Latency struct {
			AvgMS float64 `json:"avgMs"`
			Count int64   `json:"count"`
			MaxMS float64 `json:"maxMs"`
			MinMS float64 `json:"minMs"`
			P95MS float64 `json:"p95Ms"`
		} `json:"latency"`
	} `json:"aggregates"`
}

func (s *Sidecar) startOpenClawUsageExporter(ctx context.Context) {
	if s == nil || s.client == nil || s.logger == nil {
		return
	}
	go func() {
		s.exportOpenClawUsageSnapshot(ctx)
		ticker := time.NewTicker(openclawUsageExportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.exportOpenClawUsageSnapshot(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Sidecar) exportOpenClawUsageSnapshot(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	now := time.Now().UTC()
	params := map[string]any{
		"startDate":            now.Add(-24 * time.Hour).Format("2006-01-02"),
		"endDate":              now.Format("2006-01-02"),
		"mode":                 "utc",
		"limit":                1000,
		"includeContextWeight": false,
	}
	raw, err := s.client.Request(reqCtx, "sessions.usage", params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] openclaw usage snapshot export failed: %v\n", err)
		return
	}
	metrics := openclawUsageMetricsFromResponse(raw)
	for i := range metrics {
		if s.cfg != nil {
			metrics[i].gatewayHost = s.cfg.Gateway.Host
		}
	}
	persistDashboardMetricAuditEvents(s.logger, s.store, "openclaw", "", "openclaw:usage:snapshot", metrics)
}

func openclawUsageMetricsFromResponse(raw []byte) []otelDashboardMetric {
	var resp openclawUsageResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}
	out := make([]otelDashboardMetric, 0, len(resp.Aggregates.ByModel)*7+8)
	for _, row := range resp.Aggregates.ByModel {
		provider := firstNonEmpty(row.Provider, "unknown")
		model := firstNonEmpty(row.Model, "unknown")
		out = appendUsageTokenMetric(out, "openclaw.tokens", row.Totals.TotalTokens, provider, model, "total")
		out = appendUsageTokenMetric(out, "openclaw.tokens.input", row.Totals.Input, provider, model, "input")
		out = appendUsageTokenMetric(out, "openclaw.tokens.output", row.Totals.Output, provider, model, "output")
		out = appendUsageTokenMetric(out, "openclaw.tokens.cache_read", row.Totals.CacheRead, provider, model, "cache_read")
		out = appendUsageTokenMetric(out, "openclaw.tokens.cache_write", row.Totals.CacheWrite, provider, model, "cache_write")
		out = appendUsageFloatMetric(out, "openclaw.cost.usd", row.Totals.TotalCost, "usd", provider, model, "cost")
		out = appendUsageFloatMetric(out, "openclaw.messages.assistant", float64(row.Count), "1", provider, model, "usage")
	}
	out = appendUsageFloatMetric(out, "openclaw.messages.total", float64(resp.Aggregates.Messages.Total), "1", "openclaw", "all", "usage")
	out = appendUsageFloatMetric(out, "openclaw.messages.errors", float64(resp.Aggregates.Messages.Errors), "1", "openclaw", "all", "usage")
	out = appendUsageFloatMetric(out, "openclaw.tool.calls", float64(resp.Aggregates.Tools.TotalCalls), "1", "openclaw", "all", "tool")
	out = appendUsageFloatMetric(out, "openclaw.tool.unique", float64(resp.Aggregates.Tools.UniqueTools), "1", "openclaw", "all", "tool")
	out = appendUsageFloatMetric(out, "openclaw.latency.avg_ms", resp.Aggregates.Latency.AvgMS, "ms", "openclaw", "all", "latency")
	out = appendUsageFloatMetric(out, "openclaw.latency.p95_ms", resp.Aggregates.Latency.P95MS, "ms", "openclaw", "all", "latency")
	out = appendUsageFloatMetric(out, "openclaw.latency.max_ms", resp.Aggregates.Latency.MaxMS, "ms", "openclaw", "all", "latency")
	return out
}

func appendUsageTokenMetric(out []otelDashboardMetric, name string, value int64, provider, model, tokenType string) []otelDashboardMetric {
	if value <= 0 {
		return out
	}
	return append(out, otelDashboardMetric{
		metricName:   name,
		value:        float64(value),
		unit:         "tokens",
		provider:     provider,
		model:        model,
		operation:    "chat",
		tokenType:    tokenType,
		channel:      "usage",
		component:    "openclaw_usage_rpc",
		temporality:  "snapshot",
		sourceSignal: "openclaw_rpc",
	})
}

func appendUsageFloatMetric(out []otelDashboardMetric, name string, value float64, unit, provider, model, operation string) []otelDashboardMetric {
	if value <= 0 {
		return out
	}
	return append(out, otelDashboardMetric{
		metricName:   name,
		value:        value,
		unit:         unit,
		provider:     provider,
		model:        model,
		operation:    operation,
		channel:      "usage",
		component:    "openclaw_usage_rpc",
		temporality:  "snapshot",
		sourceSignal: "openclaw_rpc",
	})
}
