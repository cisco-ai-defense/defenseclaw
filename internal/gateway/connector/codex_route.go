// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Codex route-only rendering (DESIGN 7.2, 15.8, 18.1): one owned table
// [model_providers.defenseclaw_route] at the end of config.toml and the
// top-level model_provider pointing at it. The wrapped provider settings
// (wire_api, env_key, requires_openai_auth) are copied so the agent keeps
// its own login or key; the gateway forwards to routing.route_only
// .upstreams.codex. Restore puts the original model_provider line back byte
// for byte and deletes the owned table.

const (
	codexRouteProviderID = "defenseclaw_route"
	codexRouteMarker     = "# defenseclaw route-only provider (removed by defenseclaw routing disable)"
	codexRouteKeyLine    = "model_provider_line"
	codexRouteKeyTable   = "table"
	codexRouteKeyNoEOL   = "no_final_newline"
)

type codexWrappedProvider struct {
	ID    string                 `json:"id"`
	Table map[string]interface{} `json:"table,omitempty"`
}

// codexWrappedFields are the provider settings copied from the wrapped
// provider (auth, transport and request shape); base_url and name are ours.
var codexWrappedFields = []string{
	"wire_api", "env_key", "env_key_instructions", "requires_openai_auth", "query_params",
	"http_headers", "env_http_headers", "request_max_retries", "stream_max_retries", "stream_idle_timeout_ms",
}

// codexWrapped reads the provider Codex uses now (built-in openai when
// unset). A profile that sets its own model_provider is refused: routing
// only the top-level provider would leave that profile unrouted.
func codexWrapped(raw []byte) (codexWrappedProvider, error) {
	var doc struct {
		ModelProvider  string                            `toml:"model_provider"`
		Profile        string                            `toml:"profile"`
		Profiles       map[string]map[string]interface{} `toml:"profiles"`
		ModelProviders map[string]map[string]interface{} `toml:"model_providers"`
	}
	if err := parseCodexTOML(raw, &doc); err != nil {
		return codexWrappedProvider{}, fmt.Errorf("parse Codex config: %w", err)
	}
	if p := doc.Profiles[doc.Profile]; doc.Profile != "" && p != nil {
		if mp, _ := p["model_provider"].(string); mp != "" {
			return codexWrappedProvider{}, fmt.Errorf("the active Codex profile %q sets its own model_provider; route-only routes the top-level provider only", doc.Profile)
		}
	}
	id := strings.TrimSpace(doc.ModelProvider)
	if id == "" || id == "openai" {
		return codexWrappedProvider{ID: "openai", Table: map[string]interface{}{"wire_api": "responses", "requires_openai_auth": true}}, nil
	}
	if id == codexRouteProviderID {
		return codexWrappedProvider{}, fmt.Errorf("config.toml already selects %s but DefenseClaw has no record of the provider it wrapped; run defenseclaw-gateway connector route-restore --connector codex, then enable again", codexRouteProviderID)
	}
	t := doc.ModelProviders[id]
	w := codexWrappedProvider{ID: id, Table: map[string]interface{}{"wire_api": "chat"}}
	for _, k := range codexWrappedFields {
		if v, ok := t[k]; ok {
			w.Table[k] = v
		}
	}
	return w, nil
}

func tomlInlineValue(v interface{}) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, byte(0x66), -1, 64)
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, strconv.Quote(k)+" = "+tomlInlineValue(x[k]))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	case []interface{}:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, tomlInlineValue(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return strconv.Quote(fmt.Sprint(v))
}

func codexRouteTable(route *RouteOnlySetup, w codexWrappedProvider, eol string) string {
	lines := []string{
		codexRouteMarker,
		"[model_providers." + codexRouteProviderID + "]",
		"name = \"DefenseClaw route-only\"",
		// No /v1: Codex appends /responses (or /chat/completions) and the
		// gateway joins that to the wrapped provider base_url unchanged.
		"base_url = " + strconv.Quote(strings.TrimRight(route.BaseURL, "/")),
	}
	headers := map[string]interface{}{}
	if h, ok := w.Table["http_headers"].(map[string]interface{}); ok {
		for k, v := range h {
			headers[k] = v
		}
	}
	headers[RouteOnlyHeader] = route.Token
	for _, k := range codexWrappedFields {
		if k == "http_headers" {
			continue
		}
		if v, ok := w.Table[k]; ok {
			lines = append(lines, k+" = "+tomlInlineValue(v))
		}
	}
	lines = append(lines, "supports_websockets = false", "http_headers = "+tomlInlineValue(headers))
	return strings.Join(lines, eol) + eol
}

// rootRegionEnd is the byte offset of the first table header.
func rootRegionEnd(lines []string) int {
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			return i
		}
	}
	return len(lines)
}

func isModelProviderLine(l string) bool {
	t := strings.TrimSpace(l)
	if !strings.HasPrefix(t, "model_provider") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(t, "model_provider"))
	return strings.HasPrefix(rest, "=")
}

// removeCodexRouteTable deletes the owned block: from the marker (or, after
// a lost record, the bare table header) through the end of that table, and
// the blank line the render put before it.
func removeCodexRouteTable(raw string) string {
	start := strings.Index(raw, codexRouteMarker)
	if start < 0 {
		start = strings.Index(raw, "[model_providers."+codexRouteProviderID+"]")
	}
	if start < 0 {
		return raw
	}
	if start > 0 && raw[start-1] != 0x0a {
		return raw
	}
	lines := strings.SplitAfter(raw[start:], "\n")
	end := len(raw)
	off := start
	for j, l := range lines {
		t := strings.TrimSpace(l)
		if j > 0 && strings.HasPrefix(t, "[") && !strings.HasPrefix(t, "[model_providers."+codexRouteProviderID+"]") {
			end = off
			break
		}
		off += len(l)
	}
	head := strings.TrimRight(raw[:start], "\r\n")
	if head != "" {
		head += lineEnding(raw)
	}
	return head + raw[end:]
}

func lineEnding(s string) string {
	if strings.Contains(s, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// renderCodexRoute returns raw with the route applied or removed, and the
// updated record.
func renderCodexRoute(raw []byte, route *RouteOnlySetup, b *routeEnvBackup) ([]byte, error) {
	bom := ""
	text := string(raw)
	if strings.HasPrefix(text, "\ufeff") {
		bom, text = "\ufeff", strings.TrimPrefix(text, "\ufeff")
	}
	eol := lineEnding(text)
	ours := "model_provider = " + strconv.Quote(codexRouteProviderID)
	// Remove the previous render (or our render whose record was lost).
	if _, ok := b.Applied[codexRouteKeyTable]; ok || strings.Contains(text, "[model_providers."+codexRouteProviderID+"]") {
		text = removeCodexRouteTable(text)
		delete(b.Applied, codexRouteKeyTable)
		if _, noEOL := b.Original[codexRouteKeyNoEOL]; noEOL {
			text = strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r")
			delete(b.Original, codexRouteKeyNoEOL)
		}
	}
	lines := strings.SplitAfter(text, "\n")
	end := rootRegionEnd(lines)
	for i := 0; i < end; i++ {
		cur := strings.TrimRight(lines[i], "\r\n")
		applied, recorded := b.Applied[codexRouteKeyLine]
		if !(recorded && cur == applied) && !(isModelProviderLine(lines[i]) && strings.Contains(cur, codexRouteProviderID)) {
			continue
		}
		if orig := b.Original[codexRouteKeyLine]; orig != nil {
			lines[i] = *orig + eol
		} else {
			lines = append(lines[:i], lines[i+1:]...)
		}
		break
	}
	delete(b.Applied, codexRouteKeyLine)
	delete(b.Original, codexRouteKeyLine)
	text = strings.Join(lines, "")
	if route == nil {
		b.Wrapped = nil
		return []byte(bom + text), nil
	}
	w, err := codexWrapped([]byte(text))
	if err != nil {
		return nil, err
	}
	if prev, ok := b.Wrapped["id"].(string); ok && prev != "" {
		// Keep the provider the first render wrapped: the gateway forwards to
		// the upstream recorded at enable, so its key settings must match.
		if prev != w.ID {
			return nil, fmt.Errorf("Codex now selects provider %q but route-only was enabled for %q; run routing disable and enable again", w.ID, prev)
		}
	}
	b.Wrapped = map[string]interface{}{"id": w.ID}
	lines = strings.SplitAfter(text, "\n")
	end = rootRegionEnd(lines)
	replaced := false
	for i := 0; i < end; i++ {
		if isModelProviderLine(lines[i]) {
			orig := strings.TrimRight(lines[i], "\r\n")
			b.Original[codexRouteKeyLine] = &orig
			lines[i] = ours + eol
			replaced = true
			break
		}
	}
	if !replaced {
		b.Original[codexRouteKeyLine] = nil
		lines = append([]string{ours + eol}, lines...)
	}
	b.Applied[codexRouteKeyLine] = ours
	text = strings.Join(lines, "")
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += eol
		marker := "1"
		b.Original[codexRouteKeyNoEOL] = &marker
	}
	table := codexRouteTable(route, w, eol)
	text += eol + table
	b.Applied[codexRouteKeyTable] = table
	return []byte(bom + text), nil
}

// ApplyRouteOnly implements RouteOnlyConnector.
func (c *CodexConnector) ApplyRouteOnly(opts SetupOpts, route *RouteOnlySetup) error {
	path := codexConfigPath()
	if route == nil {
		b, err := loadRouteBackup(opts.DataDir, c.Name())
		if err == nil && len(b.Applied) == 0 {
			raw, rerr := os.ReadFile(path)
			if rerr != nil || !bytes.Contains(raw, []byte(codexRouteProviderID)) {
				return nil
			}
		}
	}
	return withFileLock(path, func() error {
		backup, err := loadRouteBackup(opts.DataDir, c.Name())
		if err != nil {
			return err
		}
		err = atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			if !exists && route == nil {
				return atomicTransformResult{Keep: true}, nil
			}
			out, err := renderCodexRoute(data, route, &backup)
			if err != nil {
				return atomicTransformResult{}, err
			}
			// The record goes first (see claudecode_route.go).
			if err := saveRouteBackup(opts.DataDir, c.Name(), backup); err != nil {
				return atomicTransformResult{}, fmt.Errorf("route backup: %w", err)
			}
			if exists && bytes.Equal(out, data) {
				return atomicTransformResult{Keep: true}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
		if err != nil {
			return fmt.Errorf("codex route-only config: %w", err)
		}
		return nil
	})
}

var _ RouteOnlyConnector = (*CodexConnector)(nil)
