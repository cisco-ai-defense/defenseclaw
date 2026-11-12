// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
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
	id                 string
	wireAPI            string
	envKey             string
	requiresOpenAIAuth bool
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
		return codexWrappedProvider{id: "openai", wireAPI: "responses", requiresOpenAIAuth: true}, nil
	}
	if id == codexRouteProviderID {
		return codexWrappedProvider{id: id}, nil
	}
	t := doc.ModelProviders[id]
	w := codexWrappedProvider{id: id, wireAPI: "chat"}
	if v, _ := t["wire_api"].(string); v != "" {
		w.wireAPI = v
	}
	w.envKey, _ = t["env_key"].(string)
	w.requiresOpenAIAuth, _ = t["requires_openai_auth"].(bool)
	return w, nil
}

func codexRouteTable(route *RouteOnlySetup, w codexWrappedProvider) string {
	var b strings.Builder
	b.WriteString(codexRouteMarker + "\n")
	b.WriteString("[model_providers." + codexRouteProviderID + "]\n")
	b.WriteString("name = \"DefenseClaw route-only\"\n")
	// No /v1: Codex appends /responses (or /chat/completions) and the
	// gateway joins that to the wrapped provider base_url unchanged.
	b.WriteString("base_url = " + strconv.Quote(strings.TrimRight(route.BaseURL, "/")) + "\n")
	b.WriteString("wire_api = " + strconv.Quote(w.wireAPI) + "\n")
	if w.envKey != "" {
		b.WriteString("env_key = " + strconv.Quote(w.envKey) + "\n")
	}
	if w.requiresOpenAIAuth {
		b.WriteString("requires_openai_auth = true\n")
	}
	b.WriteString("supports_websockets = false\n")
	b.WriteString("http_headers = { " + strconv.Quote(RouteOnlyHeader) + " = " + strconv.Quote(route.Token) + " }\n")
	return b.String()
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

// removeCodexRouteTable deletes the owned block (marker through the end of
// its table) and the blank line the render put before it.
func removeCodexRouteTable(raw string) string {
	i := strings.Index(raw, codexRouteMarker+"\n")
	if i < 0 {
		return raw
	}
	rest := raw[i+len(codexRouteMarker)+1:]
	end := len(rest)
	lines := strings.SplitAfter(rest, "\n")
	off := 0
	for j, l := range lines {
		if j > 0 && strings.HasPrefix(strings.TrimSpace(l), "[") {
			end = off
			break
		}
		off += len(l)
	}
	head := raw[:i]
	head = strings.TrimSuffix(head, "\n")
	if !strings.HasSuffix(head, "\n") && head != "" {
		head += "\n"
	}
	return head + rest[end:]
}

// renderCodexRoute returns raw with the route applied or removed, and the
// updated record.
func renderCodexRoute(raw []byte, route *RouteOnlySetup, b *routeEnvBackup) ([]byte, error) {
	text := string(raw)
	// Remove the previous render first (repair and disable share this).
	if _, ok := b.Applied[codexRouteKeyTable]; ok {
		text = removeCodexRouteTable(text)
		delete(b.Applied, codexRouteKeyTable)
		if _, noEOL := b.Original[codexRouteKeyNoEOL]; noEOL {
			text = strings.TrimSuffix(text, "\n")
			delete(b.Original, codexRouteKeyNoEOL)
		}
	}
	lines := strings.SplitAfter(text, "\n")
	if applied, ok := b.Applied[codexRouteKeyLine]; ok {
		end := rootRegionEnd(lines)
		for i := 0; i < end; i++ {
			if strings.TrimRight(lines[i], "\r\n") != applied {
				continue
			}
			if orig := b.Original[codexRouteKeyLine]; orig != nil {
				lines[i] = *orig + "\n"
			} else {
				lines = append(lines[:i], lines[i+1:]...)
			}
			break
		}
		delete(b.Applied, codexRouteKeyLine)
		delete(b.Original, codexRouteKeyLine)
		text = strings.Join(lines, "")
	}
	if route == nil {
		return []byte(text), nil
	}
	w, err := codexWrapped([]byte(text))
	if err != nil {
		return nil, err
	}
	lines = strings.SplitAfter(text, "\n")
	ours := "model_provider = " + strconv.Quote(codexRouteProviderID)
	end := rootRegionEnd(lines)
	replaced := false
	for i := 0; i < end; i++ {
		if isModelProviderLine(lines[i]) {
			orig := strings.TrimRight(lines[i], "\r\n")
			b.Original[codexRouteKeyLine] = &orig
			lines[i] = ours + "\n"
			replaced = true
			break
		}
	}
	if !replaced {
		b.Original[codexRouteKeyLine] = nil
		lines = append([]string{ours + "\n"}, lines...)
	}
	b.Applied[codexRouteKeyLine] = ours
	text = strings.Join(lines, "")
	table := codexRouteTable(route, w)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
		marker := "1"
		b.Original[codexRouteKeyNoEOL] = &marker
	}
	text += "\n" + table
	b.Applied[codexRouteKeyTable] = table
	return []byte(text), nil
}

// ApplyRouteOnly implements RouteOnlyConnector.
func (c *CodexConnector) ApplyRouteOnly(opts SetupOpts, route *RouteOnlySetup) error {
	path := codexConfigPath()
	// Nothing rendered and nothing to render: touch no file (the lock would
	// create the agent config directory).
	if route == nil {
		if b, err := loadRouteBackup(opts.DataDir, c.Name()); err == nil && len(b.Applied) == 0 {
			return nil
		}
	}
	return withFileLock(path, func() error {
		backup, err := loadRouteBackup(opts.DataDir, c.Name())
		if err != nil {
			return err
		}
		if route == nil && len(backup.Applied) == 0 {
			return nil
		}
		err = atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			if !exists && route == nil {
				return atomicTransformResult{Keep: true}, nil
			}
			out, err := renderCodexRoute(data, route, &backup)
			if err != nil {
				return atomicTransformResult{}, err
			}
			if exists && bytes.Equal(out, data) {
				return atomicTransformResult{Keep: true}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
		if err != nil {
			return fmt.Errorf("codex route-only config: %w", err)
		}
		return saveRouteBackup(opts.DataDir, c.Name(), backup)
	})
}

var _ RouteOnlyConnector = (*CodexConnector)(nil)
