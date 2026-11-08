// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The sensor helper's name-only parsers for brokered session-home reads
// (brokered_homes_read_linux.go, cowork-1-0-8 GAP-0008). They exist only on
// Linux, where the Cowork VM's root helper runs.

const (
	// The helper runs under MemoryMax=300M and parses one file at a time.
	// maxBrokeredFileBytes bounds one JSON or JSONC MCP config: real ones are
	// kilobytes, and the parsers build the whole document, so 1 MiB of tiny
	// members peaks near 110 MB. maxBrokeredYAMLTOMLBytes bounds a YAML or
	// TOML one: those parsers check duplicate keys in quadratic time, so 1
	// MiB of tiny keys takes tens of seconds of the helper's one CPU, and 128
	// KiB under a second. maxBrokeredClaudeStateBytes bounds
	// ~/.claude.json, which carries Claude Code's conversation state; it is
	// walked for names, not decoded (parseClaudeDiscoveryStateNames).
	// maxBrokeredHomeReadBytes bounds what one home reads, so one account's
	// files cannot leave the homes after it unread, and maxBrokeredReadBytes
	// what one request reads in all.
	maxBrokeredFileBytes        = 1 << 20
	maxBrokeredYAMLTOMLBytes    = 128 << 10
	maxBrokeredClaudeStateBytes = 32 << 20
	maxBrokeredHomeReadBytes    = 40 << 20
	maxBrokeredReadBytes        = 64 << 20
	// maxBrokeredHomeReplyBytes and maxBrokeredReplyBytes bound the encoded
	// entries one home, and one request, answer with in full. Past them an
	// entry is answered without its names (brokeredReadBudget.fit), so the
	// answer stays well inside the helper's 64 MiB frame (maxFrameBytes in
	// internal/sensor/acquire).
	maxBrokeredHomeReplyBytes = 1 << 20
	maxBrokeredReplyBytes     = 16 << 20
)

// parseMCPConfigBytesForNames is parseMCPConfigForNames, with
// readMCPServerNamesWithErr's blank-file rule, for a config the caller
// already read: the sensor helper reads it without following links
// (brokered_homes_read_linux.go). ~/.claude.json (mcpShapeClaudeState), up to
// maxBrokeredClaudeStateBytes, is walked by parseClaudeDiscoveryStateNames,
// which keeps at most limit names and reports truncated past them; the other
// shapes, up to maxBrokeredFileBytes, give every name. source names the file
// for the OpenCode resolver; nothing is opened.
func parseMCPConfigBytesForNames(shape, source string, data []byte, limit int) (names []string, truncated bool, err error) {
	if shape == mcpShapeClaudeState {
		return parseClaudeDiscoveryStateNames(data, limit)
	}
	if len(data) <= 4096 && strings.TrimSpace(string(data)) == "" {
		return nil, false, nil
	}
	var entries []config.MCPServerEntry
	switch shape {
	case mcpShapeAmp:
		entries, err = config.ParseMCPFromAmpSettings(data)
	case mcpShapeCodexTOML:
		entries, err = config.ParseMCPFromCodexConfigTOML(data)
	case mcpShapeHermesYAML:
		entries, err = config.ParseMCPFromYAMLPaths(data, hermesMCPKeyPaths...)
	case mcpShapeClaudeJSON:
		entries, err = config.ParseMCPFromClaudeJSONBothScopes(data)
	case mcpShapeSettings:
		entries, err = config.ParseMCPFromJSONCPaths(data, settingsMCPKeyPaths...)
	case mcpShapeOpenCode:
		entries, err = config.ParseMCPFromOpenCodeConfig(source, data)
	case mcpShapeClaudeDesktop:
		entries, err = config.ParseMCPFromJSONCPaths(data, []string{"mcpServers"})
	case mcpShapeOpenClaw:
		entries, err = config.ParseMCPFromOpenClawConfig(data)
	case mcpShapeNestedServers:
		entries, err = config.ParseMCPFromJSONCPaths(data, []string{"mcp", "servers"})
	case mcpShapeDotMCP:
		entries, err = config.ParseMCPFromDotMCPJSON(data)
	default:
		return nil, false, fmt.Errorf("unknown MCP config shape %q", shape)
	}
	if err != nil {
		return nil, false, err
	}
	names = make([]string, 0, len(entries))
	for _, e := range entries {
		if name := strings.TrimSpace(e.Name); name != "" {
			names = append(names, name)
		}
	}
	return names, false, nil
}

// parseClaudeDiscoveryStateNames is parseClaudeDiscoveryState's server names
// for the sensor helper, which parses another account's ~/.claude.json as
// root under MemoryMax (cowork-1-0-8 GAP-0008). It walks the document token
// by token with a json.Decoder, takes only the member names of mcpServers and
// projects.*.mcpServers, skips every value without building it, and stops at
// limit names (truncated), so its memory is O(limit) beside raw, not
// O(members).
// Keys match as json.Unmarshal matches parseClaudeDiscoveryState's fields.
func parseClaudeDiscoveryStateNames(raw []byte, limit int) (servers []string, truncated bool, err error) {
	// json.Decoder.Token has no nesting limit before jsonv2 (Go 1.26, the
	// release toolchain): its token stack grows 8 bytes a level, so 32 MiB of
	// "[" costs about 500 MB. json.Valid's scanner stops at Unmarshal's
	// depth of 10000 in constant memory, and keeps a syntax error a parse
	// error after the name cap ends the walk early.
	if !json.Valid(raw) {
		return nil, false, errors.New("claude state: not valid JSON")
	}
	walk := claudeStateNameWalk{dec: json.NewDecoder(bytes.NewReader(raw)), limit: limit}
	// Numbers stay text: a value is skipped, never converted.
	walk.dec.UseNumber()
	switch err := walk.document(); {
	case errors.Is(err, errClaudeStateNameCap):
		truncated = true
	case err != nil:
		return nil, false, err
	}
	sort.Strings(walk.servers)
	return walk.servers, truncated, nil
}

// errClaudeStateNameCap ends a walk that reached its name cap.
var errClaudeStateNameCap = errors.New("claude state: server name cap reached")

type claudeStateNameWalk struct {
	dec     *json.Decoder
	limit   int
	servers []string
}

func (w *claudeStateNameWalk) document() error {
	open, err := w.open("the document")
	if err != nil || !open {
		return w.end(err)
	}
	for w.dec.More() {
		key, err := w.key()
		if err != nil {
			return err
		}
		switch {
		case strings.EqualFold(key, "mcpServers"):
			err = w.names()
		case strings.EqualFold(key, "projects"):
			err = w.projects()
		default:
			err = w.skip()
		}
		if err != nil {
			return err
		}
	}
	return w.end(w.close())
}

// end is json.Unmarshal's rule that nothing follows the document.
func (w *claudeStateNameWalk) end(err error) error {
	if err != nil {
		return err
	}
	if _, err := w.dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("claude state: data after the document")
	}
	return nil
}

// open reads the start of an object; false for null, which
// parseClaudeDiscoveryState reads as empty.
func (w *claudeStateNameWalk) open(what string) (bool, error) {
	tok, err := w.token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return false, nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return false, fmt.Errorf("claude state: %s is not an object", what)
	}
	return true, nil
}

// token is the next token; the end of the input inside the document is an
// error, as json.Unmarshal has it.
func (w *claudeStateNameWalk) token() (json.Token, error) {
	tok, err := w.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, io.ErrUnexpectedEOF
	}
	return tok, err
}

func (w *claudeStateNameWalk) close() error {
	_, err := w.token()
	return err
}

func (w *claudeStateNameWalk) key() (string, error) {
	tok, err := w.token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errors.New("claude state: an object key is not a string")
	}
	return key, nil
}

// names takes one mcpServers object's member names, each once, as the
// direct read's map does.
func (w *claudeStateNameWalk) names() error {
	open, err := w.open("mcpServers")
	if err != nil || !open {
		return err
	}
	seen := map[string]bool{}
	for w.dec.More() {
		name, err := w.key()
		if err != nil {
			return err
		}
		if !seen[name] {
			if len(w.servers) >= w.limit {
				return errClaudeStateNameCap
			}
			seen[name] = true
			w.servers = append(w.servers, name)
		}
		if err := w.skip(); err != nil {
			return err
		}
	}
	return w.close()
}

func (w *claudeStateNameWalk) projects() error {
	open, err := w.open("projects")
	if err != nil || !open {
		return err
	}
	for w.dec.More() {
		if _, err := w.key(); err != nil {
			return err
		}
		project, err := w.open("a project")
		if err != nil {
			return err
		}
		if !project {
			continue
		}
		for w.dec.More() {
			key, err := w.key()
			if err != nil {
				return err
			}
			if strings.EqualFold(key, "mcpServers") {
				err = w.names()
			} else {
				err = w.skip()
			}
			if err != nil {
				return err
			}
		}
		if err := w.close(); err != nil {
			return err
		}
	}
	return w.close()
}

// skip passes over one value a token at a time: a large value is never held
// whole, by the decoder or here.
func (w *claudeStateNameWalk) skip() error {
	depth := 0
	for {
		tok, err := w.token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
