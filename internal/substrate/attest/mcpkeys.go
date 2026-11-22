// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	toml "github.com/pelletier/go-toml/v2"
)

// MCP config keys under case folding (substrate-1 GAP-0176). The decoders
// ParseMCPConfig uses (encoding/json, go-toml) match a struct field to a key
// case-insensitively and let the last match win, while the agents read only
// the exact key: {"mcpServers":{...},"MCPSERVERS":null} reads as no servers,
// and "Command":"true" after "command":"sh" rewrites the server. As F5 did
// for JSON-RPC keys (GAP-0156), keys equal under case folding in an object
// the scan decodes into a struct (the document, a project, a server) are
// duplicates when they fold to a key the scan decodes (mcpServers, projects,
// mcp_servers; a server's type, command, args, env, url), and a config with
// a duplicate is refused as ambiguous: a HIGH finding at template build and
// a block at run time. Keys the scan does not read are ignored, and map keys
// (server names, project paths, env names) stay exact and are not checked:
// those decoders keep them exact too.

// RuleMCPConfigAmbiguous is the finding for an MCP config with a case-folded
// duplicate key.
const RuleMCPConfigAmbiguous = "mcp-config-ambiguous-keys"

// ErrMCPConfigAmbiguous is the ParseMCPConfig error of such a config.
var ErrMCPConfigAmbiguous = errors.New("MCP config has keys that differ only by case")

// foldKey is the canonical case fold of a key: every rune to the smallest
// rune of its simple-fold orbit (so K, k and the Kelvin sign are one key, as
// in encoding/json's matching).
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b.WriteRune(min)
	}
	return b.String()
}

// mcpLevel says which object of an MCP config a JSON or TOML path is: the
// document, a project, a server, or a map of names (servers, projects) whose
// keys are data, not fields.
type mcpLevel int

const (
	levelOther mcpLevel = iota
	levelDocument
	levelServerMap
	levelProjectMap
	levelProject
	levelServer
)

// child is the level of the object under key k of an object at level l.
func (l mcpLevel) child(k string, toml bool) mcpLevel {
	servers := "mcpServers"
	if toml {
		servers = "mcp_servers"
	}
	switch l {
	case levelDocument:
		switch {
		case foldKey(k) == foldKey(servers):
			return levelServerMap
		case !toml && foldKey(k) == foldKey("projects"):
			return levelProjectMap
		}
	case levelProjectMap:
		return levelProject
	case levelProject:
		if foldKey(k) == foldKey(servers) {
			return levelServerMap
		}
	case levelServerMap:
		return levelServer
	}
	return levelOther
}

// decodesField reports whether key k of an object at l is one the scan
// decodes into a struct field (case-insensitively): only those can be
// hidden or rewritten by a case variant. Other keys are not read.
func (l mcpLevel) decodesField(k string, toml bool) bool {
	var fields []string
	switch l {
	case levelDocument:
		fields = []string{"mcpServers", "projects"}
		if toml {
			fields = []string{"mcp_servers"}
		}
	case levelProject:
		fields = []string{"mcpServers"}
	case levelServer:
		fields = []string{"type", "command", "args", "env", "url"}
	}
	for _, f := range fields {
		if foldKey(k) == foldKey(f) {
			return true
		}
	}
	return false
}

// checkMCPConfigKeys returns ErrMCPConfigAmbiguous (wrapped, naming the
// keys) when an object the scan decodes into a struct has two keys equal
// under case folding. A document that does not decode is left to the
// parser.
func checkMCPConfigKeys(p string, data []byte) error {
	if strings.HasSuffix(p, ".toml") {
		var doc map[string]any
		if toml.Unmarshal(data, &doc) != nil {
			return nil
		}
		return checkTOMLKeys(doc, levelDocument, "")
	}
	return walkJSONDocument(data, levelDocument)
}

// checkMCPServerKeys is checkMCPConfigKeys for one JSON server object (the
// argument of "claude mcp add-json").
func checkMCPServerKeys(data []byte) error {
	return walkJSONDocument(data, levelServer)
}

func ambiguous(where string, a, b string) error {
	return fmt.Errorf("%w: %q and %q%s", ErrMCPConfigAmbiguous, a, b, where)
}

func checkTOMLKeys(m map[string]any, l mcpLevel, where string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]string{}
	for _, k := range keys {
		if !l.decodesField(k, true) {
			continue
		}
		if prev, dup := seen[foldKey(k)]; dup {
			return ambiguous(where, prev, k)
		}
		seen[foldKey(k)] = k
	}
	for _, k := range keys {
		if sub, ok := m[k].(map[string]any); ok {
			if err := checkTOMLKeys(sub, l.child(k, true), where+" in "+k); err != nil {
				return err
			}
		}
	}
	return nil
}

// errNotJSON stops the key walk at the first token the decoder refuses: the
// parser then refuses the document. It must stop the walk, not just the
// current value: Decoder.More keeps answering true after an error, so a loop
// that went on would never end.
var errNotJSON = errors.New("not JSON")

// walkJSONKeys reads one JSON value from dec and checks its objects. It
// returns ErrMCPConfigAmbiguous (wrapped) or errNotJSON.
func walkJSONKeys(dec *json.Decoder, l mcpLevel, where string) error {
	tok, err := dec.Token()
	if err != nil {
		return errNotJSON
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			kt, err := dec.Token()
			k, isKey := kt.(string)
			if err != nil || !isKey {
				return errNotJSON
			}
			if l.decodesField(k, false) {
				if prev, dup := seen[foldKey(k)]; dup {
					return ambiguous(where, prev, k)
				}
				seen[foldKey(k)] = k
			}
			if err := walkJSONKeys(dec, l.child(k, false), where+" in "+k); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSONKeys(dec, levelOther, where); err != nil {
				return err
			}
		}
	default:
		return errNotJSON
	}
	if _, err := dec.Token(); err != nil { // the closing } or ]
		return errNotJSON
	}
	return nil
}

// walkJSONDocument checks one JSON document from its top level l; a document
// the decoder refuses is left to the parser.
func walkJSONDocument(data []byte, l mcpLevel) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONKeys(dec, l, ""); err != nil && !errors.Is(err, errNotJSON) {
		return err
	}
	return nil
}
