// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// Claude's state also holds project history and credentials. Discovery reads
// at most 256 MiB, never follows a link, and retains only server and project
// names; commands, environment variables, headers and URLs never become
// inventory evidence.
const maxClaudeDiscoveryStateBytes = 256 << 20

func readClaudeDiscoveryState(path string) (servers, projects []string, err error) {
	raw, err := readBoundedRegularFileNoFollow(path, maxClaudeDiscoveryStateBytes)
	if err != nil {
		return nil, nil, err
	}
	return parseClaudeDiscoveryState(raw)
}

// parseClaudeDiscoveryState is readClaudeDiscoveryState for state the caller
// already read (the sensor helper's brokered read).
func parseClaudeDiscoveryState(raw []byte) (servers, projects []string, err error) {
	var state struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, nil, err
	}
	for name := range state.MCPServers {
		servers = append(servers, name)
	}
	for project, scope := range state.Projects {
		if filepath.IsAbs(project) {
			projects = append(projects, filepath.Clean(project))
		}
		for name := range scope.MCPServers {
			servers = append(servers, name)
		}
	}
	sort.Strings(servers)
	sort.Strings(projects)
	return servers, projects, nil
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

// maxClaudeStateSkipDepth bounds the nesting skip walks, as json.Unmarshal
// bounds it, should a caller ever pass bytes json.Valid has not checked.
const maxClaudeStateSkipDepth = 10000

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
				if depth++; depth > maxClaudeStateSkipDepth {
					return errors.New("claude state: nested too deeply")
				}
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
