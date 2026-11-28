// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// claudeStateMaxBytes bounds the Claude Code state file the relay rewrites.
const claudeStateMaxBytes = 64 << 20

// claudeTrust records in Claude Code's state file (~/.claude.json) that dir
// and each folder between it and root are trusted
// (projects[<path>].hasTrustDialogAccepted), so Claude Code opens on its own
// prompt and not on "Is this a project you trust?" (substrate-1 GAP-0446).
//
// The actor is the sandbox, and the image already trusts root (/work). But
// Claude Code carries a parent folder's trust only as far as the root of the
// git repository it starts in. The copy of a git project is a git
// repository (/work/<folder>/.git, the copy a launcher on macOS or Linux
// makes), so trust on /work did not reach it. The Windows host copy has no
// .git, which is why only runs from Windows opened without the dialog.
//
// The rest of the file is kept as it is. A file that is not a regular file
// (a link the agent put there) is left alone.
func claudeTrust(file, root, dir string) error {
	return editJSONDoc(file, "claude trust", func(doc map[string]any) bool {
		projects, _ := doc["projects"].(map[string]any)
		if projects == nil {
			projects = map[string]any{}
		}
		changed := false
		for _, k := range trustFolders(root, dir) {
			p, _ := projects[k].(map[string]any)
			if p == nil {
				p = map[string]any{}
			}
			if ok, _ := p["hasTrustDialogAccepted"].(bool); ok {
				continue
			}
			p["hasTrustDialogAccepted"] = true
			projects[k] = p
			changed = true
		}
		doc["projects"] = projects
		return changed
	})
}

// editJSONDoc applies edit to the JSON object in file (a missing or empty
// file is {}) and writes it back, 0600 through a temporary file, when edit
// reports a change. Numbers are written back as they were read. claude
// trust and the MCP bridge entries (mcpconfig.go) share it.
func editJSONDoc(file, what string, edit func(doc map[string]any) bool) error {
	raw, err := readConfigFile(file)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return fmt.Errorf("%s: %s: %w", what, file, err)
		}
		if doc == nil { // the file holds null
			doc = map[string]any{}
		}
	}
	if !edit(doc) {
		return nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := writeConfigFile(file, append(out, '\n')); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func trustFolders(root, dir string) []string {
	root, dir = filepath.Clean(root), filepath.Clean(dir)
	var out []string
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for d := dir; ; d = filepath.Dir(d) {
		add(d)
		if real, err := winpath.EvalLinks(d); err == nil {
			add(real)
		}
		if d == root || !strings.HasPrefix(d, root+string(filepath.Separator)) || filepath.Dir(d) == d {
			return out
		}
	}
}
