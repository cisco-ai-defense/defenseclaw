// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// rel-1-0-6:GAP-0729: a key names a place by its words, not by a list of
// the names of descriptive keys.
func TestDestinationArgumentKey(t *testing.T) {
	for key, want := range map[string]bool{
		"path": true, "file": true, "filename": true, "target": true, "destination": true, "dest": true,
		"output": true, "out": true, "to": true, "location": true,
		"file_path": true, "filePath": true, "targetFile": true, "target-file": true, "output.file": true,
		"destinations": true, "paths": true, "files": true, "locations": true, "dests": true,
		"filepath": true, "outputfile": true, "destpath": true, "Target_Alias_Path": true,
		"description_file": true, "notePath": true, "path2": true,
		"metadata": false, "commentary": false, "description": false, "note": false, "notes": false,
		"meta": false, "payload": false, "comment": false, "summary": false, "details": false,
		"f": false, "x": false, "tomato": false, "outline": false, "total": false, "profile": false,
		"": false,
	} {
		if got := destinationArgumentKey(key); got != want {
			t.Errorf("destinationArgumentKey(%q) = %t, want %t", key, got, want)
		}
	}
}

// rel-1-0-6:GAP-0729: a path-shaped string in an extra key is judged for
// DefenseClaw's own state whatever the key is called, at any depth; every
// other protected class reads only a string under a key that names a place.
func TestUnknownKeyTwinsScopeByKey(t *testing.T) {
	const (
		notes   = "/sandbox/work/app/notes.txt"
		state   = "/sandbox/.defenseclaw/config.yaml"
		managed = "/etc/claude-code/managed-settings.json"
		winMgd  = `C:\Program Files\ClaudeCode\managed-settings.json`
	)
	// scope is "self" for a reading that counts for the state only, "full"
	// for a reading judged by every rule, "" for no reading.
	scope := func(t *testing.T, extra map[string]any, target string) string {
		t.Helper()
		args := map[string]any{"file_path": notes, "content": "x"}
		for key, value := range extra {
			args[key] = value
		}
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		input := Input{Tool: "Write", Args: raw, CWD: "/sandbox/work/app", ActiveHome: "/sandbox"}
		twins, _ := UnknownKeyTwins(input, Analyze(input))
		for _, twin := range twins {
			for _, path := range twin.Facts.Paths {
				if path.Resolved == target || path.Value == target {
					if twin.SelfProtectionOnly {
						return "self"
					}
					return "full"
				}
			}
		}
		return ""
	}
	for _, test := range []struct {
		name  string
		extra map[string]any
		path  string
		want  string
	}{
		{"prose key", map[string]any{"metadata": state}, state, "self"},
		{"prose key two", map[string]any{"commentary": state}, state, "self"},
		{"description object", map[string]any{"description": map[string]any{"note": state}}, state, "self"},
		{"meta object", map[string]any{"meta": map[string]any{"note": state}}, state, "self"},
		{"payload list", map[string]any{"payload": []any{map[string]any{"note": state}}}, state, "self"},
		{"short key", map[string]any{"f": state}, state, "self"},
		{"home form", map[string]any{"f": "~/.defenseclaw/config.yaml"}, state, "self"},
		{"place key", map[string]any{"destination": state}, state, "full"},
		{"place key with a prose word", map[string]any{"description_file": state}, state, "full"},
		{"place key above a prose key", map[string]any{"destinations": []any{map[string]any{"note": state}}}, state, "full"},
		{"place key in a prose object", map[string]any{"meta": map[string]any{"output": state}}, state, "full"},
		{"place key beats prose key", map[string]any{"metadata": state, "target": state}, state, "full"},
		{"vendor file in a prose key is text", map[string]any{"metadata": managed}, managed, ""},
		{"vendor file in a prose object is text", map[string]any{"meta": map[string]any{"note": managed}}, managed, ""},
		{"vendor file under a place key", map[string]any{"target": managed}, managed, "full"},
		{"windows vendor file in a prose key is text", map[string]any{"commentary": winMgd}, winMgd, ""},
		{"windows vendor file under a place key", map[string]any{"file": winMgd}, winMgd, "full"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scope(t, test.extra, test.path); got != test.want {
				t.Errorf("scope of %s = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

// A long run of strings in prose keys does not push a string under a place
// key out of the judged set.
func TestUnknownKeyTwinsKeepPlaceKeysPastProseOverflow(t *testing.T) {
	const state = "/sandbox/.defenseclaw/config.yaml"
	prose := map[string]any{}
	for i, path := range distinctPaths(maxUnknownKeyTargets + 4) {
		prose[string(rune('a'+i%26))+string(rune('a'+i/26))] = path
	}
	args := map[string]any{"file_path": "/sandbox/work/app/notes.txt", "content": "x", "meta": prose, "output": state}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: "Write", Args: raw, CWD: "/sandbox/work/app", ActiveHome: "/sandbox"}
	twins, overflow := UnknownKeyTwins(input, Analyze(input))
	if !overflow {
		t.Error("more prose strings than the bound must report the overflow")
	}
	for _, twin := range twins {
		for _, path := range twin.Facts.Paths {
			if path.Resolved == state && !twin.SelfProtectionOnly {
				return
			}
		}
	}
	t.Error("the string under a place key is not judged by every rule")
}
