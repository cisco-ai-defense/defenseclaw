// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDefenseClawConfigOptionsAreClassified is GAP-0787: `config set` and
// `config unset` take their options anywhere in the call, so the key is the
// first word that is not an option or an option's value. Every click option of
// the two verbs must be listed as taking a value or taking none; a new option
// fails here until a developer says which.
func TestDefenseClawConfigOptionsAreClassified(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	data, err := os.ReadFile(filepath.Join(root, "cli", "defenseclaw", "commands", "cmd_config.py"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	seen := map[string]bool{}
	for _, verb := range []string{"set", "unset"} {
		start := strings.Index(source, "@config_cmd.command(\""+verb+"\")")
		if start < 0 {
			t.Fatalf("the config %s command moved; update this test", verb)
		}
		decl := source[start:]
		if end := strings.Index(decl, "\ndef "); end > 0 {
			decl = decl[:end]
		}
		options := regexp.MustCompile(`@click\.option\(([^\n]*)`).FindAllStringSubmatch(decl, -1)
		if len(options) == 0 {
			t.Fatalf("no click options found for config %s; the layout moved", verb)
		}
		for _, option := range options {
			name := regexp.MustCompile(`"(--[a-z0-9-]+)"`).FindStringSubmatch(option[1])
			if name == nil {
				continue
			}
			seen[name[1]] = true
			isFlag := strings.Contains(option[1], "is_flag=True")
			switch {
			case isFlag && !defenseClawConfigFlagOptions[name[1]]:
				t.Errorf("config %s option %s takes no value but is not in defenseClawConfigFlagOptions", verb, name[1])
			case !isFlag && !defenseClawConfigValueOptions[name[1]]:
				t.Errorf("config %s option %s takes a value but is not in defenseClawConfigValueOptions", verb, name[1])
			}
		}
	}
	for _, listed := range []map[string]bool{defenseClawConfigFlagOptions, defenseClawConfigValueOptions} {
		for name := range listed {
			if !seen[name] {
				t.Errorf("%s is listed but neither config set nor config unset registers it", name)
			}
		}
	}
}
