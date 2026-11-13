// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"fmt"
	"regexp"
	"strings"
)

// PathRule is a rule on a file the call reads or changes. The id names a rule
// of the pack; the pack holds its title, severity and tags.
type PathRule struct {
	ID     string   `yaml:"id"`
	Access []string `yaml:"access"` // read, write, append, delete
	Regex  string   `yaml:"re"`
	re     *regexp.Regexp
}

// CommandRule is a rule on one parsed command (program and argv).
type CommandRule struct {
	ID      string   `yaml:"id"`
	Program []string `yaml:"program"`  // any of; empty: any program
	AllArgv []string `yaml:"all_argv"` // every one is an argument
	AnyArgv []string `yaml:"any_argv"` // at least one is an argument
	// ColonPathRe matches the path part of a REV:path argument (git show).
	ColonPathRe string `yaml:"colon_path_re"`
	colonPath   *regexp.Regexp
}

// compileRules is called once by load.
func (t *table) compileRules() error {
	for i := range t.PathRules {
		r := &t.PathRules[i]
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return fmt.Errorf("toolshape: path rule %s: %w", r.ID, err)
		}
		r.re = re
	}
	for i := range t.CommandRules {
		r := &t.CommandRules[i]
		if r.ColonPathRe == "" {
			continue
		}
		re, err := regexp.Compile(r.ColonPathRe)
		if err != nil {
			return fmt.Errorf("toolshape: command rule %s: %w", r.ID, err)
		}
		r.colonPath = re
	}
	return nil
}

func accessName(k Kind) []string {
	switch k {
	case KindRead:
		return []string{"read"}
	case KindWrite:
		return []string{"write", "append"}
	case KindDelete:
		return []string{"delete"}
	}
	return nil
}

// PathRules returns the ids of the path rules a call matches when it does
// kind (read, write or delete) to path. access is one of read, write, append,
// delete, list.
func PathRules(access, path string) []string {
	t, err := load()
	if err != nil || path == "" {
		return nil
	}
	path = strings.ReplaceAll(path, `\`, "/")
	var out []string
	for _, r := range t.PathRules {
		ok := false
		for _, a := range r.Access {
			if a == access {
				ok = true
				break
			}
		}
		if ok && r.re.MatchString(path) {
			out = append(out, r.ID)
		}
	}
	return out
}

// PathAccessOf maps an effect kind to the access name PathRules takes.
func PathAccessOf(k Kind) string {
	if a := accessName(k); len(a) > 0 {
		return a[0]
	}
	return ""
}

// CommandRules returns the ids of the command rules one command matches.
func CommandRules(program string, argv []string) []string {
	t, err := load()
	if err != nil {
		return nil
	}
	program = strings.ToLower(program)
	var out []string
	for _, r := range t.CommandRules {
		if len(r.Program) > 0 && !containsStr(r.Program, program) {
			continue
		}
		if !allIn(r.AllArgv, argv) {
			continue
		}
		if len(r.AnyArgv) > 0 && !anyIn(r.AnyArgv, argv) {
			continue
		}
		if r.colonPath != nil {
			hit := false
			for _, a := range argv {
				if k := strings.Index(a, ":"); k > 0 && r.colonPath.MatchString(a[k+1:]) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		out = append(out, r.ID)
	}
	return out
}

// ShellCandidate is a cheap check on shell text: does it hold a word any
// rule needs? Calls without one are not parsed again for these rules.
func ShellCandidate(text string) bool {
	t, err := load()
	if err != nil {
		return false
	}
	lower := strings.ToLower(text)
	for _, w := range t.ShellTriggers {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func allIn(want, argv []string) bool {
	for _, w := range want {
		if !containsStr(argv, w) {
			return false
		}
	}
	return true
}

func anyIn(want, argv []string) bool {
	for _, w := range want {
		if containsStr(argv, w) {
			return true
		}
	}
	return false
}
