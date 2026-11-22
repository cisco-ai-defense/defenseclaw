// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/textlower"
)

// PathRule is a rule on a file the call reads or changes. The id names a rule
// of the pack; the pack holds its title, severity and tags. A rule has one of
// re (the whole path, PathRules) and home_re (the path below the active home
// of the call, HomePathRules).
type PathRule struct {
	ID     string   `yaml:"id"`
	Access []string `yaml:"access"` // read, write, append, delete
	Regex  string   `yaml:"re"`
	// HomeRe matches the path relative to the active home of the call
	// (.config/systemd/user/x.service), whatever that home is: /home/alice
	// on a laptop, /sandbox in a Substrate actor. A home found by the shape
	// of the path misses a home of another shape (rel-1-0-10:GAP-1002).
	HomeRe string `yaml:"home_re"`
	// TextRe, when set, must also match the text of the call (the shell
	// command, or the content a write carries): the path alone is not enough.
	TextRe string `yaml:"text_re"`
	// PackTyped marks a rule whose finding the gateway judges as the pack's
	// own typed path finding of the rule (the trusted-action context
	// disposition: a local read of the file is an advisory MEDIUM, a mutation
	// keeps the rule's tier), not as a lane alert at the rule's severity, so
	// the lane gives the verdict the one-step spelling of the call gets in
	// every pack (rel-1-0-10:GAP-1058). It only matters outside the strict
	// tier and managed installs, where lane findings alert.
	PackTyped bool `yaml:"pack_typed"`
	re        *regexp.Regexp
	homeRe    *regexp.Regexp
	textRe    *regexp.Regexp
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

// TextRule is a rule on the text of a shell call, for a shape the parsed
// facts do not carry (an environment assignment in front of a command).
type TextRule struct {
	ID    string `yaml:"id"`
	Regex string `yaml:"re"`
	re    *regexp.Regexp
}

// compileRules is called once by load.
func (t *table) compileRules() error {
	for i := range t.PathRules {
		r := &t.PathRules[i]
		if (r.Regex == "") == (r.HomeRe == "") {
			return fmt.Errorf("toolshape: path rule %s: want one of re and home_re", r.ID)
		}
		source, field := r.Regex, &r.re
		if r.HomeRe != "" {
			source, field = r.HomeRe, &r.homeRe
		}
		re, err := regexp.Compile(source)
		if err != nil {
			return fmt.Errorf("toolshape: path rule %s: %w", r.ID, err)
		}
		*field = re
		if r.TextRe != "" {
			if r.textRe, err = regexp.Compile(r.TextRe); err != nil {
				return fmt.Errorf("toolshape: path rule %s text: %w", r.ID, err)
			}
		}
	}
	for i := range t.TextRules {
		r := &t.TextRules[i]
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return fmt.Errorf("toolshape: text rule %s: %w", r.ID, err)
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
// delete, list. text is the call's command or written content, for the rules
// that need more than the path.
func PathRules(access, path, text string) []string {
	return pathRules(access, path, text, func(r *PathRule) *regexp.Regexp { return r.re })
}

// HomePathRules is PathRules for the rules on a file of the active home:
// relative is the path below that home (.config/autostart/x.desktop), which
// the caller finds from the home the call runs as, never from the shape of
// the path.
func HomePathRules(access, relative, text string) []string {
	return pathRules(access, relative, text, func(r *PathRule) *regexp.Regexp { return r.homeRe })
}

func pathRules(access, path, text string, pattern func(*PathRule) *regexp.Regexp) []string {
	t, err := load()
	if err != nil || path == "" {
		return nil
	}
	path = strings.ReplaceAll(path, `\`, "/")
	var out []string
	for i := range t.PathRules {
		r := &t.PathRules[i]
		re := pattern(r)
		if re == nil || !slices.Contains(r.Access, access) {
			continue
		}
		if re.MatchString(path) && (r.textRe == nil || r.textRe.MatchString(text)) {
			out = append(out, r.ID)
		}
	}
	return out
}

// PackTypedPathRule reports whether a path rule of the table with this id is
// pack_typed (PathRule.PackTyped).
func PackTypedPathRule(id string) bool {
	t, err := load()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(t.PathRules, func(r PathRule) bool { return r.ID == id && r.PackTyped })
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
	lower := strings.ReplaceAll(textlower.Lower(text), `\`, "/")
	for _, w := range t.ShellTriggers {
		if strings.Contains(lower, w) {
			return true
		}
	}
	if !strings.ContainsAny(text, `'"\`) {
		return false
	}
	// A word split by quotes or a backslash (sh'ad'ow, sha\dow) is the word
	// the shell reads once they are removed (rel-1-0-10:GAP-1070).
	unquoted := strings.ToLower(strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(text))
	for _, w := range t.ShellTriggers {
		if strings.Contains(unquoted, w) {
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

// TextRules returns the ids of the text rules a shell command matches.
func TextRules(text string) []string {
	t, err := load()
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range t.TextRules {
		if r.re.MatchString(text) {
			out = append(out, r.ID)
		}
	}
	return out
}
