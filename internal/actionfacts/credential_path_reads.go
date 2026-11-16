// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

// Only the chain reads these candidates. No command grammar, ordinary Paths,
// operations, or parse authority is widened by this projection.
type credentialPathWord struct {
	commandID int64
	value     string
	expands   bool
}

func resolveCredentialPathWords(words []credentialPathWord, cwd, home string, commands []CommandFact) []PathFact {
	var result []PathFact
	seen := make(map[PathFact]bool)
	probes := CredentialFileShapeProbePaths()
	add := func(id int64, value string, unknown bool) {
		fact := PathFact{CommandID: id, Access: PathAccessRead, Flavor: PathFlavorPOSIX, Value: value}
		if !unknown {
			one := []PathFact{fact}
			normalizePathFactsForCommands(one, cwd, home, commands)
			fact = one[0]
		} else {
			fact.Value = ""
		}
		if !seen[fact] {
			seen[fact] = true
			result = append(result, fact)
		}
	}
	type resolveKey struct {
		id      int64
		value   string
		expands bool
	}
	resolvedWords := make(map[resolveKey]bool)
	resolve := func(id int64, value string, expands bool) {
		key := resolveKey{id, value, expands}
		if resolvedWords[key] {
			return
		}
		resolvedWords[key] = true
		if value == "" {
			return
		}
		// Check quoted embedded-program strings as well as whole argv words.
		// Whole-word checking preserves paths containing spaces.
		candidates := append([]string{value}, strings.FieldsFunc(value, func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune("'\"(){};,=", r)
		})...)
		for _, candidate := range candidates {
			if candidate == "" || strings.Contains(candidate, "://") {
				continue
			}
			glob := strings.ContainsAny(candidate, "*?[")
			if !glob {
				if _, ok := MatchCredentialFileShape(candidate); ok {
					add(id, candidate, expands)
					continue
				}
			}
			for _, probe := range probes {
				if glob {
					// Probe suffixes cover home-prefixed, relative and absolute spellings;
					// no shell expansion or unbounded filesystem glob is performed.
					parts := strings.Split(strings.TrimPrefix(candidate, "./"), "/")
					for i := range parts {
						if match, _ := path.Match(strings.Join(parts[i:], "/"), strings.TrimPrefix(probe, "/")); match {
							add(id, "", true)
							break
						}
					}
				}
			}
			if expands || glob {
				continue
			}
			local := candidate
			if strings.HasPrefix(local, "~/") && home != "" {
				local = filepath.Join(home, local[2:])
			}
			if !filepath.IsAbs(local) {
				if cwd == "" {
					continue
				}
				local = filepath.Join(cwd, local)
			}
			if target, err := filepath.EvalSymlinks(local); err == nil {
				if _, ok := MatchCredentialFileShape(target); ok {
					add(id, target, false)
				}
			}
		}
	}
	keyConsumer := make(map[int64]bool)
	transportWords := make(map[resolveKey]bool)
	for _, command := range commands {
		if command.Program == "rsync" {
			transport := false
			for _, argument := range command.Arguments {
				if transport || strings.HasPrefix(argument.Value, "--rsh=") {
					transportWords[resolveKey{command.ID, argument.Value, argument.Expands}] = true
				}
				transport = argument.Value == "-e" || argument.Value == "--rsh"
			}
		}
		if command.Effect == EffectPreview || command.Program == "ssh" || command.Program == "scp" {
			keyConsumer[command.ID] = true
		}
	}
	for _, word := range words {
		if !keyConsumer[word.commandID] && !transportWords[resolveKey{word.commandID, word.value, word.expands}] {
			resolve(word.commandID, word.value, word.expands)
		}
	}
	// The argv pass covers static nested-shell projections as well.
	for _, command := range commands {
		if command.Dialect != DialectPOSIX || command.Effect == EffectPreview || keyConsumer[command.ID] {
			continue
		}
		for _, argument := range command.Arguments {
			if !transportWords[resolveKey{command.ID, argument.Value, argument.Expands}] {
				resolve(command.ID, argument.Value, argument.Expands)
			}
		}
		// A recursive directory operand counts only after a finite table probe
		// resolves a local credentials file below it. Never invent an unknown read
		// for an ordinary repository grep, and never walk an unbounded tree.
		if command.Program != "grep" && command.Program != "rg" {
			continue
		}
		recursive := command.Program == "rg"
		for _, argument := range command.Arguments {
			if strings.HasPrefix(argument.Value, "-") && (strings.Contains(argument.Value, "r") || strings.Contains(argument.Value, "R")) {
				recursive = true
			}
		}
		if !recursive {
			continue
		}
		for _, argument := range command.Arguments {
			if argument.Expands || argument.Value == "" || strings.HasPrefix(argument.Value, "-") {
				continue
			}
			dir := argument.Value
			if !filepath.IsAbs(dir) {
				if cwd == "" {
					continue
				}
				dir = filepath.Join(cwd, dir)
			}
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				continue
			}
			for _, probe := range probes {
				file := filepath.Join(dir, strings.TrimPrefix(probe, "/"))
				if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
					resolve(command.ID, file, false)
				}
			}
		}
	}
	return result
}
