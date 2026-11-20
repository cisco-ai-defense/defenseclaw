// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bufio"
	"bytes"
	"path"
	"sort"
	"strings"
)

// The settings files in the agent's HOME that run a program the hooks never
// see (substrate-1 GAP-0360): git runs core.fsmonitor on every git status,
// and npm runs script-shell for every script. The environment allowlist
// stops the same settings made through variables (GIT_CONFIG_*, NODE_OPTIONS);
// the build refuses an image whose HOME carries them in a file. The kit's
// own /etc/gitconfig and /usr/local/etc/npmrc are attested, root-owned files
// and are not looked at here. Shell start files (~/.bashrc) are code by
// nature, as trusted as the base image's own programs, and are not refused;
// BASH_ENV, ENV and PROMPT_COMMAND are refused as variables.

// gitCodeKeys are the git settings that name a program or another
// configuration file, as section.key (lower case); "*" is any subsection.
var gitCodeKeys = map[string]bool{
	"core.fsmonitor": true, "core.hookspath": true, "core.sshcommand": true, "core.pager": true, "core.editor": true,
	"core.askpass": true, "core.gitproxy": true, "credential.helper": true, "credential.*.helper": true,
	"diff.external": true, "diff.*.textconv": true, "diff.*.command": true, "filter.*.clean": true, "filter.*.smudge": true,
	"filter.*.process": true, "merge.*.driver": true, "sequence.editor": true, "gpg.program": true, "gpg.*.program": true,
	"include.path": true, "includeif.*.path": true, "uploadpack.packobjectshook": true, "interactive.difffilter": true,
	"difftool.*.cmd": true, "mergetool.*.cmd": true, "web.browser": true, "browser.*.cmd": true,
}

// npmCodeKeys are the npm settings that run a program or load code.
var npmCodeKeys = map[string]bool{
	"script-shell": true, "node-options": true, "onload-script": true, "init-module": true, "git": true,
	"shell": true, "editor": true, "browser": true, "viewer": true,
}

// codeLoadingSettings lists the settings files below home that set one of
// those keys, each with the keys it sets (never their values).
func codeLoadingSettings(fsys *ImageFS, home string) []HookFile {
	if !path.IsAbs(home) || path.Clean(home) == "/" {
		return nil
	}
	var out []HookFile
	check := func(p string, keys []string) {
		if len(keys) == 0 {
			return
		}
		sort.Strings(keys)
		out = append(out, HookFile{Path: p, Mode: "-",
			Note: "sets " + strings.Join(keys, ", ") + ", which run a program DefenseClaw's hooks never see; remove them from the image"})
	}
	for _, p := range []string{path.Join(home, ".gitconfig"), path.Join(home, ".config", "git", "config")} {
		if data, err := fsys.Read(p); err == nil {
			check(p, gitSettings(data))
		}
	}
	if data, err := fsys.Read(path.Join(home, ".npmrc")); err == nil {
		check(path.Join(home, ".npmrc"), npmSettings(data))
	}
	return out
}

// gitSettings returns the code-running keys a git config file sets, as
// section.key. core.fsmonitor set to a boolean uses git's own daemon and
// runs nothing; an alias that starts with "!" runs a shell command.
func gitSettings(data []byte) []string {
	seen := map[string]bool{}
	section, sub := "", ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '[' {
			end := strings.IndexByte(l, ']')
			if end < 0 {
				continue
			}
			h := strings.TrimSpace(l[1:end])
			section, sub = h, ""
			if i := strings.IndexAny(h, " \t\""); i >= 0 {
				section, sub = h[:i], strings.Trim(strings.TrimSpace(h[i:]), "\"")
			} else if i := strings.IndexByte(h, '.'); i >= 0 {
				section, sub = h[:i], h[i+1:]
			}
			section = strings.ToLower(section)
			// The rest of the line may hold a setting too ([core] pager = x).
			l = strings.TrimSpace(l[end+1:])
			if l == "" {
				continue
			}
		}
		k, v, _ := strings.Cut(l, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "" {
			continue
		}
		name := section + "." + k
		pattern := name
		if sub != "" {
			pattern = section + ".*." + k
		}
		switch {
		case section == "alias" && strings.HasPrefix(strings.Trim(v, "\""), "!"):
			seen["alias."+k] = true
		case name == "core.fsmonitor" && isGitBool(v):
		case gitCodeKeys[pattern], section == "pager": // pager.<command> runs a pager
			if sub != "" {
				name = section + "." + sub + "." + k
			}
			seen[name] = true
		}
	}
	return keysOf(seen)
}

func isGitBool(v string) bool {
	switch strings.ToLower(strings.Trim(v, "\"")) {
	case "", "true", "false", "yes", "no", "on", "off", "0", "1":
		return true
	}
	return false
}

// npmSettings returns the code-running keys an npmrc sets.
func npmSettings(data []byte) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		k, _, _ := strings.Cut(l, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if npmCodeKeys[k] {
			seen[k] = true
		}
	}
	return keysOf(seen)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
