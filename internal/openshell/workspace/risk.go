// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Flag is a change that can run code on the host (or signals an attempt to
// set that up).
type Flag struct {
	Path string `json:"path"`
	// Label is the operator-facing name, e.g. "package.json#scripts.postinstall".
	Label    string   `json:"label"`
	Kind     RiskKind `json:"kind"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// contentFunc returns the bytes of one side of a change (nil, false when
// unavailable: deleted, too large, binary).
type contentFunc func(c TreeChange, after bool) ([]byte, bool)

var npmLifecycleScripts = map[string]struct{}{
	"preinstall": {}, "install": {}, "postinstall": {}, "prepare": {}, "preprepare": {},
	"postprepare": {}, "prepublish": {}, "prepublishonly": {}, "prepack": {}, "postpack": {},
	"dependencies": {}, "preuninstall": {}, "uninstall": {}, "postuninstall": {},
}

// classifyChanges flags the changes that can execute on the host.
func classifyChanges(changes []TreeChange, content contentFunc, sensitive []string) []Flag {
	var flags []Flag
	add := func(f Flag) { flags = append(flags, f) }
	for _, c := range changes {
		if c.NewMode == "040000" || c.OldMode == "040000" && c.Status != "T" {
			continue
		}
		if c.Status == "D" {
			continue
		}
		rel := c.Path
		base := strings.ToLower(path.Base(rel))
		switch c.NewMode {
		case modeGitlink:
			add(Flag{Path: rel, Label: rel, Kind: RiskNestedRepo, Severity: SeverityCritical,
				Detail: "an embedded git repository was added; git runs its config (and anything it points to) when you run git status here"})
			continue
		case modeSymlink:
			target, _ := content(c, true)
			t := string(target)
			if escapesRoot(rel, t) {
				add(Flag{Path: rel, Label: rel, Kind: RiskSymlink, Severity: SeverityCritical,
					Detail: "symbolic link to " + t + ", outside the project: tools on this machine follow it to your files"})
			} else {
				add(Flag{Path: rel, Label: rel, Kind: RiskSymlink, Severity: SeverityInfo, Detail: "symbolic link to " + t})
			}
			continue
		}
		switch base {
		case "package.json":
			flags = append(flags, packageScriptFlags(c, content)...)
		case ".gitattributes":
			if f, ok := gitattributesFlag(c, content); ok {
				add(f)
			}
		case ".gitmodules":
			flags = append(flags, gitmodulesFlags(c, content)...)
		}
		if r, ok := classifyPath(rel); ok {
			add(Flag{Path: rel, Label: rel, Kind: r.kind, Severity: r.severity, Detail: r.detail})
		}
		switch {
		case c.Status == "A" && c.NewMode == modeExec:
			add(Flag{Path: rel, Label: rel, Kind: RiskExecutable, Severity: SeverityHigh, Detail: "new executable file"})
		case c.Status != "A" && c.NewMode == modeExec && c.OldMode != modeExec:
			add(Flag{Path: rel, Label: rel, Kind: RiskExecutable, Severity: SeverityHigh, Detail: "made executable"})
		}
		if _, ok := isSecretName(rel); ok {
			add(Flag{Path: rel, Label: rel, Kind: RiskSecretFile, Severity: SeverityMedium, Detail: "a secret-like file was created or changed"})
		}
		if p, ok := matchAny(sensitive, rel); ok {
			add(Flag{Path: rel, Label: rel, Kind: RiskPolicy, Severity: SeverityHigh, Detail: "matches the sensitive-change pattern " + p})
		}
	}
	return sortFlags(flags)
}

func sortFlags(flags []Flag) []Flag {
	seen := map[string]struct{}{}
	out := flags[:0]
	for _, f := range flags {
		key := f.Label + "\x00" + string(f.Kind)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.rank() != out[j].Severity.rank() {
			return out[i].Severity.rank() > out[j].Severity.rank()
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// escapesRoot reports whether a symlink at rel pointing at target resolves
// outside the tree it lives in.
func escapesRoot(rel, target string) bool {
	if target == "" {
		return false
	}
	if path.IsAbs(target) {
		return true
	}
	joined := path.Join(path.Dir(rel), target)
	return joined == ".." || strings.HasPrefix(joined, "../")
}

type packageJSON struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	OptionalDeps    map[string]string `json:"optionalDependencies"`
	Bin             json.RawMessage   `json:"bin"`
}

var remoteDependencyRE = regexp.MustCompile(`^(git(\+[a-z]+)?:|https?:|file:|link:|[\w.-]+/[\w.-]+(#.*)?$)`)

func packageScriptFlags(c TreeChange, content contentFunc) []Flag {
	after, ok := content(c, true)
	if !ok {
		return []Flag{{Path: c.Path, Label: c.Path, Kind: RiskPackageScripts, Severity: SeverityHigh, Detail: "package.json changed and could not be inspected"}}
	}
	var newPkg, oldPkg packageJSON
	if err := json.Unmarshal(after, &newPkg); err != nil {
		return []Flag{{Path: c.Path, Label: c.Path, Kind: RiskPackageScripts, Severity: SeverityHigh, Detail: "package.json changed and is not valid JSON"}}
	}
	if before, ok := content(c, false); ok {
		_ = json.Unmarshal(before, &oldPkg)
	}
	var flags []Flag
	keys := make([]string, 0, len(newPkg.Scripts))
	for k := range newPkg.Scripts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if oldPkg.Scripts[k] == newPkg.Scripts[k] {
			continue
		}
		sev, detail := SeverityMedium, "npm script changed (runs when you invoke it)"
		if _, ok := npmLifecycleScripts[strings.ToLower(k)]; ok {
			sev, detail = SeverityHigh, "npm lifecycle script changed (runs automatically on install)"
		}
		flags = append(flags, Flag{Path: c.Path, Label: c.Path + "#scripts." + k, Kind: RiskPackageScripts, Severity: sev,
			Detail: fmt.Sprintf("%s: %s", detail, truncate(newPkg.Scripts[k], 120))})
	}
	for _, deps := range []struct {
		name     string
		old, new map[string]string
	}{
		{"dependencies", oldPkg.Dependencies, newPkg.Dependencies},
		{"devDependencies", oldPkg.DevDependencies, newPkg.DevDependencies},
		{"optionalDependencies", oldPkg.OptionalDeps, newPkg.OptionalDeps},
	} {
		names := make([]string, 0, len(deps.new))
		for n := range deps.new {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := deps.new[n]
			if deps.old[n] == v || !remoteDependencyRE.MatchString(v) {
				continue
			}
			flags = append(flags, Flag{Path: c.Path, Label: c.Path + "#" + deps.name + "." + n, Kind: RiskDependencies, Severity: SeverityMedium,
				Detail: "dependency now comes from " + truncate(v, 120)})
		}
	}
	if string(oldPkg.Bin) != string(newPkg.Bin) && len(newPkg.Bin) > 0 {
		flags = append(flags, Flag{Path: c.Path, Label: c.Path + "#bin", Kind: RiskPackageScripts, Severity: SeverityMedium, Detail: "package bin entries changed"})
	}
	return flags
}

var gitattrDriverRE = regexp.MustCompile(`(^|\s)(filter|diff|merge)=([^\s]+)`)

func gitattributesFlag(c TreeChange, content contentFunc) (Flag, bool) {
	after, ok := content(c, true)
	if !ok {
		return Flag{Path: c.Path, Label: c.Path, Kind: RiskGitAttributes, Severity: SeverityHigh, Detail: "git attributes changed and could not be inspected"}, true
	}
	before, _ := content(c, false)
	old := map[string]struct{}{}
	for _, m := range gitattrDriverRE.FindAllStringSubmatch(string(before), -1) {
		old[m[2]+"="+m[3]] = struct{}{}
	}
	var added []string
	for _, m := range gitattrDriverRE.FindAllStringSubmatch(string(after), -1) {
		d := m[2] + "=" + m[3]
		if _, ok := old[d]; !ok {
			added = append(added, d)
		}
	}
	if len(added) == 0 {
		return Flag{}, false
	}
	return Flag{Path: c.Path, Label: c.Path, Kind: RiskGitAttributes, Severity: SeverityHigh,
		Detail: "assigns git filter/diff/merge drivers, which git runs on this machine: " + strings.Join(dedupe(added), ", ")}, true
}

var (
	gitmodulesSectionRE = regexp.MustCompile(`^\s*\[\s*submodule\s+"([^"]*)"\s*\]`)
	gitmodulesURLRE     = regexp.MustCompile(`^\s*url\s*=\s*(.*?)\s*$`)
)

// parseGitmodules maps submodule name to URL.
func parseGitmodules(b []byte) map[string]string {
	out := map[string]string{}
	name := ""
	for _, line := range strings.Split(string(b), "\n") {
		if m := gitmodulesSectionRE.FindStringSubmatch(line); m != nil {
			name = m[1]
			continue
		}
		if m := gitmodulesURLRE.FindStringSubmatch(line); m != nil && name != "" {
			out[name] = strings.Trim(m[1], `"`)
		}
	}
	return out
}

func gitmodulesFlags(c TreeChange, content contentFunc) []Flag {
	after, _ := content(c, true)
	before, _ := content(c, false)
	oldURLs, newURLs := parseGitmodules(before), parseGitmodules(after)
	var flags []Flag
	names := make([]string, 0, len(newURLs))
	for n := range newURLs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if o, ok := oldURLs[n]; ok && o == newURLs[n] {
			continue
		}
		detail := "new submodule from " + newURLs[n]
		if o, ok := oldURLs[n]; ok {
			detail = "submodule URL changed from " + o + " to " + newURLs[n]
		}
		flags = append(flags, Flag{Path: c.Path, Label: c.Path + "#" + n, Kind: RiskSubmodule, Severity: SeverityCritical, Detail: detail})
	}
	return flags
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
