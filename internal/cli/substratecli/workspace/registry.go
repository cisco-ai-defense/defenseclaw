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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// Registry kinds of a bound secret (substrate.secret_templates[].registry).
const (
	RegistryNPM  = "npm"
	RegistryPyPI = "pypi"
)

// The files written in the agent's home at start (B1 2.6), relative to
// $HOME. pip reads two user files: PipLegacyConfFile always, and
// PipConfFile under $XDG_CONFIG_HOME (default ~/.config), which wins a key
// both set. A connector that points XDG_CONFIG_HOME elsewhere (Devin's
// kit-owned folder) would miss PipConfFile, so the start writes the same
// index to both (GAP-0977).
const (
	NPMRCFile         = ".npmrc"
	PipConfFile       = ".config/pip/pip.conf"
	PipLegacyConfFile = ".pip/pip.conf"
	PyPIRCFile        = ".pypirc"
)

// registryFileNames are the files the start reads and may write, in order.
var registryFileNames = []string{NPMRCFile, PipConfFile, PipLegacyConfFile, PyPIRCFile}

// registryMarker is the first line of every file DefenseClaw writes at
// agent start: a later start replaces such a file, and the doctor reads it
// as "written at start".
const registryMarker = "# Written by DefenseClaw at agent start (placeholders only)."

// RegistryEntry is one registry host a secret is bound to in the agent's
// policy: the agent's npm or pip sends Placeholder there and Substrate
// egress swaps the header for the real credential on that host only. No
// value is ever here.
type RegistryEntry struct {
	Kind, Secret, Host, Placeholder string
}

// RegistryEntries keeps the entries that name one exact host (a pattern
// such as *.example.com cannot name a registry) and a known kind, with the
// default placeholder where none is set. Sorted by kind and host; the first
// entry wins a host.
func RegistryEntries(in []RegistryEntry) []RegistryEntry {
	seen := map[string]bool{}
	var out []RegistryEntry
	for _, e := range in {
		e.Host = strings.ToLower(strings.TrimSpace(e.Host))
		if (e.Kind != RegistryNPM && e.Kind != RegistryPyPI) || !registryHostRE.MatchString(e.Host) || seen[e.Kind+" "+e.Host] {
			continue
		}
		if e.Placeholder == "" || !registryValueRE.MatchString(e.Placeholder) {
			e.Placeholder = kit.PlaceholderSecret
		}
		if !registryValueRE.MatchString(e.Secret) {
			e.Secret = e.Kind
		}
		seen[e.Kind+" "+e.Host] = true
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// RegistryFiles renders the files for entries (the RegistryEntries form):
// path (relative to $HOME) to content. A kind with no entry has no file.
//
//   - npm: ~/.npmrc, one //HOST/:_authToken=PLACEHOLDER line per host
//     (npm reads the user file after the kit's global one).
//   - pypi: ~/.config/pip/pip.conf and ~/.pip/pip.conf name the first
//     index host as index-url with the placeholder as its password (upload
//     hosts are not indexes); ~/.pypirc names every host as an upload
//     repository.
func RegistryFiles(entries []RegistryEntry) map[string]string {
	out := map[string]string{}
	var npm, pipIndex, pypirc strings.Builder
	var servers []string
	for _, e := range entries {
		switch e.Kind {
		case RegistryNPM:
			fmt.Fprintf(&npm, "//%s/:_authToken=%s\n", e.Host, e.Placeholder)
		case RegistryPyPI:
			repo := "https://" + e.Host + "/"
			if pypiUploadHost(e.Host) {
				repo = "https://" + e.Host + "/legacy/"
			} else if pipIndex.Len() == 0 {
				fmt.Fprintf(&pipIndex, "[global]\nindex-url = https://__token__:%s@%s/simple\n", e.Placeholder, e.Host)
			}
			name := e.Secret
			for slices.Contains(servers, name) {
				name += "-" + strings.ReplaceAll(e.Host, ".", "-")
			}
			servers = append(servers, name)
			fmt.Fprintf(&pypirc, "\n[%s]\nrepository = %s\nusername = __token__\npassword = %s\n", name, repo, e.Placeholder)
		}
	}
	head := registryMarker + "\n# Substrate egress swaps each placeholder for the real credential on its bound host only.\n"
	if npm.Len() > 0 {
		out[NPMRCFile] = head + npm.String()
	}
	if pipIndex.Len() > 0 {
		out[PipConfFile] = head + pipIndex.String()
		out[PipLegacyConfFile] = out[PipConfFile]
	}
	if pypirc.Len() > 0 {
		out[PyPIRCFile] = head + "[distutils]\nindex-servers =\n    " + strings.Join(servers, "\n    ") + "\n" + pypirc.String()
	}
	return out
}

func pypiUploadHost(h string) bool { return h == "upload.pypi.org" || h == "test.pypi.org" }

// RegistryProbe is what the agent's home and the image hold before the
// start writes anything: the content of each file that exists (Links names
// those that are symbolic links, or sit in a folder below $HOME that is a
// link or not a folder (GAP-0974); they are never read or written; TooLarge
// those over registryFileCap, which are kept as they are), and the
// hosts the image's global npmrc names with a token: the template build
// writes them for launchers older than 1.0.11 (GAP-0529). BakedNPMTokens
// maps each such host to its placeholder.
type RegistryProbe struct {
	Files          map[string]string
	Links          []string
	TooLarge       []string
	BakedNPM       []string
	BakedNPMTokens map[string]string
	ReadError      error
}

// Mode says how an agent gets its registry placeholders: "start" (files
// DefenseClaw wrote at agent start, or lines it added at start to an
// image's own npmrc), "template" (lines its template image carries from
// its build), "template+start", or "none" (none of these was found).
func (p RegistryProbe) Mode() string {
	start := false
	for _, f := range registryFileNames {
		if c := p.Files[f]; strings.HasPrefix(c, registryMarker) || (f == NPMRCFile && strings.Contains(c, "\n"+registryAppendMarker+"\n")) {
			start = true
		}
	}
	switch {
	case start && len(p.BakedNPM) > 0:
		return "template+start"
	case start:
		return "start"
	case len(p.BakedNPM) > 0:
		return "template"
	}
	return "none"
}

// RegistryPlan is what the start writes and what it says.
type RegistryPlan struct {
	// Write maps a path relative to $HOME to its new content.
	Write map[string]string
	// Hosts are the registry hosts the written files name, by kind.
	Hosts map[string][]string
	// Notes say which files were kept and why.
	Notes []string
}

// PlanRegistryFiles merges the rendered files with what the agent's home
// holds. A file DefenseClaw wrote at an earlier start is replaced. An npmrc
// of the image (or the person) keeps its lines, and only hosts it does not
// set yet are added; one that holds a credential is refused, as the
// template build refuses a base image npmrc that holds one (D14: an actor
// holds no secret value). A pip.conf or .pypirc of the image is kept as is.
// A symbolic link is never written through.
func PlanRegistryFiles(entries []RegistryEntry, probe RegistryProbe) RegistryPlan {
	plan := RegistryPlan{Write: map[string]string{}, Hosts: map[string][]string{}}
	placeholders := map[string]bool{kit.PlaceholderSecret: true}
	for _, e := range entries {
		placeholders[e.Placeholder] = true
	}
	// A host the image's global npmrc already names with the same
	// placeholder (the template build's lines) is not written again.
	// Build-time lines: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
	var baked []string
	kept := make([]RegistryEntry, 0, len(entries))
	for _, e := range entries {
		if ph, ok := probe.BakedNPMTokens[e.Host]; e.Kind == RegistryNPM && ok && ph == e.Placeholder {
			baked = append(baked, e.Host)
			continue
		}
		kept = append(kept, e)
	}
	entries = kept
	if len(baked) > 0 {
		plan.Notes = append(plan.Notes, "the template's npm configuration already names "+strings.Join(baked, ", ")+" (placeholders from its build); DefenseClaw did not add them to ~/.npmrc")
	}
	rendered := RegistryFiles(entries)
	for _, f := range registryFileNames {
		content, ok := rendered[f]
		if !ok {
			continue
		}
		// ~/.pip/pip.conf only repeats the index of ~/.config/pip/pip.conf
		// (which wins a key both set), so it is written only with it: an
		// image's or a linked ~/.config/pip/pip.conf keeps pip as it was.
		if f == PipLegacyConfFile && plan.Write[PipConfFile] == "" {
			continue
		}
		if slices.Contains(probe.Links, f) {
			plan.Notes = append(plan.Notes, fmt.Sprintf("~/%s in the agent is a link, or a folder on its path is a link or not a folder; DefenseClaw did not write registry placeholders through it", f))
			continue
		}
		if slices.Contains(probe.TooLarge, f) {
			plan.Notes = append(plan.Notes, fmt.Sprintf("~/%s in the agent is larger than %d KiB; DefenseClaw kept it as it is and added no registry placeholders to it", f, registryFileCap>>10))
			continue
		}
		old, exists := probe.Files[f]
		switch {
		case !exists || strings.HasPrefix(old, registryMarker):
		case f == NPMRCFile:
			if k, bad := npmrcCredential(old, placeholders); bad {
				plan.Notes = append(plan.Notes, fmt.Sprintf("~/.npmrc in the agent sets %s, a credential: DefenseClaw did not add registry placeholders to it; remove the credential from the image and bind the registry with defenseclaw substrate secrets add (egress adds it)", k))
				continue
			}
			// Compare keys the file sets, not text: a comment that names a
			// bound host sets nothing (GAP-0976).
			set := npmrcKeys(old)
			var add, keptKeys []string
			for _, line := range strings.Split(content, "\n") {
				if !strings.HasPrefix(line, "//") {
					continue
				}
				k, v, _ := strings.Cut(line, "=")
				ov, has := set[strings.ToLower(k)]
				switch {
				case !has:
					add = append(add, line)
				case ov != v:
					keptKeys = append(keptKeys, k)
				}
			}
			if len(keptKeys) > 0 {
				plan.Notes = append(plan.Notes, fmt.Sprintf("~/.npmrc in the agent already sets %s; DefenseClaw kept the image's line, so Substrate egress swaps only the placeholder it holds", strings.Join(keptKeys, ", ")))
			}
			if len(add) == 0 {
				continue
			}
			content = strings.TrimRight(old, "\n") + "\n" + registryAppendMarker + "\n" + strings.Join(add, "\n") + "\n"
		default:
			plan.Notes = append(plan.Notes, fmt.Sprintf("~/%s in the agent is the image's; DefenseClaw kept it and added no registry placeholder to it", f))
			continue
		}
		if len(content) > registryWriteMax {
			plan.Notes = append(plan.Notes, fmt.Sprintf("~/%s with the registry placeholders would be larger than %d KiB; DefenseClaw kept the agent's file as it is and added none", f, registryWriteMax>>10))
			continue
		}
		plan.Write[f] = content
	}
	for _, e := range entries {
		f := NPMRCFile
		if e.Kind == RegistryPyPI {
			f = PyPIRCFile
		}
		if _, ok := plan.Write[f]; ok || (e.Kind == RegistryPyPI && plan.Write[PipConfFile] != "") {
			plan.Hosts[e.Kind] = append(plan.Hosts[e.Kind], e.Host)
		}
	}
	return plan
}

// registryAppendMarker opens the lines added to an image's own npmrc.
const registryAppendMarker = "# Added by DefenseClaw at agent start (placeholders only):"

// npmrcKeys maps each key data sets (trimmed, lowercased) to its value
// (trimmed, unquoted; the last line wins, as in npm). Blank lines and
// comments (# or ;) set nothing.
func npmrcKeys(data string) map[string]string {
	set := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		set[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return set
}

// npmrcCredential reports the first npmrc key of data that holds a
// credential that is not one of the placeholders.
func npmrcCredential(data string, placeholders map[string]bool) (string, bool) {
	for _, line := range strings.Split(data, "\n") {
		k, ok := kit.NPMCredential(line)
		if !ok {
			continue
		}
		_, v, _ := strings.Cut(line, "=")
		if placeholders[strings.Trim(strings.TrimSpace(strings.TrimSuffix(v, "\r")), `"'`)] {
			continue
		}
		return k, true
	}
	return "", false
}

// registryFileCap is the largest registry file the start reads and
// merges (96 KiB). A file of the agent's home over it is kept as it is,
// with a Note, and never cut (GAP-0978: a 64 KiB read cut an image
// ~/.npmrc and lost its tail settings).
const registryFileCap = 96 << 10

// registryWriteMax bounds a file the start writes. Its content travels in
// one environment variable (DC_REG_*), and Linux refuses an exec whose
// single environment string is over 128 KiB; a merge that would be larger
// is not written (a Note says so), so no file is ever written in part.
const registryWriteMax = 120 << 10

// registryProbeScript prints each registry file of the agent's home and
// the image's global npmrc, after a separator line with a fresh nonce
// (DC_REG_SEP), so file content cannot forge a separator. A link, or a
// file in a folder below $HOME that is a link or not a folder, is named
// (L), never read. Each file is read up to one byte past registryFileCap,
// so a larger one is seen as larger, not as its first part.
var registryProbeScript = `for f in ` + strings.Join(registryFileNames, " ") + `; do
p="$HOME/$f"
l=; d=$(dirname "$f")
while [ "$d" != . ]; do { [ -L "$HOME/$d" ] || { [ -e "$HOME/$d" ] && [ ! -d "$HOME/$d" ]; }; } && l=1; d=$(dirname "$d"); done
if [ -n "$l" ] || [ -L "$p" ]; then printf '\n%s L %s\n' "$DC_REG_SEP" "$f"
elif [ -f "$p" ]; then printf '\n%s F %s\n' "$DC_REG_SEP" "$f"; head -c ` + strconv.Itoa(registryFileCap+1) + ` "$p"; fi
done
if [ -f ` + kit.NPMGlobalConfig + ` ]; then printf '\n%s G global\n' "$DC_REG_SEP"; head -c ` + strconv.Itoa(registryFileCap) + ` ` + kit.NPMGlobalConfig + `; fi
exit 0
`

// registryWriteScript writes each non-empty DC_REG_* file as the agent's
// user (0600), through a fresh temporary file (mktemp, never an existing
// or predictable name) renamed over the old one, so a link put at the file
// in the meantime is replaced, not followed. Each folder below $HOME is
// made one at a time and refused when it is a link or not a folder, and a
// file that is a folder (or a link to one) is refused, so nothing is ever
// written through a link (GAP-0974). A refused file is named on stderr;
// the others are still written, and the script exits 3.
var registryWriteScript = `umask 077
rc=0
w() {
[ -n "$2" ] || return 0
r="$HOME"
for c in $(dirname "$1" | tr / ' '); do
[ "$c" != . ] || continue
r="$r/$c"
if [ -L "$r" ] || { [ -e "$r" ] && [ ! -d "$r" ]; }; then echo "~/$1: ~${r#"$HOME"} is a link or not a folder" >&2; return 3; fi
[ -d "$r" ] || mkdir "$r" || return 3
done
p="$HOME/$1"
if [ -d "$p" ]; then echo "~/$1 is a folder" >&2; return 3; fi
t=$(mktemp "$r/.dc-reg.XXXXXXXX") || return 3
printf '%s' "$2" > "$t" && mv -f "$t" "$p" || { rm -f "$t"; return 3; }
}
` + registryWriteCalls() + `exit $rc
`

var registryEnv = map[string]string{NPMRCFile: "DC_REG_NPMRC", PipConfFile: "DC_REG_PIPCONF", PipLegacyConfFile: "DC_REG_PIPLEGACY", PyPIRCFile: "DC_REG_PYPIRC"}

func registryWriteCalls() string {
	var b strings.Builder
	for _, f := range registryFileNames {
		fmt.Fprintf(&b, "w %s \"$%s\" || rc=3\n", f, registryEnv[f])
	}
	return b.String()
}

// ProbeRegistryFiles reads the registry files of the agent's home and the
// image's global npmrc through the relay.
func ProbeRegistryFiles(ctx context.Context, ex osw.Execer, sandbox string) RegistryProbe {
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	sep := "==DC-REG-" + hex.EncodeToString(nonce[:]) + "=="
	res, err := ex.Exec(ctx, sandbox, osw.ExecRequest{Argv: []string{"/bin/sh", "-c", registryProbeScript},
		Env: map[string]string{"DC_REG_SEP": sep}, Timeout: 30 * time.Second, Idempotent: true})
	p := RegistryProbe{Files: map[string]string{}}
	switch {
	case err != nil:
		p.ReadError = err
		return p
	case res.ExitCode != 0:
		p.ReadError = fmt.Errorf("reading the agent's registry files exited %d", res.ExitCode)
		return p
	}
	parts := strings.Split(string(res.Stdout), "\n"+sep+" ")
	for _, part := range parts[1:] {
		head, body, _ := strings.Cut(part, "\n")
		kind, name, _ := strings.Cut(head, " ")
		switch kind {
		case "L":
			p.Links = append(p.Links, name)
		case "F":
			if len(body) > registryFileCap {
				p.TooLarge = append(p.TooLarge, name)
				continue
			}
			p.Files[name] = body
		case "G":
			for _, line := range strings.Split(body, "\n") {
				if h, ok := strings.CutPrefix(strings.TrimSpace(line), "//"); ok && strings.Contains(h, "/:_authToken=") {
					host, ph, _ := strings.Cut(h, "/:_authToken=")
					host = strings.ToLower(host)
					if p.BakedNPMTokens == nil {
						p.BakedNPMTokens = map[string]string{}
					}
					if _, dup := p.BakedNPMTokens[host]; !dup {
						p.BakedNPM = append(p.BakedNPM, host)
						p.BakedNPMTokens[host] = strings.Trim(strings.TrimSpace(ph), `"'`)
					}
				}
			}
		}
	}
	return p
}

// WriteRegistryFiles writes plan.Write in the agent's home through the
// relay (as the agent's user when the relay is separated), before the agent
// starts.
func WriteRegistryFiles(ctx context.Context, ex osw.Execer, sandbox string, plan RegistryPlan) error {
	if len(plan.Write) == 0 {
		return nil
	}
	env := map[string]string{}
	for f, content := range plan.Write {
		env[registryEnv[f]] = content
	}
	res, err := ex.Exec(ctx, sandbox, osw.ExecRequest{Argv: []string{"/bin/sh", "-c", registryWriteScript}, Env: env, Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New("writing the registry files in the agent failed: " + strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// StartRegistryFiles reads the agent's home, plans the registry files
// for entries and writes them: the agent-start step of B1 2.6.
func StartRegistryFiles(ctx context.Context, ex osw.Execer, sandbox string, entries []RegistryEntry) (RegistryPlan, error) {
	probe := ProbeRegistryFiles(ctx, ex, sandbox)
	if probe.ReadError != nil {
		return RegistryPlan{}, probe.ReadError
	}
	plan := PlanRegistryFiles(entries, probe)
	return plan, WriteRegistryFiles(ctx, ex, sandbox, plan)
}

var (
	registryHostRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	registryValueRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
)
