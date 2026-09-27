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

package image

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// probeSchema is the first line every probe prints.
const probeSchema = "dcprobe 1"

// ProbedFile is one in-image file as the probe saw it.
type ProbedFile struct {
	Path   string
	Mode   uint32
	UID    int
	GID    int
	SHA256 string
}

// ProbedDir is one in-image directory as the probe saw it.
type ProbedDir struct {
	Path string
	Mode uint32
	UID  int
	GID  int
}

// Binary is a resolved in-image executable.
type Binary struct {
	Name     string `json:"name,omitempty"`
	Realpath string `json:"realpath"`
	SHA256   string `json:"sha256"`
}

// ProbeResult is the parsed output of the post-build probe.
type ProbeResult struct {
	Files          map[string]ProbedFile
	Missing        []string
	Dirs           map[string]ProbedDir
	Binaries       map[string]Binary
	MissingBinary  []string
	VersionLine    string
	HarnessVersion string
	NetworkBinary  []Binary
	// Owners records the mode and owner of every resolved binary and
	// network binary realpath.
	Owners map[string]ProbedFile
}

// workloadWritableRoots hold files the sandbox workload can create or
// replace; a required binary must never resolve below one of them.
var workloadWritableRoots = []string{connector.SandboxHomeDir, "/tmp", "/var/tmp", "/dev/shm", "/work", "/home", "/run", "/proc"}

var (
	probeSHARE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	probePathRE = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]*$`)
)

// probeScript returns the POSIX sh program the probe runs inside the image.
// It prints one record per line; every value is a path, number or digest,
// so records are space-separated.
func probeScript(c *Context) string {
	var b strings.Builder
	b.WriteString("set -u\n")
	b.WriteString("printf '%s\\n' " + shQuote(probeSchema) + "\n")
	b.WriteString(`meta() { stat -c '%a %u %g' "$1" 2>/dev/null; }` + "\n")
	b.WriteString(`digest() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }` + "\n")
	for _, f := range c.ImageFiles {
		q := shQuote(f.Path)
		fmt.Fprintf(&b, "if [ -f %s ] && [ ! -L %s ]; then printf 'file %%s %%s %%s\\n' %s \"$(meta %s)\" \"$(digest %s)\"; else printf 'missing %%s\\n' %s; fi\n", q, q, q, q, q, q)
	}
	for _, d := range c.Dirs {
		q := shQuote(d)
		fmt.Fprintf(&b, "if [ -d %s ] && [ ! -L %s ]; then printf 'dir %%s %%s\\n' %s \"$(meta %s)\"; else printf 'missing %%s\\n' %s; fi\n", q, q, q, q, q)
	}
	for _, bin := range c.Artifacts.Binaries {
		q := shQuote(bin.Name)
		// The hooks run their tools from the baked PATH, never the image's;
		// the harness itself is what the workload PATH starts.
		lookup := "command -v " + q
		if bin.Role == connector.SandboxBinaryRuntime {
			lookup = "PATH=" + shQuote(connector.SandboxHookPATH) + "; " + lookup
		}
		fmt.Fprintf(&b, "p=\"$(%s 2>/dev/null)\"; case \"$p\" in /*) r=\"$(readlink -f \"$p\")\"; printf 'bin %%s %%s %%s %%s\\n' %s \"$r\" \"$(digest \"$r\")\" \"$(meta \"$r\")\" ;; *) printf 'nobin %%s\\n' %s ;; esac\n", lookup, q, q)
	}
	probe := c.Spec.Harness.Probe()
	argv := make([]string, 0, len(probe.VersionArgv))
	for _, a := range probe.VersionArgv {
		argv = append(argv, shQuote(a))
	}
	fmt.Fprintf(&b, "printf 'version %%s\\n' \"$(%s 2>/dev/null | head -n 1 | tr -cd 'A-Za-z0-9 ._()+-')\"\n", strings.Join(argv, " "))
	fmt.Fprintf(&b, "( %s\n) 2>/dev/null | while IFS= read -r n; do [ -n \"$n\" ] && [ -f \"$n\" ] && printf 'net %%s %%s %%s\\n' \"$n\" \"$(digest \"$n\")\" \"$(meta \"$n\")\"; done\n", probe.NetworkBinaries)
	b.WriteString("printf 'end\\n'\n")
	return b.String()
}

// ParseProbe parses probe output. It is strict about the record grammar and
// requires the schema header and the end marker, so truncated or foreign
// output never verifies.
func ParseProbe(out []byte, versionRE *regexp.Regexp) (ProbeResult, error) {
	res := ProbeResult{Files: map[string]ProbedFile{}, Dirs: map[string]ProbedDir{}, Binaries: map[string]Binary{}, Owners: map[string]ProbedFile{}}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	started, ended := false, false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if !started {
			if line == probeSchema {
				started = true
			}
			continue
		}
		if ended {
			if strings.TrimSpace(line) != "" {
				return res, fmt.Errorf("probe: output after end marker")
			}
			continue
		}
		kind, rest, _ := strings.Cut(line, " ")
		fields := strings.Fields(rest)
		switch kind {
		case "file":
			if len(fields) != 5 || !probePathRE.MatchString(fields[0]) || !probeSHARE.MatchString(fields[4]) {
				return res, fmt.Errorf("probe: malformed file record %q", line)
			}
			mode, uid, gid, err := parseMeta(fields[1], fields[2], fields[3])
			if err != nil {
				return res, fmt.Errorf("probe: %q: %w", line, err)
			}
			res.Files[fields[0]] = ProbedFile{Path: fields[0], Mode: mode, UID: uid, GID: gid, SHA256: fields[4]}
		case "dir":
			if len(fields) != 4 || !probePathRE.MatchString(fields[0]) {
				return res, fmt.Errorf("probe: malformed dir record %q", line)
			}
			mode, uid, gid, err := parseMeta(fields[1], fields[2], fields[3])
			if err != nil {
				return res, fmt.Errorf("probe: %q: %w", line, err)
			}
			res.Dirs[fields[0]] = ProbedDir{Path: fields[0], Mode: mode, UID: uid, GID: gid}
		case "missing":
			if len(fields) != 1 {
				return res, fmt.Errorf("probe: malformed missing record %q", line)
			}
			res.Missing = append(res.Missing, fields[0])
		case "bin":
			if len(fields) != 6 || !probePathRE.MatchString(fields[1]) || !probeSHARE.MatchString(fields[2]) {
				return res, fmt.Errorf("probe: malformed bin record %q", line)
			}
			mode, uid, gid, err := parseMeta(fields[3], fields[4], fields[5])
			if err != nil {
				return res, fmt.Errorf("probe: %q: %w", line, err)
			}
			res.Binaries[fields[0]] = Binary{Name: fields[0], Realpath: fields[1], SHA256: fields[2]}
			res.Owners[fields[1]] = ProbedFile{Path: fields[1], Mode: mode, UID: uid, GID: gid, SHA256: fields[2]}
		case "nobin":
			if len(fields) != 1 {
				return res, fmt.Errorf("probe: malformed nobin record %q", line)
			}
			res.MissingBinary = append(res.MissingBinary, fields[0])
		case "version":
			res.VersionLine = strings.TrimSpace(rest)
			if versionRE != nil {
				if m := versionRE.FindStringSubmatch(res.VersionLine); len(m) == 2 {
					res.HarnessVersion = m[1]
				}
			}
		case "net":
			if len(fields) != 5 || !probePathRE.MatchString(fields[0]) || !probeSHARE.MatchString(fields[1]) {
				return res, fmt.Errorf("probe: malformed net record %q", line)
			}
			mode, uid, gid, err := parseMeta(fields[2], fields[3], fields[4])
			if err != nil {
				return res, fmt.Errorf("probe: %q: %w", line, err)
			}
			res.NetworkBinary = append(res.NetworkBinary, Binary{Realpath: fields[0], SHA256: fields[1]})
			res.Owners[fields[0]] = ProbedFile{Path: fields[0], Mode: mode, UID: uid, GID: gid, SHA256: fields[1]}
		case "end":
			ended = true
		default:
			return res, fmt.Errorf("probe: unknown record %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("probe: read output: %w", err)
	}
	if !started || !ended {
		return res, fmt.Errorf("probe: output is incomplete (header=%t end=%t)", started, ended)
	}
	sort.Strings(res.Missing)
	sort.Strings(res.MissingBinary)
	sort.Slice(res.NetworkBinary, func(i, j int) bool { return res.NetworkBinary[i].Realpath < res.NetworkBinary[j].Realpath })
	return res, nil
}

func parseMeta(modeText, uidText, gidText string) (uint32, int, int, error) {
	mode, err := strconv.ParseUint(modeText, 8, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("bad mode %q", modeText)
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("bad uid %q", uidText)
	}
	gid, err := strconv.Atoi(gidText)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("bad gid %q", gidText)
	}
	return uint32(mode), uid, gid, nil
}

// Verify checks a probe result against the context it was built from: every
// artifact present with the rendered bytes, mode and owner, DefenseClaw
// directories root-owned 0755, every required binary resolvable, the pinned
// harness version installed and at least one network binary found.
func (c *Context) Verify(res ProbeResult) error {
	var problems []string
	for _, f := range c.ImageFiles {
		got, ok := res.Files[f.Path]
		if !ok {
			problems = append(problems, f.Path+" is missing")
			continue
		}
		sum := sha256.Sum256(f.Data)
		if got.SHA256 != hex.EncodeToString(sum[:]) {
			problems = append(problems, f.Path+" content differs from the rendered artifact")
		}
		if got.Mode != uint32(f.Mode.Perm()) {
			problems = append(problems, fmt.Sprintf("%s mode %04o, want %04o", f.Path, got.Mode, uint32(f.Mode.Perm())))
		}
		if got.UID != f.UID || got.GID != f.GID {
			problems = append(problems, fmt.Sprintf("%s owner %d:%d, want %d:%d", f.Path, got.UID, got.GID, f.UID, f.GID))
		}
	}
	for _, d := range c.Dirs {
		got, ok := res.Dirs[d]
		if !ok {
			problems = append(problems, d+" directory is missing")
			continue
		}
		if got.UID != 0 || got.GID != 0 || got.Mode != 0o755 {
			problems = append(problems, fmt.Sprintf("%s is %04o %d:%d, want root 0755", d, got.Mode, got.UID, got.GID))
		}
	}
	for _, bin := range c.Artifacts.Binaries {
		got, ok := res.Binaries[bin.Name]
		if !ok {
			where := "the image PATH"
			if bin.Role == connector.SandboxBinaryRuntime {
				where = "the baked hook PATH " + connector.SandboxHookPATH
			}
			problems = append(problems, "binary "+bin.Name+" is not on "+where)
			continue
		}
		if problem := workloadWritableBinary(got.Realpath, res.Owners[got.Realpath]); problem != "" {
			problems = append(problems, "binary "+bin.Name+" "+problem)
		}
	}
	for _, bin := range res.NetworkBinary {
		if problem := workloadWritableBinary(bin.Realpath, res.Owners[bin.Realpath]); problem != "" {
			problems = append(problems, "network binary "+problem)
		}
	}
	if res.HarnessVersion != c.HarnessVersion {
		problems = append(problems, fmt.Sprintf("%s reports %q, want the pinned %s", c.Spec.Harness.Command, res.VersionLine, c.HarnessVersion))
	}
	if len(res.NetworkBinary) == 0 {
		problems = append(problems, "no harness network binary was found")
	}
	if len(problems) > 0 {
		return fmt.Errorf("openshell image %s failed verification: %s", c.Tag, strings.Join(problems, "; "))
	}
	return nil
}

// workloadWritableBinary explains why the sandbox workload could replace the
// binary at realpath, or returns "": it must be a root:root file that
// neither group nor others can write, outside every workload-writable root.
func workloadWritableBinary(realpath string, meta ProbedFile) string {
	for _, root := range workloadWritableRoots {
		if realpath == root || strings.HasPrefix(realpath, root+"/") {
			return fmt.Sprintf("resolves to %s, under the workload-writable %s", realpath, root)
		}
	}
	if meta.Path != realpath {
		return fmt.Sprintf("resolves to %s, whose owner the probe did not report", realpath)
	}
	if meta.UID != 0 || meta.GID != 0 || meta.Mode&0o022 != 0 {
		return fmt.Sprintf("resolves to %s (%04o %d:%d), want a root:root file only root can write", realpath, meta.Mode, meta.UID, meta.GID)
	}
	return ""
}

// probeRunArgs is the docker run argv of the post-build probe: no network,
// the sandbox run-as identity, HOME as OpenShell sets it, the harness's
// startup env, and the script on stdin-free argv.
func probeRunArgs(c *Context) []string {
	args := []string{"run", "--rm", "--network", "none",
		"--user", strconv.Itoa(c.Spec.UID) + ":" + strconv.Itoa(c.Spec.GID),
		"-e", "HOME=" + connector.SandboxHomeDir,
	}
	keys := make([]string, 0, len(c.Artifacts.Env))
	for key := range c.Artifacts.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "-e", key+"="+c.Artifacts.Env[key])
	}
	return append(args, "--entrypoint", "/bin/sh", c.Tag, "-c", probeScript(c))
}

// shQuote single-quotes s for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
