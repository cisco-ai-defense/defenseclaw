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

package manager

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// The sandbox collector. Discovery of what an agent installed in its
// sandbox, and the opt-in process tree, read the sandbox through one exec of
// a read-only script DefenseClaw builds on the host (collectScript): bash and
// the image's own find, head, tail, tr, readlink and base64, run from the
// root-owned /usr/bin and /bin in an empty environment, as the workload. It
// prints line-framed records, never an archive (see receiveBundle in
// workspace/pull.go: the agent shapes every file, and an archive it made is
// never unpacked on the host). The host names every path it wants read
// (collectPlan, from inventory.PlanSandboxScan) and treats the answer as the
// agent's: a record is kept only when it is well formed, its path is
// absolute, clean, printable and under /sandbox, /work or
// /opt/defenseclaw-harness and within what was asked, and its content fits
// the bounds (ai_discovery.max_file_bytes, max_files_per_scan, the stream's
// collectStreamBytes). What is kept is written as owner-only regular files
// and directories (never links, FIFOs or devices) into a fresh tree under
// <data_dir>/sandboxes/<name>/discovery/root, which the inventory scanner
// reads (see inventory.ScanSandboxRoot).

// collectSchema heads every collector answer; collectEnd closes a complete
// one.
const (
	collectSchema = "dccollect 1"
	collectEnd    = "end"
)

// Collector bounds. collectStreamBytes caps the answer (the exec's stdout).
const (
	collectStreamBytes = 4 << 20
	// collectMaxEntries bounds the entries one answer may make in the tree,
	// and collectDirEntries the entries the script lists per folder pass.
	collectMaxEntries = 8192
	collectDirEntries = 512
	// collectMaxProcesses bounds the processes one answer reports, and
	// collectMaxArgs and collectMaxArgBytes the argument vector kept of each.
	collectMaxProcesses = 4096
	collectMaxArgs      = 16
	collectMaxArgBytes  = 256
	collectMaxEnvNames  = 512
	collectMaxPathBytes = 4096
	collectMaxCommBytes = 64
	// collectManifestDepth bounds how deep a project is searched for
	// package manifests.
	collectManifestDepth = 12
	// userHZ is the clock-tick rate of /proc/<pid>/stat start times, which
	// Linux fixes at 100 for user space on every architecture OpenShell runs.
	userHZ = 100
)

// collectRoots are the sandbox folders whose files the collector may report:
// the workload's home, the live-mounted projects and the harness install.
var collectRoots = []string{connector.SandboxHomeDir, harness.WorkRoot, harness.InstallRootBase}

// sandboxExecutableDirs are the workload-writable folders of the sandbox an
// executable lookup tries, with the harness's own bin folder: a CLI the agent
// installed lands in one of them. /usr and /bin are the image's.
var sandboxExecutableDirs = []string{
	connector.SandboxHomeDir + "/.local/bin", connector.SandboxHomeDir + "/bin", connector.SandboxHomeDir + "/.npm-global/bin",
	connector.SandboxHomeDir + "/.cargo/bin", connector.SandboxHomeDir + "/go/bin", connector.SandboxHomeDir + "/.bun/bin",
	connector.SandboxHomeDir + "/.deno/bin", connector.SandboxHomeDir + "/.volta/bin",
}

// collectScript is the collector, run as
//
//	bash -p -c collectScript defenseclaw-collect MODE MAXBYTES DIRMAX [KIND VALUE]...
//
// MODE is discover (the workload's processes, its environment variable
// names, the paths the KIND VALUE pairs name) or ps (every process, for the
// process tree). Pairs: S path (presence), D1/D2/D3 path (a folder, listed
// that deep), C path (content), H path (content, its last MAXBYTES), W path
// (a project searched for the manifests M name and U suffix, not entering K
// folders), N name and R dir (an executable lookup), O argv|cwd (ps mode:
// also each process's arguments or working directory).
//
// Records, one per line: "T 100 <boot epoch>", "P pid ppid uid start
// state", "Pc pid comm", "Pa pid arg", "Pt pid argv0-target", "L /proc/pid
// exe|cwd target", "V name", "X size mtime path", "E type size mtime path"
// (type f, d, l or another find %y letter), "F path" followed by the file's
// base64 on the next line, "Q what" (a bound was reached) and "end". Paths
// and text come last on their line. find prints NUL-terminated records that
// tr turns into lines, with a newline inside one turned into \001, which the
// host refuses; the shell's own text has its control characters replaced.
// A path with a control character is skipped. Files are read only when
// they are regular files as looked at and as opened, and never past their
// bound; nothing in the sandbox is written. A FIFO swapped in between the
// look and the open holds the read until the exec's timeout stops the
// script: that run reports nothing, and the last record stays.
const collectScript = `export LC_ALL=C
mode=$1 max=$2 dirmax=$3
shift 3
st=() rd=() hs=() wk=() nm=() pd=() mn=() ms=() sk=() dl=() dd=()
argv=0 cwd=0
while [ "$#" -ge 2 ]; do
  case $1 in
    S) st+=("$2") ;; C) rd+=("$2") ;; H) hs+=("$2") ;; W) wk+=("$2") ;;
    N) nm+=("$2") ;; R) pd+=("$2") ;; M) mn+=("$2") ;; U) ms+=("$2") ;; K) sk+=("$2") ;;
    D1|D2|D3) dl+=("$2"); dd+=("${1#D}") ;;
    O) case $2 in argv) argv=1 ;; cwd) cwd=1 ;; esac ;;
  esac
  shift 2
done
nl0() { tr '\n\0' '\001\n'; }
clean() { local v=$1; v=${v//[[:cntrl:]]/?}; R=${v:0:$2}; }
ctl() { case $1 in *[[:cntrl:]]*) return 0 ;; esac; return 1; }
content() {
  ctl "$1" && return 0
  [ -f "$1" ] && [ ! -p "$1" ] || return 0
  { exec 3<"$1"; } 2>/dev/null || return 0
  [ -f /dev/fd/3 ] || [ -f /proc/self/fd/3 ] || { exec 3<&-; return 0; }
  printf 'F %s\n' "$1"
  if [ "$2" = tail ]; then tail -c "$max" <&3 | base64 -w0; else head -c "$max" <&3 | base64 -w0; fi
  printf '\n'
  exec 3<&-
}
printf '%s\n' 'dccollect 1'
while read -r k v _; do [ "$k" = btime ] && printf 'T 100 %s\n' "$v"; done < /proc/stat
uid=$EUID n=0
declare -A envs=()
for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  line=
  { read -r -d '' line < "$d/stat"; } 2>/dev/null
  [ -n "$line" ] || continue
  u=
  while read -r k a b _; do [ "$k" = Uid: ] && { u=$b; break; }; done 2>/dev/null < "$d/status"
  [ -n "$u" ] || continue
  [ "$mode" = ps ] || [ "$u" = "$uid" ] || continue
  n=$((n + 1))
  [ "$n" -le 4096 ] || { printf 'Q processes\n'; break; }
  set -f; set -- ${line##*) }; set +f
  printf 'P %s %s %s %s %s\n' "$pid" "$2" "$u" "${20:-0}" "$1"
  comm=
  { read -r -d '' comm < "$d/comm"; } 2>/dev/null
  comm=${comm%$'\n'}
  clean "$comm" 64
  printf 'Pc %s %s\n' "$pid" "$R"
  i=0
  if [ "$mode" = discover ] || [ "$argv" = 1 ]; then
    while { IFS= read -r -d '' a || [ -n "$a" ]; } && [ "$i" -lt 16 ]; do
      clean "$a" 256
      printf 'Pa %s %s\n' "$pid" "$R"
      i=$((i + 1))
      if [ "$mode" = discover ]; then
        t=
        if [ "${a##*/}" != "$comm" ]; then
          case $a in
            /*) t=$(readlink -f -- "$a" 2>/dev/null) ;;
            */*) t=$(readlink -f -- "$d/cwd/$a" 2>/dev/null) ;;
          esac
        fi
        [ -n "$t" ] && clean "$t" 4096 && printf 'Pt %s %s\n' "$pid" "$R"
        break
      fi
      a=
    done 2>/dev/null < "$d/cmdline"
  fi
  if [ "$mode" = discover ] && [ "${#envs[@]}" -lt 512 ]; then
    while IFS= read -r -d '' kv; do
      k=${kv%%=*}
      [[ $k =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] && envs[$k]=1
    done 2>/dev/null < "$d/environ"
  fi
done
for k in "${!envs[@]}"; do printf 'V %s\n' "$k"; done
if [ "$cwd" = 1 ]; then
  find /proc -mindepth 2 -maxdepth 2 -path '/proc/[0-9]*' \( -name exe -o -name cwd \) -printf 'L %h %f %l\0' 2>/dev/null | nl0
else
  find /proc -mindepth 2 -maxdepth 2 -path '/proc/[0-9]*' -name exe -printf 'L %h %f %l\0' 2>/dev/null | nl0
fi
[ "$mode" = discover ] || { printf '%s\n' end; exit 0; }
for e in "${nm[@]}"; do
  for d in "${pd[@]}"; do
    p=$d/$e
    if [ -f "$p" ] && [ -x "$p" ]; then
      find -H "$p" -maxdepth 0 -printf 'X %s %T@ %p\0' 2>/dev/null | nl0
      break
    fi
  done
done
[ "${#st[@]}" -eq 0 ] || find -H "${st[@]}" -maxdepth 0 -printf 'E %y %s %T@ %p\0' 2>/dev/null | nl0
for i in "${!dl[@]}"; do
  d=${dl[$i]}
  [ -e "$d" ] || continue
  find -H "$d" -maxdepth 0 -printf 'E %y %s %T@ %p\0' 2>/dev/null | nl0
  [ -d "$d" ] || continue
  find -H "$d" -mindepth 1 -maxdepth 1 -printf 'E %y %s %T@ %p\0' 2>/dev/null | head -z -n "$dirmax" | nl0
  [ "${dd[$i]}" -gt 1 ] || continue
  find -H "$d" -mindepth 2 -maxdepth "${dd[$i]}" -printf 'E %y %s %T@ %p\0' 2>/dev/null | head -z -n "$dirmax" | nl0
done
for f in "${rd[@]}" "${hs[@]}"; do
  [ -e "$f" ] && find -H "$f" -maxdepth 0 -printf 'E %y %s %T@ %p\0' 2>/dev/null | nl0
done
for f in "${rd[@]}"; do
  [ -f "$f" ] || continue
  sz=$(find -H "$f" -maxdepth 0 -size -$((max + 1))c -printf 1 2>/dev/null)
  [ -n "$sz" ] && content "$f" head
done
for f in "${hs[@]}"; do content "$f" tail; done
names=()
for m in "${mn[@]}"; do names+=(-o -name "$m"); done
for m in "${ms[@]}"; do names+=(-o -name "*$m"); done
skips=()
for m in "${sk[@]}"; do skips+=(-o -iname "$m"); done
for w in "${wk[@]}"; do
  [ -d "$w" ] && [ "${#names[@]}" -gt 0 ] || continue
  while IFS= read -r -d '' r; do
    sz=${r%% *} r=${r#* } mt=${r%% *} f=${r#* }
    ctl "$f" && continue
    printf 'E f %s %s %s\n' "$sz" "$mt" "$f"
    content "$f" head
  done < <(find -H "$w" -mindepth 1 -maxdepth 12 \( -type d \( -false "${skips[@]}" \) -prune \) -o -type f \( -false "${names[@]}" \) -size -$((max + 1))c -printf '%s %T@ %p\0' 2>/dev/null | head -z -n "$dirmax")
done
printf '%s\n' end
`

// collectArgv is the collector's command for mode and its KIND VALUE pairs.
// It runs in an empty environment with every tool from the image's
// root-owned /usr/bin and /bin: the workload cannot plant one.
func collectArgv(mode string, maxBytes int64, pairs []string) []string {
	argv := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + connector.SandboxHomeDir, "LC_ALL=C",
		"/bin/bash", "-p", "-c", collectScript, "defenseclaw-collect", mode, strconv.FormatInt(maxBytes, 10), strconv.Itoa(collectDirEntries)}
	return append(argv, pairs...)
}

// collectScope is what one collector run asked for: the answer may report
// these paths and nothing else.
type collectScope struct {
	// roots are the sandbox folders anything may be under (collectRoots).
	roots []string
	// exact are paths asked for by name (presence, content, history);
	// content the ones whose content was asked for.
	exact, content map[string]bool
	// dirs are folders listed, with their depth; walks are projects
	// searched for manifests (manifests and suffixes name them).
	dirs      map[string]int
	walks     []string
	manifests map[string]bool
	suffixes  []string
	// exeDirs and binaries make up the executable lookups.
	exeDirs  map[string]bool
	binaries map[string]bool
}

func newCollectScope() *collectScope {
	return &collectScope{roots: collectRoots, exact: map[string]bool{}, content: map[string]bool{}, dirs: map[string]int{},
		manifests: map[string]bool{}, exeDirs: map[string]bool{}, binaries: map[string]bool{}}
}

// inRoots reports a sandbox path under one of the scope's roots.
func (s *collectScope) inRoots(p string) bool {
	for _, root := range s.roots {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// entryAllowed reports whether the answer may report an entry at p: asked
// for by name, a folder listed or inside one within its depth, or a manifest
// in a project searched.
func (s *collectScope) entryAllowed(p string) bool {
	if !s.inRoots(p) {
		return false
	}
	if s.exact[p] {
		return true
	}
	if _, ok := s.dirs[p]; ok {
		return true
	}
	level := 0
	for anc := path.Dir(p); ; anc = path.Dir(anc) {
		level++
		if depth, ok := s.dirs[anc]; ok && level <= depth {
			return true
		}
		if anc == "/" || level > collectManifestDepth {
			break
		}
	}
	return s.manifestAllowed(p)
}

// manifestAllowed reports a package manifest inside a project searched.
func (s *collectScope) manifestAllowed(p string) bool {
	base := path.Base(p)
	named := s.manifests[base]
	for _, suffix := range s.suffixes {
		named = named || strings.HasSuffix(strings.ToLower(base), suffix)
	}
	if !named {
		return false
	}
	for _, w := range s.walks {
		if strings.HasPrefix(p, w+"/") && strings.Count(p[len(w):], "/") <= collectManifestDepth {
			return true
		}
	}
	return false
}

// contentAllowed reports a file whose content may be sent.
func (s *collectScope) contentAllowed(p string) bool {
	return s.inRoots(p) && (s.content[p] || s.manifestAllowed(p))
}

// executableAllowed reports an executable a lookup asked for.
func (s *collectScope) executableAllowed(p string) bool {
	return s.inRoots(p) && s.exeDirs[path.Dir(p)] && s.binaries[path.Base(p)]
}

// collectedEntry is one entry of the tree the answer reports.
type collectedEntry struct {
	Path  string
	Type  byte // 'f', 'd' or 'l'
	Size  int64
	MTime time.Time
}

// collectedProcess is one process of the answer. Every field is the
// sandbox's, and the text ones the workload's to choose.
type collectedProcess struct {
	PID, PPID, UID int
	StartTicks     int64
	State          string
	Comm           string
	Args           []string
	Argv0Target    string
	Exe, Cwd       string
}

// collection is a parsed collector answer.
type collection struct {
	// Boot is the sandbox kernel's boot time (/proc/stat btime), which
	// process start times count from.
	Boot        time.Time
	Processes   []*collectedProcess
	EnvNames    []string
	Executables map[string]collectedEntry
	Entries     []collectedEntry
	Contents    map[string][]byte
	// ProcessesCapped reports processes left out at the process bound.
	ProcessesCapped bool
	// Ended is set when the answer was complete.
	Ended bool
	// Problems say where the answer fell short (a bound, records refused).
	Problems []string
	// Refused counts the records refused.
	Refused int
}

// started is when a process started, or zero when unknown.
func (c *collection) started(p *collectedProcess) time.Time {
	if c.Boot.IsZero() || p.StartTicks <= 0 {
		return time.Time{}
	}
	return c.Boot.Add(time.Duration(p.StartTicks) * time.Second / userHZ).UTC()
}

var (
	collectEnvName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	collectProcPath = regexp.MustCompile(`^/proc/([0-9]{1,10})$`)
)

// parseCollection reads a collector answer. truncated reports an answer cut
// at its bound: its last, partial line is dropped. Only records the scope
// allows are kept; every other one is counted as refused, and the answer
// stays usable. An answer without the schema line is not the collector's.
func parseCollection(out []byte, truncated bool, scope *collectScope, maxFileBytes int64) (*collection, error) {
	c := &collection{Executables: map[string]collectedEntry{}, Contents: map[string][]byte{}}
	lines := bytes.Split(out, []byte{'\n'})
	// What follows the last newline is a line cut short (or nothing).
	if last := lines[len(lines)-1]; len(last) > 0 || truncated {
		truncated = true
	}
	lines = lines[:len(lines)-1]
	if len(lines) == 0 || string(lines[0]) != collectSchema {
		return nil, errors.New("the sandbox's answer is not the collector's")
	}
	procs := map[int]*collectedProcess{}
	envs := map[string]bool{}
	seenEntry := map[string]bool{}
	entryCapped := false
	refuse := func() { c.Refused++ }
	for i := 1; i < len(lines); i++ {
		line := string(lines[i])
		if c.Ended {
			c.Problems = append(c.Problems, "the collector's answer goes on after its end")
			c.Ended = false
			break
		}
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case collectEnd:
			if rest != "" {
				refuse()
				continue
			}
			c.Ended = true
		case "T":
			hz, boot, ok := strings.Cut(rest, " ")
			secs, err := strconv.ParseInt(boot, 10, 64)
			if !ok || hz != strconv.Itoa(userHZ) || err != nil || secs <= 0 || secs > 1<<40 {
				refuse()
				continue
			}
			c.Boot = time.Unix(secs, 0).UTC()
		case "P":
			f := strings.Split(rest, " ")
			if len(c.Processes) >= collectMaxProcesses {
				c.ProcessesCapped = true
				continue
			}
			if len(f) != 5 {
				refuse()
				continue
			}
			pid, e1 := strconv.Atoi(f[0])
			ppid, e2 := strconv.Atoi(f[1])
			uid, e3 := strconv.Atoi(f[2])
			start, e4 := strconv.ParseInt(f[3], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || pid <= 0 || ppid < 0 || uid < 0 || start < 0 ||
				len(f[4]) != 1 || !isASCIILetter(f[4][0]) || procs[pid] != nil {
				refuse()
				continue
			}
			p := &collectedProcess{PID: pid, PPID: ppid, UID: uid, StartTicks: start, State: f[4]}
			procs[pid] = p
			c.Processes = append(c.Processes, p)
		case "Pc", "Pa", "Pt":
			pidText, text, _ := strings.Cut(rest, " ")
			pid, err := strconv.Atoi(pidText)
			p := procs[pid]
			if err != nil || p == nil {
				refuse()
				continue
			}
			switch tag {
			case "Pc":
				p.Comm = collectText(text, collectMaxCommBytes)
			case "Pa":
				if len(p.Args) < collectMaxArgs {
					p.Args = append(p.Args, collectText(text, collectMaxArgBytes))
				}
			case "Pt":
				if target, ok := cleanCollectPath(text); ok {
					p.Argv0Target = target
				}
			}
		case "L":
			proc, link, _ := strings.Cut(rest, " ")
			kind, target, _ := strings.Cut(link, " ")
			m := collectProcPath.FindStringSubmatch(proc)
			if m == nil {
				refuse()
				continue
			}
			pid, _ := strconv.Atoi(m[1])
			p := procs[pid]
			target, ok := cleanCollectPath(strings.TrimSuffix(target, " (deleted)"))
			if p == nil || !ok || (kind != "exe" && kind != "cwd") {
				// Another process's link (one the answer reports no process
				// for), or one the collector could not read.
				continue
			}
			if kind == "exe" {
				p.Exe = target
			} else {
				p.Cwd = target
			}
		case "V":
			if !collectEnvName.MatchString(rest) || envs[rest] || len(c.EnvNames) >= collectMaxEnvNames {
				refuse()
				continue
			}
			envs[rest] = true
			c.EnvNames = append(c.EnvNames, rest)
		case "X":
			e, ok := parseCollectEntry("f " + rest)
			if !ok || !scope.executableAllowed(e.Path) {
				refuse()
				continue
			}
			name := path.Base(e.Path)
			if _, dup := c.Executables[name]; !dup {
				c.Executables[name] = e
			}
		case "E":
			e, ok := parseCollectEntry(rest)
			if !ok || !scope.entryAllowed(e.Path) {
				refuse()
				continue
			}
			if seenEntry[e.Path] {
				continue
			}
			if len(c.Entries) >= collectMaxEntries {
				entryCapped = true
				continue
			}
			seenEntry[e.Path] = true
			c.Entries = append(c.Entries, e)
		case "F":
			p, ok := cleanCollectPath(rest)
			if i+1 >= len(lines) {
				// Its data line was cut off.
				refuse()
				continue
			}
			i++
			data := lines[i]
			if !ok || !scope.contentAllowed(p) {
				refuse()
				continue
			}
			if int64(base64.StdEncoding.DecodedLen(len(data))) > maxFileBytes+2 {
				refuse()
				c.Problems = appendOnce(c.Problems, fmt.Sprintf("a file over %d bytes was not read", maxFileBytes))
				continue
			}
			content, err := base64.StdEncoding.DecodeString(string(data))
			if err != nil || int64(len(content)) > maxFileBytes {
				refuse()
				continue
			}
			c.Contents[p] = content
		case "Q":
			c.ProcessesCapped = c.ProcessesCapped || rest == "processes"
			c.Problems = appendOnce(c.Problems, "the collector stopped at its bound of "+collectText(rest, 64))
		default:
			refuse()
		}
	}
	if entryCapped {
		c.Problems = append(c.Problems, fmt.Sprintf("the sandbox listed more than %d entries", collectMaxEntries))
	}
	if c.ProcessesCapped {
		c.Problems = appendOnce(c.Problems, fmt.Sprintf("the sandbox has more than %d processes", collectMaxProcesses))
	}
	// A file whose content was asked for and that is over the bound is
	// listed but not read: what it configures is unknown.
	oversize := 0
	for _, e := range c.Entries {
		if _, read := c.Contents[e.Path]; !read && e.Type == 'f' && e.Size > maxFileBytes && scope.contentAllowed(e.Path) {
			oversize++
		}
	}
	if oversize > 0 {
		c.Problems = append(c.Problems, fmt.Sprintf("%d file(s) over %d bytes were not read", oversize, maxFileBytes))
	}
	if truncated {
		c.Problems = append(c.Problems, fmt.Sprintf("the collector's answer was cut at %d bytes", collectStreamBytes))
	} else if !c.Ended {
		c.Problems = append(c.Problems, "the collector's answer was cut short")
	}
	if c.Refused > 0 {
		c.Problems = append(c.Problems, fmt.Sprintf("%d records the sandbox sent were refused", c.Refused))
	}
	return c, nil
}

// parseCollectEntry reads "type size mtime path".
func parseCollectEntry(rest string) (collectedEntry, bool) {
	f := strings.SplitN(rest, " ", 4)
	if len(f) != 4 || len(f[0]) != 1 {
		return collectedEntry{}, false
	}
	size, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || size < 0 {
		return collectedEntry{}, false
	}
	secs, err := strconv.ParseFloat(f[2], 64)
	if err != nil || math.IsNaN(secs) || secs < 0 || secs > 1<<33 {
		return collectedEntry{}, false
	}
	p, ok := cleanCollectPath(f[3])
	if !ok {
		return collectedEntry{}, false
	}
	return collectedEntry{Path: p, Type: f[0][0], Size: size, MTime: time.Unix(0, int64(secs*float64(time.Second))).UTC()}, true
}

// cleanCollectPath accepts an absolute, clean, printable sandbox path within
// the path bounds.
func cleanCollectPath(p string) (string, bool) {
	if p == "" || len(p) > collectMaxPathBytes || !utf8.ValidString(p) || !path.IsAbs(p) || path.Clean(p) != p {
		return "", false
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return "", false
		}
	}
	for _, elem := range strings.Split(p[1:], "/") {
		if len(elem) > 255 || elem == ".." {
			return "", false
		}
	}
	return p, true
}

// collectText is agent-chosen display text: valid UTF-8, no control
// characters, at most limit bytes.
func collectText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	return truncate(s, limit)
}

func isASCIILetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// writeCollectedTree writes the entries and contents of c into a fresh tree
// at root (removed first): folders 0700, files 0600 regular files holding
// their content (empty without one), a link or another type as an empty
// file or not at all, each with its modification time. Every component is
// created here, so nothing in the tree can lead outside it. It returns how
// many entries it wrote.
func writeCollectedTree(root string, c *collection) (int, error) {
	if !filepath.IsAbs(root) {
		return 0, fmt.Errorf("the discovery tree %s is not absolute", root)
	}
	if err := os.RemoveAll(root); err != nil {
		return 0, err
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return 0, err
	}
	entries := map[string]collectedEntry{}
	for _, e := range c.Entries {
		entries[e.Path] = e
	}
	for p := range c.Contents {
		if e, ok := entries[p]; !ok || e.Type != 'f' {
			entries[p] = collectedEntry{Path: p, Type: 'f', MTime: entries[p].MTime}
		}
	}
	for _, e := range c.Executables {
		if _, ok := entries[e.Path]; !ok {
			entries[e.Path] = e
		}
	}
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	made := map[string]byte{"/": 'd'}
	var dirs []collectedEntry
	written := 0
	host := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	// mkdirs makes the folders above p, refusing a component written as a
	// file already.
	mkdirs := func(p string) bool {
		var chain []string
		for anc := path.Dir(p); anc != "/"; anc = path.Dir(anc) {
			chain = append(chain, anc)
		}
		for i := len(chain) - 1; i >= 0; i-- {
			anc := chain[i]
			switch made[anc] {
			case 'd':
				continue
			case 0:
				if err := os.Mkdir(host(anc), 0o700); err != nil {
					return false
				}
				made[anc] = 'd'
			default:
				return false
			}
		}
		return true
	}
	for _, p := range paths {
		e := entries[p]
		if made[p] != 0 || !mkdirs(p) {
			c.Refused++
			continue
		}
		switch e.Type {
		case 'd':
			if err := os.Mkdir(host(p), 0o700); err != nil {
				c.Refused++
				continue
			}
			made[p] = 'd'
			dirs = append(dirs, e)
		case 'f', 'l':
			// A link is listed as what it is called, never followed or made.
			if err := writeCollectedFile(host(p), c.Contents[p]); err != nil {
				c.Refused++
				continue
			}
			made[p] = 'f'
			setCollectedTime(host(p), e.MTime)
		default:
			// A FIFO, socket or device is not reproduced.
			c.Refused++
			continue
		}
		written++
	}
	// Folders last, deepest first: writing into one changes its time.
	slices.SortFunc(dirs, func(a, b collectedEntry) int { return strings.Count(b.Path, "/") - strings.Count(a.Path, "/") })
	for _, e := range dirs {
		setCollectedTime(host(e.Path), e.MTime)
	}
	return written, nil
}

// writeCollectedFile creates one new owner-only regular file, never following
// what is at its path.
func writeCollectedFile(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func setCollectedTime(p string, t time.Time) {
	if t.IsZero() {
		return
	}
	_ = os.Chtimes(p, t, t)
}

// removeTree removes a discovery tree, refusing a link in its place.
func removeTree(p string) error {
	if info, err := os.Lstat(p); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return os.Remove(p)
	}
	return os.RemoveAll(p)
}
