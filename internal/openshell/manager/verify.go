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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The workload check after ready. A sandbox runs as DefenseClaw prepared it
// when its workload runs as the identity its image was built for, holds no
// capabilities and can write its home, and when DefenseClaw's own files in
// it (the hooks, the launcher, the harness's managed settings) are the ones
// it delivered, root-owned and out of the workload's reach. On the MicroVM
// driver none of that is the container runtime's doing: the identity is the
// gateway's configuration ([openshell.drivers.vm] sandbox_uid and
// sandbox_gid) and the image is unpacked into a disk of the driver's own;
// on docker it is the container runtime's and the policy's
// process.run_as_user. So one exec checks it after every create and start,
// on every driver, and a sandbox that is not as prepared is deleted
// (create) or stopped (start). The check
// reads CapEff in its own exec: that holds for the harness too while the
// harness also starts through the supervisor's exec path.
//
// It compares with record.Verify, written once at create from what the
// create delivered, never with a fresh render: an upgrade that changes a
// hook would otherwise refuse every sandbox created before it.

// Workload check bounds: the exec's timeout (it is retried like any
// idempotent probe) and the output it may print.
const (
	verifyTimeout   = 30 * time.Second
	verifyMaxOutput = 64 << 10
)

// verifyScript prints what the check compares, one tagged line each, and
// "end" last, so an answer cut short is refused. It runs in an empty
// environment (env -i) with every tool by absolute path, under Landlock's
// read-only /usr and /bin: at a start the sandbox keeps what the last
// session wrote, and an id or sha256sum planted earlier on the image PATH
// (under /sandbox) would otherwise answer for itself. The shell reads the
// hostname, the capabilities, the processors and the memory (in kB) itself.
// The arguments are the files to check; a "mount" line names each that is a
// mount point, with its options. Only the vm check name adds the guest root
// boundary and localhost resolver results; the docker check retains its
// original work and output.
const verifyScript = `workload_uid=$(/usr/bin/id -u)
printf 'uid %s\n' "$workload_uid"
printf 'gid %s\n' "$(/usr/bin/id -g)"
host=
read -r host < /proc/sys/kernel/hostname
printf 'hostname %s\n' "$host"
if [ -w "$HOME" ]; then echo 'home writable'; else echo 'home read-only'; fi
while read -r key value; do
  [ "$key" = CapEff: ] && printf 'capeff %s\n' "$value"
done < /proc/self/status
cpus=0
while read -r key rest; do
  [ "$key" = processor ] && cpus=$((cpus + 1))
done < /proc/cpuinfo
printf 'cpus %s\n' "$cpus"
while read -r key value rest; do
  [ "$key" = MemTotal: ] && printf 'memtotal %s\n' "$value"
done < /proc/meminfo
if [ "$0" = defenseclaw-verify-vm ]; then
  root_entries_fixed() {
    probe=/.defenseclaw-verify-$$
    control=$HOME/.defenseclaw-verify-$$
    moved=$control.moved
    [ ! -e "$probe" ] && [ ! -L "$probe" ] &&
      [ ! -e "$control" ] && [ ! -L "$control" ] &&
      [ ! -e "$moved" ] && [ ! -L "$moved" ] || return 1
    # A move from another mount may copy instead of testing rename.
    root_mount=$(/usr/bin/stat -c %m /) || return 1
    home_mount=$(/usr/bin/stat -L -c %m "$HOME") || return 1
    [ "$root_mount" = "$home_mount" ] || return 1
    changed_mode=false
    if [ $((0$root_mode & 0200)) -eq 0 ]; then
      /usr/bin/chmod u+w / 2>/dev/null || return 1
      changed_mode=true
    fi
    (
      trap '/usr/bin/rm -f -- "$control" "$moved" 2>/dev/null' EXIT
      # A denial only proves the root boundary when these same operations
      # work in the workload's writable home.
      /usr/bin/mkdir -- "$control" 2>/dev/null || exit 1
      /usr/bin/rmdir -- "$control" 2>/dev/null || exit 1
      : > "$control" || exit 1
      /usr/bin/mv -- "$control" "$moved" 2>/dev/null || exit 1
      /usr/bin/mv -- "$moved" "$control" 2>/dev/null || exit 1
      /usr/bin/ln -s -- /usr "$moved" 2>/dev/null || exit 1
      /usr/bin/rm -f -- "$moved" 2>/dev/null || exit 1
      ( set -C; : > "$moved" ) 2>/dev/null || exit 1
      /usr/bin/rm -f -- "$moved" 2>/dev/null || exit 1
      if /usr/bin/mkdir -- "$probe" 2>/dev/null; then
        /usr/bin/rmdir -- "$probe" 2>/dev/null
        exit 1
      fi
      if ( : > "$probe" ) 2>/dev/null; then
        /usr/bin/rm -f -- "$probe" 2>/dev/null
        exit 1
      fi
      if ( set -C; : > "$probe" ) 2>/dev/null; then
        /usr/bin/rm -f -- "$probe" 2>/dev/null
        exit 1
      fi
      if /usr/bin/ln -s -- /usr "$probe" 2>/dev/null; then
        /usr/bin/rm -f -- "$probe" 2>/dev/null
        exit 1
      fi
      [ -f "$control" ] && [ ! -L "$control" ] || exit 1
      if /usr/bin/mv -- "$control" "$probe" 2>/dev/null; then
        /usr/bin/rm -f -- "$probe" 2>/dev/null
        exit 1
      fi
      [ -f "$control" ] && [ ! -L "$control" ] || exit 1
      /usr/bin/rm -f -- "$control" 2>/dev/null || exit 1
      [ ! -e "$probe" ] && [ ! -L "$probe" ] &&
        [ ! -e "$control" ] && [ ! -L "$control" ] &&
        [ ! -e "$moved" ] && [ ! -L "$moved" ]
    )
    fixed=$?
    if [ "$changed_mode" = true ]; then
      /usr/bin/chmod "$root_mode" / 2>/dev/null || return 1
    fi
    return "$fixed"
  }
  rootdir=writable
  if [ ! -L / ] && [ -d / ]; then
    root_owner=$(/usr/bin/stat -c %u /) || root_owner=
    root_mode=$(/usr/bin/stat -c %a /) || root_mode=777
    if [ $((0$root_mode & 022)) -eq 0 ]; then
      if [ "$root_owner" = 0 ] && [ "$workload_uid" != 0 ]; then
        rootdir=root
      elif [ "$root_owner" = "$workload_uid" ]; then
        if root_entries_fixed; then rootdir=fixed; fi
      else
        rootdir="owner $root_owner"
      fi
    fi
  fi
  printf 'rootdir %s\n' "$rootdir"
  trusted_resolver() {
    for d in /usr /usr/local /usr/local/lib /usr/local/lib/defenseclaw; do
      [ ! -L "$d" ] && [ -d "$d" ] && [ "$(/usr/bin/stat -c %u "$d")" = 0 ] || return 1
      mode=$(/usr/bin/stat -c %a "$d") || return 1
      [ $((0$mode & 022)) -eq 0 ] || return 1
    done
    f=/usr/local/lib/defenseclaw/localhost-resolver
    [ -f "$f" ] && [ ! -L "$f" ] && [ "$(/usr/bin/stat -c %u "$f")" = 0 ] || return 1
    mode=$(/usr/bin/stat -c %a "$f") || return 1
    [ $((0$mode & 022)) -eq 0 ]
  }
  if { [ "$rootdir" = root ] || [ "$rootdir" = fixed ]; } && trusted_resolver && localhost=$(/usr/local/lib/defenseclaw/localhost-resolver 2>/dev/null); then
    printf '%s\n' "$localhost" | while IFS= read -r answer; do printf 'localhost %s\n' "$answer"; done
    echo localhost-ok
  else
    echo localhost-failed
  fi
fi
if [ "$#" -gt 0 ]; then
  /usr/bin/sha256sum -- "$@" | while read -r sum file; do printf 'sha256 %s %s\n' "$sum" "$file"; done
  /usr/bin/stat -c 'stat %u %g %a %n' -- "$@"
  while read -r mount_id parent_id devno root mnt opts rest; do
    for p in "$@"; do [ "$mnt" = "$p" ] && printf 'mount %s %s\n' "$opts" "$mnt"; done
  done < /proc/self/mountinfo
fi
echo end`

// localhostResolverPath is the pinned caller every DefenseClaw MicroVM image
// carries (image.microVMResolverPath).
const localhostResolverPath = "/usr/local/lib/defenseclaw/localhost-resolver"

// verifyArgv is the workload check's command for the files of want;
// resolver adds the MicroVM localhost result.
func verifyArgv(want verifyRecord, resolver bool) []string {
	checkName := "defenseclaw-verify"
	if resolver {
		checkName += "-vm"
	}
	argv := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + connector.SandboxHomeDir,
		"/bin/sh", "-c", verifyScript, checkName}
	for _, f := range want.Files {
		argv = append(argv, f.Path)
	}
	return argv
}

// verifyExpectation is what the workload check expects of a sandbox created
// from img: the identity the image was built for, and each root-owned file
// DefenseClaw placed in the image for the harness, from the artifacts the
// create rendered for it (the image's own render). Files the workload owns
// (its settings under HOME) are its to change, and are not checked.
func verifyExpectation(img image.Record, spec *harness.Spec, arts connector.SandboxArtifacts) *verifyRecord {
	v := &verifyRecord{UID: img.UID, GID: img.GID}
	files := slices.Concat(arts.Files, []connector.SandboxFile{spec.Launcher()}, spec.ShellFiles())
	for _, f := range files {
		if f.Owner != connector.SandboxOwnerRoot {
			continue
		}
		sum := sha256.Sum256(f.Data)
		v.Files = append(v.Files, verifyFile{Path: f.Path, SHA256: hex.EncodeToString(sum[:]), Mode: uint32(f.Mode.Perm())})
	}
	slices.SortFunc(v.Files, func(a, b verifyFile) int { return strings.Compare(a.Path, b.Path) })
	v.Files = slices.CompactFunc(v.Files, func(a, b verifyFile) bool { return a.Path == b.Path })
	return v
}

// workloadFacts is what the workload check found.
type workloadFacts struct {
	UID, GID     int
	Hostname     string
	HomeWritable bool
	CapEff       string
	// CPUs are the processors the workload sees, and MemTotalKB the
	// memory (/proc/meminfo MemTotal, in kB; a little under what the
	// MicroVM was given, the kernel keeps some).
	CPUs              int
	MemTotalKB        int64
	Files             map[string]*fileFacts
	LocalhostAnswers  []string
	LocalhostOK       bool
	LocalhostReported bool
	RootDir           string
	RootDirOwner      int
	// DirectResolverOK is set only by a separate exec of the pinned caller,
	// and DirectResolverRefusal to the reason that caller refused with.
	DirectResolverOK      bool
	DirectResolverRefusal string
	// ResolverExempt marks a MicroVM whose record is from before the guest
	// resolver check (verifyRecord.LocalhostResolver): its create passed
	// the hook-fire MicroVM verdict of DefenseClaw 1.0.7 and earlier.
	ResolverExempt bool
	// seen holds the tags of the single-valued lines read.
	seen map[string]bool
	// End is set when the answer was complete.
	End bool
}

// fileFacts is what the check found of one file.
type fileFacts struct {
	SHA256     string
	Stat       bool
	UID, GID   int
	Mode       uint32
	MountPoint bool
	// MountOptions are the options of the mount the file is the mount
	// point of (the last one, which is the one in effect).
	MountOptions string
}

// parseWorkloadFacts reads verifyScript's answer. A line it does not know,
// or a single-valued one twice, fails: the answer is not the script's.
func parseWorkloadFacts(out []byte) (workloadFacts, error) {
	facts := workloadFacts{Files: map[string]*fileFacts{}, seen: map[string]bool{}}
	file := func(path string) *fileFacts {
		f := facts.Files[path]
		if f == nil {
			f = &fileFacts{}
			facts.Files[path] = f
		}
		return f
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		if facts.End {
			return facts, fmt.Errorf("the answer goes on after its end: %q", truncate(line, 120))
		}
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case "uid", "gid", "hostname", "home", "capeff", "cpus", "memtotal", "rootdir":
			if facts.seen[tag] {
				return facts, fmt.Errorf("the answer has %s twice", tag)
			}
			facts.seen[tag] = true
		}
		var err error
		switch tag {
		case "uid":
			facts.UID, err = strconv.Atoi(rest)
		case "gid":
			facts.GID, err = strconv.Atoi(rest)
		case "hostname":
			facts.Hostname = rest
		case "home":
			facts.HomeWritable = rest == "writable"
		case "capeff":
			facts.CapEff = rest
		case "cpus":
			facts.CPUs, err = strconv.Atoi(rest)
		case "memtotal":
			facts.MemTotalKB, err = strconv.ParseInt(rest, 10, 64)
		case "rootdir":
			switch rest {
			case "root", "fixed", "writable":
				facts.RootDir = rest
			default:
				owner, ok := strings.CutPrefix(rest, "owner ")
				if !ok || owner == "" {
					err = fmt.Errorf("a malformed root directory result")
					break
				}
				facts.RootDirOwner, err = strconv.Atoi(owner)
				if err == nil && facts.RootDirOwner >= 0 {
					facts.RootDir = "owner"
				} else if err == nil {
					err = fmt.Errorf("a malformed root directory owner")
				}
			}
		case "sha256":
			sum, path, ok := strings.Cut(rest, " ")
			if !ok || path == "" {
				err = fmt.Errorf("a digest without a file")
				break
			}
			file(path).SHA256 = sum
		case "stat":
			parts := strings.SplitN(rest, " ", 4)
			if len(parts) != 4 || parts[3] == "" {
				err = fmt.Errorf("a malformed stat line")
				break
			}
			f := file(parts[3])
			var mode uint64
			f.UID, err = strconv.Atoi(parts[0])
			if err == nil {
				f.GID, err = strconv.Atoi(parts[1])
			}
			if err == nil {
				mode, err = strconv.ParseUint(parts[2], 8, 32)
			}
			f.Mode, f.Stat = uint32(mode), err == nil
		case "mount":
			opts, path, ok := strings.Cut(rest, " ")
			if !ok || path == "" {
				err = fmt.Errorf("a malformed mount line")
				break
			}
			f := file(path)
			f.MountPoint, f.MountOptions = true, opts
		case "localhost":
			if facts.LocalhostReported || len(rest) > 512 || strings.ContainsAny(rest, "\x00\r") || len(facts.LocalhostAnswers) >= 64 {
				err = fmt.Errorf("a malformed localhost answer")
				break
			}
			facts.LocalhostAnswers = append(facts.LocalhostAnswers, rest)
		case "localhost-ok", "localhost-failed":
			if rest != "" || facts.LocalhostReported {
				err = fmt.Errorf("a malformed localhost result")
				break
			}
			facts.LocalhostReported = true
			facts.LocalhostOK = tag == "localhost-ok"
		case "end":
			facts.End = true
		default:
			err = fmt.Errorf("an unknown line")
		}
		if err != nil {
			return facts, fmt.Errorf("%s: %q", err.Error(), truncate(line, 120))
		}
	}
	return facts, nil
}

// workloadLimits is an organization's openshell.admin.max_resources as the
// workload check judges it: the settings as written, and parsed (0 is no
// maximum; the resolver refuses a malformed one on its own).
type workloadLimits struct {
	cpu, memory            string
	cpuMillis, memoryBytes int64
}

func adminLimits(max config.OpenShellResourcesConfig) workloadLimits {
	l := workloadLimits{cpu: strings.TrimSpace(max.CPU), memory: strings.TrimSpace(max.Memory)}
	if n, err := config.ParseOpenShellCPU(l.cpu); l.cpu != "" && err == nil {
		l.cpuMillis = n
	}
	if n, err := config.ParseOpenShellMemory(l.memory); l.memory != "" && err == nil {
		l.memoryBytes = n
	}
	return l
}

// sharedLimitProblems judges what a workload of a driver without
// per-sandbox limits (vm) sees against the organization's maximum. The
// create and the start judged the gateway-wide vcpus and mem_mib the
// daemon reads from the gateway's configuration, but the running gateway
// can take others (launchd's environment, a file changed since its last
// restart): what the MicroVM got is checked too.
func sharedLimitProblems(got workloadFacts, d openshell.Driver, limits workloadLimits) []string {
	var out []string
	fix := "; lower vcpus and mem_mib under [openshell.drivers." + string(d.Name) + "] in the gateway's gateway.toml and restart it " +
		"(`defenseclaw sandbox doctor --fix`)"
	if limits.cpuMillis > 0 {
		switch {
		case !got.seen["cpus"] || got.CPUs <= 0:
			out = append(out, "the check could not count the workload's processors, which your organization caps at "+limits.cpu)
		case int64(got.CPUs)*1000 > limits.cpuMillis:
			out = append(out, fmt.Sprintf("the workload has %d processors, and your organization caps sandbox cpu at %s%s", got.CPUs, limits.cpu, fix))
		}
	}
	if limits.memoryBytes > 0 {
		switch {
		case !got.seen["memtotal"] || got.MemTotalKB <= 0:
			out = append(out, "the check could not read the workload's memory, which your organization caps at "+limits.memory)
		case got.MemTotalKB*1024 > limits.memoryBytes:
			out = append(out, fmt.Sprintf("the workload has %d MiB of memory, and your organization caps sandbox memory at %s%s", got.MemTotalKB>>10, limits.memory, fix))
		}
	}
	return out
}

// cutShortProblem is what the workload check says when its answer ends
// before "end".
const cutShortProblem = "the check's answer was cut short"

// shellStartEnv are the variables a shell reads on start-up and obeys
// before it runs a script: SHELLOPTS=noexec makes the workload check's
// shell read its script and run none of it, so the answer is empty. A
// sandbox created with one of them in --env can be refused for that alone.
// BASH_ENV and ENV are not here: the create refuses them by name already
// (reservedEnv).
var shellStartEnv = []string{"BASHOPTS", "SHELLOPTS"}

// cutShortWithEnv is the refusal of a check whose answer was cut short in a
// sandbox created with the environment env: when env sets a shell start-up
// variable it names the setting and says what to do, in one sentence.
// Without one it is the plain cutShortProblem.
func cutShortWithEnv(env map[string]string) string {
	var names []string
	for _, n := range shellStartEnv {
		if _, ok := env[n]; ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return cutShortProblem
	}
	return cutShortProblem + ", most likely by the shell setting " + strings.Join(names, ", ") + " passed with --env; run the sandbox again without it"
}

// workloadProblems lists how the sandbox differs from want, as the user
// reads it; none means it runs as DefenseClaw prepared it. d is the
// sandbox's compute driver, which says where a wrong identity comes from,
// and whether the cpu and memory the workload sees are judged against the
// organization's limits (a driver without per-sandbox limits).
func workloadProblems(want verifyRecord, got workloadFacts, d openshell.Driver, limits workloadLimits) []string {
	var out []string
	if !got.End {
		return []string{cutShortProblem}
	}
	for _, tag := range []string{"uid", "gid", "hostname", "home", "capeff"} {
		if !got.seen[tag] {
			out = append(out, "the check did not report the workload's "+tag)
		}
	}
	if len(out) > 0 {
		return out
	}
	if got.UID != want.UID || got.GID != want.GID {
		msg := fmt.Sprintf("the workload runs as uid %d:%d, not %d:%d, the identity its image was built for and its policy's process.run_as_user names",
			got.UID, got.GID, want.UID, want.GID)
		if d.GatewayIdentity {
			msg = fmt.Sprintf("the OpenShell %[1]s driver runs sandboxes as uid %[2]d:%[3]d, but DefenseClaw's images are built for %[4]d:%[5]d; "+
				"set sandbox_uid = %[4]d and sandbox_gid = %[5]d under [openshell.drivers.%[1]s] in the gateway's gateway.toml "+
				"(`defenseclaw sandbox doctor --fix`)", d.Name, got.UID, got.GID, want.UID, want.GID)
		}
		out = append(out, msg)
	}
	if !got.HomeWritable {
		out = append(out, "the workload cannot write its home "+connector.SandboxHomeDir)
	}
	if caps, err := strconv.ParseUint(got.CapEff, 16, 64); err != nil || caps != 0 {
		out = append(out, "the workload holds capabilities (CapEff "+truncate(got.CapEff, 32)+"); DefenseClaw runs it with none")
	}
	if !d.SandboxLimits {
		out = append(out, sharedLimitProblems(got, d, limits)...)
	}
	if d.Name == openshell.DriverVM && !got.ResolverExempt {
		switch got.RootDir {
		case "root", "fixed":
		case "writable":
			out = append(out, "the MicroVM workload can add or rename entries of its root folder, so DefenseClaw cannot trust what it resolves localhost to")
		case "owner":
			out = append(out, fmt.Sprintf("the MicroVM root folder is owned by uid %d, not root or the workload uid %d", got.RootDirOwner, got.UID))
		default:
			out = append(out, "the MicroVM check did not report the root folder's protection")
		}
		if got.RootDir == "root" || got.RootDir == "fixed" {
			if problem := microVMResolverProblem(got); problem != "" {
				out = append(out, problem)
			}
		}
		if !got.DirectResolverOK {
			out = append(out, directResolverProblem(got.DirectResolverRefusal))
		}
	}
	for _, w := range want.Files {
		f := got.Files[w.Path]
		switch {
		case f == nil || f.SHA256 == "":
			out = append(out, w.Path+" is missing")
			continue
		case !strings.EqualFold(f.SHA256, w.SHA256):
			out = append(out, w.Path+" is not the file DefenseClaw delivered")
		}
		switch {
		case !f.Stat:
			out = append(out, w.Path+" could not be inspected")
		case f.UID != w.UID || f.GID != w.GID:
			out = append(out, fmt.Sprintf("%s is owned by %d:%d, not %d:%d", w.Path, f.UID, f.GID, w.UID, w.GID))
		case f.Mode&0o022 != 0:
			out = append(out, fmt.Sprintf("%s is writable by its group or others (mode %o)", w.Path, f.Mode))
		case f.Mode != w.Mode:
			out = append(out, fmt.Sprintf("%s has mode %o, not %o", w.Path, f.Mode, w.Mode))
		}
		// A file bind-mounted from the host is the host user's, which is
		// the workload's uid: the read-only mount is what keeps it.
		if w.ReadOnlyMount && (!f.MountPoint || !slices.Contains(strings.Split(f.MountOptions, ","), "ro")) {
			out = append(out, w.Path+" is not on a read-only mount")
		}
	}
	return out
}

// microVMResolverProblem judges what the pinned caller printed when the
// image's shell ran it. The shell is the image's, so this result alone
// admits nothing; the direct exec (directResolverOK) must pass too.
func microVMResolverProblem(got workloadFacts) string {
	if !got.LocalhostReported || !got.LocalhostOK || len(got.LocalhostAnswers) == 0 {
		return "the MicroVM could not resolve localhost to its loopback ingress"
	}
	if !resolverAnswerOK(got.LocalhostAnswers) {
		return "the MicroVM resolver did not return only its loopback ingress for localhost"
	}
	return ""
}

// resolverAnswerOK judges the lines of the pinned caller
// (image/testdata/localhost-resolver.c): one line per distinct answer of
// the unspec, inet and inet6 queries in that order, each 127.0.0.1 or ::1,
// at least one unspec answer, and "loopback-only" last.
func resolverAnswerOK(lines []string) bool {
	if len(lines) < 2 || lines[len(lines)-1] != "loopback-only" {
		return false
	}
	rank := map[string]int{"unspec 127.0.0.1": 0, "unspec ::1": 0, "inet 127.0.0.1": 1, "inet6 ::1": 2}
	seen := map[string]bool{}
	last, unspec := 0, false
	for _, line := range lines[:len(lines)-1] {
		r, ok := rank[line]
		if !ok || seen[line] || r < last {
			return false
		}
		seen[line], last = true, r
		unspec = unspec || r == 0
	}
	return unspec
}

// directResolverOK judges the output of the pinned caller invoked directly
// as the sandbox workload (resolverAnswerOK, newline-terminated).
func directResolverOK(out []byte) bool {
	if len(out) == 0 || len(out) > 4096 || out[len(out)-1] != '\n' {
		return false
	}
	return resolverAnswerOK(strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"))
}

// directResolverRefusal is the reason the pinned caller refused with
// ("refused <reason>" last), or "".
func directResolverRefusal(out []byte) string {
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	reason, ok := strings.CutPrefix(lines[len(lines)-1], "refused ")
	if !ok || len(out) > 4096 {
		return ""
	}
	switch reason {
	case "preload", "nss", "nonloopback", "noanswer", "family":
		return reason
	}
	return ""
}

// directResolverProblem says why the direct resolver check failed.
func directResolverProblem(refusal string) string {
	switch refusal {
	case "preload":
		return "the MicroVM image loads code into every program ahead of libc (/etc/ld.so.preload), so DefenseClaw cannot verify what its programs resolve localhost to"
	case "nss":
		return "the MicroVM image's /etc/nsswitch.conf lets an NSS module or DNS answer localhost besides /etc/hosts, so DefenseClaw cannot verify what its programs resolve localhost to; set `hosts: files dns` in the image"
	case "nonloopback", "family":
		return "the MicroVM resolver did not return only its loopback ingress for localhost"
	case "noanswer":
		return "the MicroVM could not resolve localhost to its loopback ingress"
	}
	return "the MicroVM could not verify localhost with its resolver caller"
}

// verifyWorkload runs the workload check in sandbox name and returns what
// it found. A sandbox that does not run as want expects, or that cannot be
// checked, is refused with CodePolicyRejected: the caller deletes or stops
// it, so one not as prepared never keeps running, and outcome (what the
// caller does with it, "it was deleted") ends the refusal's message. env is
// the extra environment the create passed (nil at a start); a check cut
// short names the shell setting in it that most likely did that.
func (m *Manager) verifyWorkload(ctx context.Context, gw *Gateway, name string, want verifyRecord, eff *packs.Effective, outcome string, env map[string]string) (workloadFacts, error) {
	// A MicroVM record from before the guest resolver check keeps the check
	// it was created under (verifyRecord.LocalhostResolver).
	resolverCheck := gw.Driver.Name == openshell.DriverVM && want.LocalhostResolver
	res, err := m.ownExec(ctx, gw, name, verifyArgv(want, resolverCheck), openshell.ExecOptions{
		Timeout: verifyTimeout, Idempotent: true, MaxOutputBytes: verifyMaxOutput,
	})
	if err != nil {
		m.dropGateway(gw, err)
		return workloadFacts{}, upstream("check the workload of sandbox "+name, err)
	}
	facts, perr := parseWorkloadFacts(res.Stdout)
	var problems []string
	switch {
	case res.Truncated:
		problems = []string{"the check's answer was too long"}
	case perr != nil:
		problems = []string{"the check's answer cannot be read (" + perr.Error() + ")"}
	case res.ExitCode != 0:
		problems = []string{fmt.Sprintf("the check exited with status %d", res.ExitCode)}
	default:
		facts.ResolverExempt = gw.Driver.Name == openshell.DriverVM && !resolverCheck
		if resolverCheck {
			// Execute the pinned caller directly. The image's env and shell can
			// alter their own output, so their localhost lines are insufficient.
			resolver, resolverErr := m.ownExec(ctx, gw, name,
				[]string{localhostResolverPath}, openshell.ExecOptions{
					Timeout: verifyTimeout, Attempts: 1, MaxOutputBytes: 4096, NoSandboxTimeout: true,
				})
			if resolverErr != nil {
				m.dropGateway(gw, resolverErr)
				return workloadFacts{}, upstream("check the resolver of sandbox "+name, resolverErr)
			}
			facts.DirectResolverOK = !resolver.Truncated && resolver.ExitCode == 0 && directResolverOK(resolver.Stdout)
			if !resolver.Truncated {
				facts.DirectResolverRefusal = directResolverRefusal(resolver.Stdout)
			}
		}
		problems = workloadProblems(want, facts, gw.Driver, adminLimits(eff.MaxResources()))
		if len(problems) == 1 && problems[0] == cutShortProblem {
			problems[0] = cutShortWithEnv(env)
		}
	}
	if len(problems) == 0 {
		return facts, nil
	}
	detail := strings.Join(problems, "; ")
	m.logf("%s: sandbox %s does not run as DefenseClaw prepared it: %s", gatewaylog.ErrCodeOpenShellPolicyRejected, name, detail)
	return facts, &sandboxapi.Error{Code: sandboxapi.CodePolicyRejected,
		Message: "sandbox " + name + " does not run as DefenseClaw prepared it; " + outcome, Detail: truncate(detail, 2048)}
}

// verifyStarted runs the workload check of a sandbox a start just made
// ready, against what its create recorded, and keeps the hostname it
// found. A sandbox that fails it is stopped again before the error
// returns, so one not as prepared never keeps running. Every create records
// what the check expects (create.go); a record without it cannot be
// checked, and is refused the same way.
func (m *Manager) verifyStarted(ctx context.Context, gw *Gateway, b *box, rec record) error {
	outcome := stoppedUnverifiedOutcome(gw.Driver.StopFlushes)
	if rec.Verify == nil {
		m.logf("%s: sandbox %s has no workload check in its record; stopping it again", gatewaylog.ErrCodeOpenShellPolicyRejected, rec.Name)
		refusal := &sandboxapi.Error{Code: sandboxapi.CodePolicyRejected,
			Message: "sandbox " + rec.Name + " does not run as DefenseClaw prepared it; " + outcome,
			Detail:  "its record does not say what its create delivered, so it cannot be checked: before deleting it, try `defenseclaw sandbox pull " + rec.Name + " --apply` (or --branch or --patch-out FILE) and confirm the work was saved; a fresh pull of this stopped copy may be refused because it must start again. If so, keep the sandbox while you assess recovery; delete it only after saving the work you need, then run it again"}
		if m.stopUnverified(ctx, gw, b) != nil {
			return stillRunning(rec.Name, refusal, outcome)
		}
		return refusal
	}
	m.mu.Lock()
	eff := b.eff
	m.mu.Unlock()
	facts, err := m.verifyWorkload(ctx, gw, rec.Name, *rec.Verify, eff, outcome, nil)
	if err != nil {
		if m.stopUnverified(ctx, gw, b) != nil {
			return stillRunning(rec.Name, err, outcome)
		}
		return err
	}
	m.mu.Lock()
	changed := facts.Hostname != "" && b.rec.Hostname != facts.Hostname
	if changed {
		b.rec.Hostname = facts.Hostname
	}
	m.mu.Unlock()
	if changed {
		if err := m.saveRecord(b); err != nil {
			m.logf("record the hostname of %s: %v", rec.Name, err)
		}
	}
	return nil
}

// stoppedUnverifiedOutcome keeps Docker's work claim while qualifying a
// MicroVM stop: a failed guest sync cannot preserve its later writes.
func stoppedUnverifiedOutcome(stopFlushes bool) string {
	if !stopFlushes {
		return "DefenseClaw stopped it again (only work through the last successful disk sync is kept)"
	}
	return "DefenseClaw stopped it again (its work is kept)"
}

// stopUnverified stops again a sandbox a start must not leave running (it
// failed the workload check, still has a rule of its last session, or did
// not get its network back on a new supervisor), flushing its disk first
// where the driver's stop does not (the last session's work stays for
// pull), and records the phase OpenShell reports then. A flush that fails
// holds the stop back (GAP-0902): the VM keeps running, contained
// (containUnsynced). It returns why the sandbox was not stopped: it then
// still runs, and the start's refusal must say so rather than that it was
// stopped (GAP-0014).
func (m *Manager) stopUnverified(ctx context.Context, gw *Gateway, b *box) error {
	ctx, cancel := detached(ctx, rollbackTimeout)
	defer cancel()
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	if !gw.Driver.StopFlushes {
		if flushErr := m.flushSandbox(ctx, gw, name); flushErr != nil {
			m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
			err := containedStopRefusal(name, flushErr, m.containUnsynced(ctx, b, "its start failed"))
			m.logf("%s: sandbox %s must not keep running after its start: %v", gatewaylog.ErrCodeOpenShellSandboxFailed, name, err)
			return err
		}
	}
	_, err := gw.Client.StopSandbox(ctx, name)
	if err == nil {
		_, err = gw.Client.WaitStopped(ctx, name)
	}
	if err != nil {
		m.logf("%s: sandbox %s must not keep running after its start, and stopping it again failed: %v",
			gatewaylog.ErrCodeOpenShellSandboxFailed, name, err)
	}
	m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
	return err
}

// stillRunning is the refusal err of a start whose sandbox DefenseClaw
// could not stop again (stopUnverified failed): the sandbox still runs, so
// the refusal drops stopped, the outcome it ends with when the stop works,
// and says how to stop it. The stop's own error is in the log.
func stillRunning(name string, err error, stopped string) error {
	out := sandboxapi.Error{Code: sandboxapi.CodeInternal, Message: err.Error()}
	var apiErr *sandboxapi.Error
	if errors.As(err, &apiErr) {
		out = *apiErr
	}
	out.Message = strings.TrimSuffix(strings.TrimSuffix(out.Message, stopped), "; ") +
		"; DefenseClaw could not stop the sandbox again, so it is still running: stop it with `defenseclaw sandbox stop " + name + "`"
	return &out
}
