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
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The workload check after ready. A sandbox runs as DefenseClaw prepared it
// when its workload runs as the identity its image was built for, holds no
// capabilities and can write its home, and when DefenseClaw's own files in
// it (the hooks, the launcher, the harness's managed settings) are the ones
// it delivered, root-owned and out of the workload's reach. On the MicroVM
// driver none of that is the container runtime's doing: the identity is the
// gateway's configuration ([openshell.drivers.vm] sandbox_uid and
// sandbox_gid) and the image is unpacked into a disk of the driver's own.
// So one exec checks it after every create and start (on every driver that
// does not skip it, openshell.Driver.SkipWorkloadCheck), and a sandbox that
// is not as prepared is deleted (create) or stopped (start). The check
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
// hostname and the capabilities itself. The arguments are the files to
// check; a "mount" line names each that is a mount point, with its options.
const verifyScript = `printf 'uid %s\n' "$(/usr/bin/id -u)"
printf 'gid %s\n' "$(/usr/bin/id -g)"
host=
read -r host < /proc/sys/kernel/hostname
printf 'hostname %s\n' "$host"
if [ -w "$HOME" ]; then echo 'home writable'; else echo 'home read-only'; fi
while read -r key value; do
  [ "$key" = CapEff: ] && printf 'capeff %s\n' "$value"
done < /proc/self/status
if [ "$#" -gt 0 ]; then
  /usr/bin/sha256sum -- "$@" | while read -r sum file; do printf 'sha256 %s %s\n' "$sum" "$file"; done
  /usr/bin/stat -c 'stat %u %g %a %n' -- "$@"
  while read -r mount_id parent_id devno root mnt opts rest; do
    for p in "$@"; do [ "$mnt" = "$p" ] && printf 'mount %s %s\n' "$opts" "$mnt"; done
  done < /proc/self/mountinfo
fi
echo end`

// verifyArgv is the workload check's command for the files of want.
func verifyArgv(want verifyRecord) []string {
	argv := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + connector.SandboxHomeDir,
		"/bin/sh", "-c", verifyScript, "defenseclaw-verify"}
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
	Files        map[string]*fileFacts
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
		case "uid", "gid", "hostname", "home", "capeff":
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

// workloadProblems lists how the sandbox differs from want, as the user
// reads it; none means it runs as DefenseClaw prepared it. d is the
// sandbox's compute driver, which says where a wrong identity comes from.
func workloadProblems(want verifyRecord, got workloadFacts, d openshell.Driver) []string {
	var out []string
	if !got.End {
		return []string{"the check's answer was cut short"}
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
		msg := fmt.Sprintf("the workload runs as uid %d:%d, not %d:%d, the identity its image was built for", got.UID, got.GID, want.UID, want.GID)
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

// verifyWorkload runs the workload check in sandbox name and returns what
// it found. A sandbox that does not run as want expects, or that cannot be
// checked, is refused with CodePolicyRejected: the caller deletes or stops
// it, so one not as prepared never keeps running.
func (m *Manager) verifyWorkload(ctx context.Context, gw *Gateway, name string, want verifyRecord) (workloadFacts, error) {
	res, err := gw.Client.Exec(ctx, name, verifyArgv(want), openshell.ExecOptions{
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
		problems = workloadProblems(want, facts, gw.Driver)
	}
	if len(problems) == 0 {
		return facts, nil
	}
	detail := strings.Join(problems, "; ")
	m.logf("%s: sandbox %s does not run as DefenseClaw prepared it: %s", gatewaylog.ErrCodeOpenShellPolicyRejected, name, detail)
	return facts, &sandboxapi.Error{Code: sandboxapi.CodePolicyRejected,
		Message: "sandbox " + name + " does not run as DefenseClaw prepared it", Detail: truncate(detail, 2048)}
}

// verifyStarted runs the workload check of a sandbox a start just made
// ready, against what its create recorded, and keeps the hostname it
// found. A sandbox that fails it is stopped again before the error
// returns, so one not as prepared never keeps running. Of a record from
// before the check only the identity is checked: what its create delivered
// is not known.
func (m *Manager) verifyStarted(ctx context.Context, gw *Gateway, b *box, rec record) error {
	var want verifyRecord
	if rec.Verify != nil {
		want = *rec.Verify
	} else {
		want.UID, want.GID = m.runAs()
	}
	facts, err := m.verifyWorkload(ctx, gw, rec.Name, want)
	if err != nil {
		m.stopUnverified(ctx, gw, b)
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

// stopUnverified stops a sandbox that failed the workload check after a
// start, flushing its disk first where the driver's stop does not (the
// last session's work stays for pull), and records the phase OpenShell
// reports then.
func (m *Manager) stopUnverified(ctx context.Context, gw *Gateway, b *box) {
	ctx, cancel := detached(ctx, rollbackTimeout)
	defer cancel()
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	if !gw.Driver.StopFlushes {
		m.flushSandbox(ctx, gw, name)
	}
	_, err := gw.Client.StopSandbox(ctx, name)
	if err == nil {
		_, err = gw.Client.WaitStopped(ctx, name)
	}
	if err != nil {
		m.logf("%s: sandbox %s failed its check after the start, and stopping it failed too: %v",
			gatewaylog.ErrCodeOpenShellSandboxFailed, name, err)
	}
	m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
}
