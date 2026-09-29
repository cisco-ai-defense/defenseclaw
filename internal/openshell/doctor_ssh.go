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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// SSHSandboxHost is the host name the OpenShell 0.1.1 CLI gives ssh for
// every sandbox (the ProxyCommand names the sandbox), so ssh_config
// settings for it, or for `Host *`, apply to every sandbox alike.
const SSHSandboxHost = "sandbox"

// sshSharing is what `ssh -G` reports of connection sharing.
type sshSharing struct {
	master, path string
}

// shares reports whether ssh would use, or leave, a control socket: a
// ControlPath alone makes ssh ride a master someone else opened.
func (s sshSharing) shares() bool { return s.path != "" && s.path != "none" }

// off reports whether ssh would neither open a master connection nor use
// a control socket: ControlMaster no ("false" in `ssh -G`), ControlPath
// none.
func (s sshSharing) off() bool { return (s.master == "false" || s.master == "no") && !s.shares() }

// parseSSHSharing reads `ssh -G` output (lower-case "key value" lines; no
// controlpath line means none).
func parseSSHSharing(out []byte) (sshSharing, bool) {
	var s sshSharing
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "controlmaster":
			s.master, found = strings.TrimSpace(value), true
		case "controlpath":
			s.path = strings.TrimSpace(value)
		}
	}
	return s, found
}

// sshConfigFor runs `<ssh> -G sandbox`, which prints the effective
// configuration without connecting.
func (r *doctorRun) sshConfigFor(ctx context.Context, ssh string) (sshSharing, error) {
	out, err := r.Runner.Output(ctx, Command{Name: ssh, Args: []string{"-G", SSHSandboxHost}, Timeout: 15 * time.Second})
	if err != nil {
		if line := lastLine(out); line != "" {
			err = fmt.Errorf("%w: %s", err, line)
		}
		return sshSharing{}, fmt.Errorf("ssh -G %s: %w", SSHSandboxHost, err)
	}
	s, ok := parseSSHSharing(out)
	if !ok {
		return sshSharing{}, fmt.Errorf("%s -G %s printed no controlmaster setting", ssh, SSHSandboxHost)
	}
	return s, nil
}

// checkSSHSharing checks that the ssh DefenseClaw runs the OpenShell CLI
// with shares no connections between sandboxes, and names the user's own
// ssh configuration when it would share them for `openshell` commands run
// outside DefenseClaw.
func (r *doctorRun) checkSSHSharing(ctx context.Context) {
	c := Check{ID: CheckIDSSHSharing, Title: "SSH connection sharing"}
	defer func() { r.add(c) }()
	shim, err := r.SSHShim()
	var sharing *SSHSharingError
	switch {
	case errors.As(err, &sharing):
		c.Status = StatusFail
		c.Detail = "DefenseClaw refuses to start sandbox sessions: " + sharing.Cause()
		c.Fix = &Fix{Summary: sharing.Fix()}
		return
	case err != nil:
		c.Status = StatusFail
		c.Detail = "DefenseClaw cannot give the OpenShell CLI an ssh with connection sharing off, so it refuses to start sandbox sessions: " + err.Error()
		c.Fix = &Fix{Summary: "set TMPDIR to a directory only you can write, on a filesystem not mounted noexec: DefenseClaw makes a private folder there for each OpenShell command"}
		return
	case shim == nil:
		c.Status = StatusWarn
		c.Detail = "no ssh on PATH: the OpenShell CLI needs one for sandbox connect, file transfers and port forwards"
		c.Fix = &Fix{Summary: "install the OpenSSH client"}
		return
	}
	defer func() { _ = shim.Remove() }()
	ours, err := r.sshConfigFor(ctx, shim.Path)
	switch {
	case err != nil:
		c.Status = StatusWarn
		c.Detail = "could not confirm that the ssh DefenseClaw runs the OpenShell CLI with shares no connections: " + err.Error()
		return
	case !ours.off():
		sharing := newSSHSharingError(shim.Real, sshPathWithoutShims(shim.pathEnv), ours, nil)
		c.Status = StatusFail
		c.Detail = sharing.Cause()
		c.Fix = &Fix{Summary: sharing.Fix()}
		return
	}
	c.Status = StatusPass
	c.Detail = "off for the OpenShell sessions DefenseClaw runs (ssh " + strings.Join(SSHNoSharingOptions(), " ") + ")"
	if shim.Fallback != "" {
		c.Detail += "; its ssh is under " + filepath.Dir(shim.Dir) + ", not the temporary directory: " + shim.Fallback
	}
	theirs, err := r.sshConfigFor(ctx, shim.Real)
	switch {
	case err != nil:
		c.Detail += "; could not read your own ssh configuration: " + err.Error()
	case theirs.shares():
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("your ssh configuration shares connections for host %q, the name OpenShell gives every sandbox (ControlMaster %s, ControlPath %s). "+
			"DefenseClaw turns that off for the OpenShell sessions it runs. An `openshell sandbox connect`, `upload`, `download` or `forward` that you run yourself "+
			"can still reach another sandbox than the one you name, through the connection an earlier one left open", SSHSandboxHost, theirs.master, theirs.path)
		c.Fix = &Fix{Summary: "turn it off for OpenShell's host in ~/.ssh/config, above any `Host *`: `Host " + SSHSandboxHost + "` with `ControlMaster no` and `ControlPath none`"}
	default:
		c.Detail += "; your ssh configuration shares none for host " + SSHSandboxHost + " either"
	}
}
