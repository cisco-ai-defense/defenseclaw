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

package openshelltest

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// SSHRecorder is a recording ssh first on PATH and a stand-in openshell
// CLI that runs `ssh` from PATH with its own arguments, as the real CLI
// does for sandbox connect, transfers and forwards. The recording ssh
// answers -G as OpenSSH would (SSHDashG) and records every other run.
type SSHRecorder struct {
	// SSH is the recording ssh: the real one a shim must run.
	SSH string
	// OpenShell is the stand-in CLI, for openshell.CLI.Binary.
	OpenShell string
	log       string
}

// SSHCall is one ssh the stand-in CLI ran.
type SSHCall struct {
	// Via is the ssh PATH resolved for the CLI.
	Via string
	// PathHead is the first entry of the CLI's PATH.
	PathHead string
	// Args are what the recording ssh received.
	Args []string
}

// SSHDashG starts a stand-in ssh script (after its #! line): given -G, it
// prints the controlmaster and controlpath lines OpenSSH would for its
// command line, and exits. As in OpenSSH, the first -o value of an option
// wins, and -S and -M win wherever they are; unset, ControlMaster is no
// and ControlPath none (no line). DefenseClaw's ssh shim is refused unless
// `ssh -G sandbox` through it shows connection sharing off.
const SSHDashG = `for _dc_a in "$@"; do [ "$_dc_a" = -G ] && _dc_g=1; done
if [ -n "${_dc_g-}" ]; then
  _dc_cm= _dc_cp= _dc_s= _dc_m=
  while [ $# -gt 0 ]; do
    _dc_o=
    case $1 in
    -o) [ $# -gt 1 ] && { shift; _dc_o=$1; } ;;
    -o?*) _dc_o=${1#-o} ;;
    -S) [ $# -gt 1 ] && { shift; _dc_s=$1; } ;;
    -S?*) _dc_s=${1#-S} ;;
    -M) _dc_m=1 ;;
    esac
    case $_dc_o in
    [Cc]ontrol[Mm]aster=*) [ -n "$_dc_cm" ] || _dc_cm=${_dc_o#*=} ;;
    [Cc]ontrol[Pp]ath=*) [ -n "$_dc_cp" ] || _dc_cp=${_dc_o#*=} ;;
    esac
    shift
  done
  [ -z "$_dc_s" ] || _dc_cp=$_dc_s
  [ -z "$_dc_m" ] || _dc_cm=yes
  case ${_dc_cm:-no} in no) _dc_cm=false ;; yes) _dc_cm=true ;; esac
  printf 'hostname sandbox\ncontrolmaster %s\n' "$_dc_cm"
  case ${_dc_cp:-none} in none) ;; *) printf 'controlpath %s\n' "$_dc_cp" ;; esac
  exit 0
fi
`

// NewSSHRecorder puts the recording ssh first on PATH for the rest of t.
func NewSSHRecorder(t *testing.T) *SSHRecorder {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &SSHRecorder{SSH: filepath.Join(bin, "ssh"), OpenShell: filepath.Join(dir, "openshell"), log: filepath.Join(dir, "ssh.log")}
	log := quote(r.log)
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(r.SSH, SSHDashG+`{ printf 'args'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> `+log+"\n")
	write(r.OpenShell, `printf 'via %s\n' "$(command -v ssh)" >> `+log+`
printf 'path %s\n' "${PATH%%:*}" >> `+log+`
ssh "$@"
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return r
}

// Calls returns every ssh the stand-in CLI ran so far.
func (r *SSHRecorder) Calls(t *testing.T) []SSHCall {
	t.Helper()
	data, err := os.ReadFile(r.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var calls []SSHCall
	var cur SSHCall
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		switch kind {
		case "via":
			cur.Via = rest
		case "path":
			cur.PathHead = rest
		case "args":
			for _, a := range strings.Split(rest, " [") {
				if a = strings.TrimPrefix(a, "["); a != "" {
					cur.Args = append(cur.Args, strings.TrimSuffix(a, "]"))
				}
			}
			calls = append(calls, cur)
			cur = SSHCall{}
		}
	}
	return calls
}

// ExpectShimmed fails t unless the CLI ran ssh n times, each through a
// DefenseClaw shim first on its PATH that passed the no-sharing options
// before the CLI's arguments, and each shim is gone.
func (r *SSHRecorder) ExpectShimmed(t *testing.T, n int) []SSHCall {
	t.Helper()
	calls := r.Calls(t)
	if len(calls) != n {
		t.Fatalf("ssh ran %d times, want %d: %+v", len(calls), n, calls)
	}
	opts := openshell.SSHNoSharingOptions()
	for _, c := range calls {
		dir := filepath.Dir(c.Via)
		if !strings.HasPrefix(filepath.Base(dir), "defenseclaw-ssh-") || c.PathHead != dir {
			t.Fatalf("the CLI's ssh is %s with PATH starting %s, not DefenseClaw's shim", c.Via, c.PathHead)
		}
		if len(c.Args) < len(opts) || !slices.Equal(c.Args[:len(opts)], opts) {
			t.Fatalf("ssh args = %q, want %q first", c.Args, opts)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("shim directory %s left behind: %v", dir, err)
		}
	}
	return calls
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
