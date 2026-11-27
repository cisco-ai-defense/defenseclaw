// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

type hardLinkOperandCase struct {
	ID        string `json:"id"`
	Command   string `json:"command"`
	Alias     string `json:"alias"`
	Member    string `json:"member"`
	Certainty string `json:"certainty"`
	Reach     string `json:"reach"`
	Basis     string `json:"basis"`
}

func TestDET111R2HardLinkOperandsUseIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-host fixture: the authorized_keys members come from the host key reader (hookpaths.ProtectedAuthorizedKeysPaths, host separators), so a POSIX path names none of them on a Windows host, and a Windows host reads every hook call with Windows paths (gateway effectWindowsCall)")
	}
	const home = "/home/alice"
	const project = "/home/alice/project"
	const keys = "/home/alice/.ssh/authorized_keys"
	opt := effects.Options{Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX, Home: home, CWD: project, Env: map[string]string{"HOME": home}}
	f, err := os.Open("../effects/testdata/det111_r2_hardlinks.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var tc hardLinkOperandCase
		if err := json.Unmarshal(sc.Bytes(), &tc); err != nil {
			t.Fatal(err)
		}
		if tc.Member != keys {
			t.Fatalf("%s fixture member %q, want %q", tc.ID, tc.Member, keys)
		}
		t.Run(tc.ID, func(t *testing.T) {
			fix := NewHardLinkFixture().Link(project+"/"+tc.Alias, keys).File(project + "/ordinary/x")
			res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.Command, Workdir: project}, opt)
			facts := Project(res, Env{Home: home, Flavor: effects.FlavorPOSIX, Identity: fix.Identity, Resolve: func(p string) (string, bool) {
				if filepath.IsAbs(p) {
					return p, true
				}
				return filepath.Join(project, p), true
			}})
			for _, fact := range facts {
				for _, protected := range Protected(fact.Target) {
					if protected.Set == SetSSHAuthorizedKeys && protected.Certainty == tc.Certainty && protected.Basis == tc.Basis && protected.Reach == tc.Reach {
						return
					}
				}
			}
			t.Fatalf("%s did not match protected alias identity (%s/%s/%s)\n%+v", tc.ID, tc.Certainty, tc.Reach, tc.Basis, res)
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
