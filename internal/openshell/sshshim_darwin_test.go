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

//go:build darwin

package openshell_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// addACL adds a macOS ACL entry to path for the rest of t.
func addACL(t *testing.T, path, entry string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a %q %s: %v: %s", entry, path, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

// A macOS ACL grants write without changing the mode bits the other
// checks read: a 0700 temporary directory with an inheritable "everyone
// allow add_file,delete_child" entry used to pass them, and the shim made
// in it inherited "everyone allow write". Such a directory, or one above
// it, is refused (the shim goes under the data directory instead), and so
// is a shim or shim directory that gains such an entry afterwards.
func TestSSHShimRefusesWritableMacOSACLs(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bin")
	recordingSSH(t, bin)
	unsafe := "has write-capable macOS ACL entry: another user could replace the ssh DefenseClaw gives the OpenShell CLI there"

	base := realTempDir(t)
	addACL(t, base, "everyone allow list,add_file,search,add_subdirectory,delete_child,file_inherit,directory_inherit")
	openshell.SetSSHShimBase(t, base)
	if s, err := openshell.NewSSHShim(bin); err == nil || s != nil || !strings.Contains(err.Error(), base+" "+unsafe) {
		t.Fatalf("NewSSHShim in a directory with a writable ACL = %+v, %v", s, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("a refused shim left %v in %s", entries, base)
	}

	// A directory above it counts too.
	parent := realTempDir(t)
	child := filepath.Join(parent, "tmp")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	addACL(t, parent, "everyone allow add_subdirectory,delete_child")
	openshell.SetSSHShimBase(t, child)
	if s, err := openshell.NewSSHShim(bin); err == nil || s != nil || !strings.Contains(err.Error(), parent+" "+unsafe) {
		t.Fatalf("NewSSHShim below a directory with a writable ACL = %+v, %v", s, err)
	}

	// Entries that grant no write are fine: the deny macOS puts on home
	// folders, and read access.
	plain := realTempDir(t)
	addACL(t, plain, "everyone deny delete")
	addACL(t, plain, "everyone allow list,search,readattr")
	openshell.SetSSHShimBase(t, base)
	openshell.SetSSHShimFallback(t, filepath.Join(plain, "openshell-ssh"))
	s, err := openshell.NewSSHShim(bin)
	if err != nil || s == nil || filepath.Dir(s.Dir) != filepath.Join(plain, "openshell-ssh") || !strings.Contains(s.Fallback, base+" "+unsafe) {
		t.Fatalf("NewSSHShim falling back from a directory with a writable ACL = %+v, %v", s, err)
	}
	defer s.Remove()
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}

	// An entry added to the shim or its directory afterwards.
	addACL(t, s.Path, "everyone allow write,append")
	if err := s.Verify(); err == nil || !strings.Contains(err.Error(), s.Path+" "+unsafe) {
		t.Fatalf("Verify of a shim everyone may write = %v", err)
	}
	if err := exec.Command("/bin/chmod", "-N", s.Path).Run(); err != nil {
		t.Fatal(err)
	}
	addACL(t, s.Dir, "everyone allow add_file,delete_child")
	if err := s.Verify(); err == nil || !strings.Contains(err.Error(), s.Dir+" "+unsafe) {
		t.Fatalf("Verify in a shim directory everyone may add to = %v", err)
	}

	// A directory that passed is remembered only while it is unchanged: an
	// entry added after one shim was made there stops the next.
	above := realTempDir(t)
	below := filepath.Join(above, "tmp")
	if err := os.Mkdir(below, 0o700); err != nil {
		t.Fatal(err)
	}
	openshell.SetSSHShimBase(t, below)
	first, err := openshell.NewSSHShim(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Remove(); err != nil {
		t.Fatal(err)
	}
	addACL(t, above, "everyone allow add_subdirectory,delete_child")
	if s, err := openshell.NewSSHShim(bin); err == nil || s != nil || !strings.Contains(err.Error(), above+" "+unsafe) {
		t.Fatalf("NewSSHShim after a writable ACL was added above = %+v, %v", s, err)
	}
}
