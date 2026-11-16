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

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The lifecycle test fault lets the CI upgrade gate prove that a failed
// upgrade rolls back, and a bundle cell prove that a failure after the
// commit leaves the receipt, the bundle state and the enforced policy in
// agreement. A file named testFaultFileName in the root-only lifecycle state
// directory, owned by root, with no group or other access, names the stage:
// testFaultAfterServices makes an apply fail right after its services
// started, so the transaction rolls back; testFaultAfterCommit makes it
// report an error once its deployment committed, as a later step that fails
// does (GAP-0271). Only root can create it there; any other file of that
// name is ignored with a warning. This lifecycle runs only the standalone
// profile; Secure Client never reads it.
const (
	testFaultFileName      = ".test-fault"
	testFaultAfterServices = "after_services"
	testFaultAfterCommit   = "after_commit"
	codeLifecycleTestFault = "lifecycle_test_fault"
)

// testFaultRequested reports whether the test fault file asks this run to
// fail at stage. Whenever the file exists, the check of the first stage
// (after_services) says in the result what the lifecycle did with it.
func (l *lifecycle) testFaultRequested(stage string) bool {
	env := l.env
	path := env.P(filepath.Join(env.Layout.LifecycleDir, testFaultFileName))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	ignore := func(reason string) bool {
		if stage == testFaultAfterServices {
			l.result.AddWarning(codeLifecycleTestFault, fmt.Sprintf("ignored the lifecycle test fault file %s: %s", path, reason))
		}
		return false
	}
	if err != nil {
		return ignore(err.Error())
	}
	if !info.Mode().IsRegular() {
		return ignore("it is not a regular file")
	}
	if uid, _, err := env.OwnerOf(path); err != nil || uid != 0 {
		return ignore("it is not owned by root")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ignore("other accounts can read or write it")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ignore(err.Error())
	}
	named := strings.TrimSpace(string(data))
	if named != testFaultAfterServices && named != testFaultAfterCommit {
		return ignore(fmt.Sprintf("it names the stage %q; the stages are %q and %q", named, testFaultAfterServices, testFaultAfterCommit))
	}
	if named != stage {
		return false
	}
	when := "after its services started"
	if stage == testFaultAfterCommit {
		when = "after its deployment committed"
	}
	l.result.AddWarning(codeLifecycleTestFault, fmt.Sprintf("the lifecycle test fault file %s failed this run %s", path, when))
	return true
}
