// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

// EvalLinks is path with every link on the way followed, as the system
// opens it: the place a check that a path lies under a root must judge.
// filepath.EvalSymlinks follows symbolic links only. Since Go 1.23 it leaves
// a Windows junction (a mount point) unfollowed, and a standard user can
// make a junction without any privilege, so a path that leaves a root
// through a junction would still look like it is under the root
// (rel-1-0-10:GAP-2182). On Windows the result is the final path of the
// opened file or folder (GetFinalPathNameByHandle), with junctions and
// symbolic links followed alike, and without the \\?\ prefix. A
// reparse point that names no other place (an app execution alias, for
// example) is its own final path. Everywhere else EvalLinks is
// filepath.EvalSymlinks. A path that does not exist gives an error that
// matches fs.ErrNotExist, as it does for filepath.EvalSymlinks, and a path
// that cannot be resolved gives an error, never the unresolved path.
func EvalLinks(path string) (string, error) { return evalLinks(path) }
