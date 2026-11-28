// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import "runtime"

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

// FinalPath is EvalLinks with the real final path always: a path named
// through a subst or mapped drive letter is given as the folder or share the
// drive maps to, where EvalLinks keeps the drive letter. A deny-sense check
// (a refused folder, "is it inside the data folder") compares this spelling
// as well, so a drive letter that maps into the refused folder is refused
// (rel-1-0-10:GAP-2210). Everywhere but Windows it is EvalLinks.
func FinalPath(path string) (string, error) { return finalPath(path) }

// DenySenseResolvers are the resolvers a deny-sense check compares a path
// with, each spelling in turn: EvalLinks and, on Windows, FinalPath. Off
// Windows FinalPath is EvalLinks, so the list holds EvalLinks once and a
// check does not resolve every path twice. The caller must not change the
// slice.
func DenySenseResolvers() []func(string) (string, error) { return denySenseResolvers }

var denySenseResolvers = func() []func(string) (string, error) {
	if runtime.GOOS == "windows" {
		return []func(string) (string, error){EvalLinks, FinalPath}
	}
	return []func(string) (string, error){EvalLinks}
}()
