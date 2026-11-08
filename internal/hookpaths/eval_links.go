// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

// EvalLinks is the path with every link on the way followed, as the system
// opens it. filepath.EvalSymlinks follows symbolic links only: since Go 1.23
// it leaves a Windows junction (a mount point) as an ordinary folder, so a
// project folder that is a junction to a folder outside the profile looked
// like a folder inside it (rel-1-0-9:GAP-0621). On Windows the result is the
// final path of the opened file, junctions included; elsewhere it is the
// symbolic-link result. A path that does not exist is the not-exist error,
// as for filepath.EvalSymlinks.
func EvalLinks(name string) (string, error) {
	resolved, err := pathEvalSymlinks(name)
	if err != nil {
		return "", err
	}
	return followMountPoints(resolved)
}
