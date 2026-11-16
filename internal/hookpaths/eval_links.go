// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

// EvalLinks is the path with every link on the way followed, as the system
// opens it. filepath.EvalSymlinks follows symbolic links only: since Go 1.23
// it fails a Windows path that crosses a junction (a mount point) with a
// not-found error, which a proof that reads a missing root as no root took
// for a root that is not there, so a project folder that is a junction to a
// folder outside the profile looked like no folder at all
// (rel-1-0-9:GAP-0621). On Windows the result is the final path of the
// opened file or folder, junctions and symbolic links included; elsewhere it
// is the symbolic-link result. A path that does not exist is the not-exist
// error, as for filepath.EvalSymlinks.
func EvalLinks(name string) (string, error) { return evalLinks(name) }
