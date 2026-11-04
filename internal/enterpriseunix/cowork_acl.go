// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// coworkACLTargets adds no probes when no Cowork files are installed or
// planned. Files and the dedicated leaf are ours to repair; shared ancestors
// are validation-only, just like vendor machine-policy ancestors.
func (e *Env) coworkACLTargets(files []string) []aclTarget {
	if e.GOOS != "darwin" {
		return nil
	}
	var targets []aclTarget
	add := func(path string, dir, ancestor bool) {
		info, err := os.Lstat(e.P(path))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
			return
		}
		targets = append(targets, aclTarget{
			path: e.P(path), dir: dir, ancestor: ancestor,
			publishedDir: dir, publishedFile: !dir, requireListing: true,
		})
	}
	found := false
	for _, path := range files {
		if isCoworkPath(path) {
			found = true
			add(path, false, false)
		}
	}
	if !found {
		return nil
	}
	add(macCoworkDir, true, false)
	for path := filepath.Dir(macCoworkDir); ; path = filepath.Dir(path) {
		add(path, true, true)
		if path == "/" || path == "." {
			break
		}
	}
	return targets
}

func mergeCoworkACLTargets(targets, cowork []aclTarget) []aclTarget {
	for _, extra := range cowork {
		merged := false
		for i := range targets {
			if targets[i].path == extra.path {
				// Cowork assets are deliberately public even if their mode
				// drifted to 0600; retain unrelated read-only ACL entries.
				targets[i].private = false
				targets[i].publishedDir = targets[i].publishedDir || extra.publishedDir
				targets[i].publishedFile = targets[i].publishedFile || extra.publishedFile
				targets[i].requireListing = true
				// Never repair a shared Cowork ancestor's ACL as a side effect
				// of including it in another part of the deployment.
				targets[i].ancestor = targets[i].ancestor || extra.ancestor
				merged = true
				break
			}
		}
		if !merged {
			targets = append(targets, extra)
		}
	}
	return targets
}

// coworkACLProblems is the read-only host-delivery check, independent of the
// generic deployment report. paths are canonical installed Cowork file paths.
// Any returned problem makes host_ready false. Call only while enabled.
func (e *Env) coworkACLProblems(ctx context.Context, paths []string) []string {
	findings, err := e.aclFindings(ctx, e.coworkACLTargets(paths))
	var problems []string
	if err != nil {
		problems = append(problems, "cannot inspect Cowork VM sensor ACLs: "+err.Error())
	}
	var ancestors, owned []aclFinding
	for _, finding := range findings {
		if finding.ancestor {
			ancestors = append(ancestors, finding)
		} else {
			owned = append(owned, finding)
		}
	}
	if len(ancestors) > 0 {
		problems = append(problems, ancestorACLProblem(ancestors, e.lifecycleCommand(ActionRepair)))
	}
	if len(owned) > 0 {
		problems = append(problems, fmt.Sprintf("macOS ACL entries grant unsafe access or deny users reading the Cowork VM sensor files: %s; run `%s` to remove those entries", describeACLFindings(owned), e.lifecycleCommand(ActionRepair)))
	}
	return problems
}
