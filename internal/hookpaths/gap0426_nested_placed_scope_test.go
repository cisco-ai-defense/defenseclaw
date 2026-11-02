// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0426: a copy inside a top-level call argument is placed by the
// statement walk. Its archive scope must stay tied to the placed directory
// after cd; marking it unplaced makes every write globally opaque.
func TestGAP0426NestedPlacedCopyScope(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := `cd ~ && f=project/backup; echo $(cp -a project/src $f)`
	links := commandLinks(command, project, home, nil, false, false)
	if !links.cdScopes || links.globalOpaque || len(links.placedCopyDestinations) == 0 {
		t.Fatalf("nested copy lost its placed scope: cdScopes=%t globalOpaque=%t placed=%v scopes=%v",
			links.cdScopes, links.globalOpaque, links.placedCopyDestinations, links.opaqueScopes)
	}
}
