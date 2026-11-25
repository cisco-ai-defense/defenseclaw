// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bounded

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// readerClockReads are the only wall-clock reads a reader package keeps, by
// "<file>:<function>", each with why it is no bound of the reading (DET111
// step 2: a reader counts work, never time, so a call gets the same answer on
// a loaded box and an idle one; the hook answer budget stays with the caller).
var readerClockReads = map[string]string{
	// I/O answer waits on a network share: the answer is the share's, and a
	// share that does not answer in the call's budget is "unanswered", which
	// already counts as not clear (never an allow). The one allowed non-work
	// bound of the registry.
	"internal/hookpaths/network_path.go:askNetworkShare":  "network-share answer wait",
	"internal/hookpaths/network_path_links.go:stillPlain": "network-share answer wait",
	// The walk slot wait of a credential path resolve (substrate-1
	// GAP-1083): a recursive search waits for a free walk slot only within
	// what the hook call may still wait. It decides whether the walk runs,
	// never what it reads; a walk that gets no slot is cut, and a cut
	// resolve is TRUNCATED (CredentialPathReadCaps), never an allow.
	"internal/actionfacts/credential_path_reads.go:take": "walk slot wait in the hook's answer budget",
	// The settle check of a file system fingerprint (activeStateSettleLimit):
	// a folder changed in the clock tick of the walk could change again with
	// the same stamp, so its view is not kept across calls. It decides only
	// whether a walk is reused, never what the walk reads.
	"internal/hookpaths/action_target_mention.go:activeStateViewOf":     "fingerprint settle check",
	"internal/hookpaths/action_target_mention.go:activeStateIdentities": "fingerprint settle check",
	// The parse cache ages its entries out by time: a parse is a pure
	// function of the command text, so a hit and a miss give the same tree.
	"internal/shellparse/parse_cache.go:cachedParse": "cache eviction of a pure parse",
	"internal/shellparse/parse_cache.go:storeParse":  "cache eviction of a pure parse",
}

// TestReadersCountWorkNotTime fails on a time.Now, time.Since or time.Until in
// a reader package (readerPackages) outside readerClockReads.
func TestReadersCountWorkNotTime(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var problems []string
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", ".venv", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !isReaderDir(filepath.ToSlash(filepath.Dir(rel))) {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // the build reports it
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := rel + ":" + fn.Name.Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "time" || sel.Sel.Name != "Now" && sel.Sel.Name != "Since" && sel.Sel.Name != "Until" {
					return true
				}
				if _, allowed := readerClockReads[key]; allowed {
					seen[key] = true
					return true
				}
				problems = append(problems, fset.Position(call.Pos()).String()+": time."+sel.Sel.Name+" in "+fn.Name.Name+
					": a reader counts work (bounded.Counter, a registered cap), never time")
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key := range readerClockReads {
		if !seen[key] {
			problems = append(problems, key+": listed in readerClockReads and reads no clock: delete the entry")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
