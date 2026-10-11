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

// Package regodata finds the data documents a Rego bundle reads outside
// data.defenseclaw. Since config_version 9 the gateway loads no data.json, so
// such a read sees nothing: the policy engine refuses the bundle and the v8 to
// v9 migration records the read. Both use this package so they agree on which
// modules are affected.
package regodata

import (
	"sort"

	"github.com/open-policy-agent/opa/ast" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// Read is a module that reads data documents outside data.defenseclaw.
type Read struct {
	// Module is the module name (its file name).
	Module string
	// Docs are the documents read ("data.config", "data.operator_policy"),
	// first read first, without duplicates.
	Docs []string
}

// OutsideReads returns the modules whose package is one of roots, or that
// such a module reaches through a data.defenseclaw reference, and that read
// a data document outside data.defenseclaw, in the order they are reached
// (roots by module name first). Modules no root reaches, such as policy
// tests, cannot change a verdict and are not reported.
func OutsideReads(modules map[string]*ast.Module, roots ...string) []Read {
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	reached := make(map[string]bool, len(names))
	var queue []string
	for _, name := range names {
		pkg := modules[name].Package.Path.String()
		for _, root := range roots {
			if pkg == root {
				reached[name] = true
				queue = append(queue, name)
				break
			}
		}
	}
	var reads []Read
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		refs, docs := ModuleReads(modules[name])
		if len(docs) > 0 {
			reads = append(reads, Read{Module: name, Docs: docs})
		}
		for _, other := range names {
			if reached[other] {
				continue
			}
			for _, ref := range refs {
				if refOverlaps(ref, modules[other].Package.Path) {
					reached[other] = true
					queue = append(queue, other)
					break
				}
			}
		}
	}
	return reads
}

// ModuleReads returns the data.defenseclaw references in the imports and
// rules of mod, and the data documents outside data.defenseclaw it reads. The
// package clause names the document of the module itself and a with target
// replaces a document for one expression; neither reads one, so only a with
// value is inspected. Comments and string literals are not references.
//
// A read of the data root itself (data, data[key], data[f(x)]) can reach any
// document, a removed data.json one included, so it is reported in its
// computed form ("data[key]") and also kept as a reference that reaches
// every module.
func ModuleReads(mod *ast.Module) ([]ast.Ref, []string) {
	var refs []ast.Ref
	var docs []string
	seen := map[string]bool{}
	addDoc := func(doc string) {
		if !seen[doc] {
			seen[doc] = true
			docs = append(docs, doc)
		}
	}
	var walk *ast.GenericVisitor
	walk = ast.NewGenericVisitor(func(node any) bool {
		if with, ok := node.(*ast.With); ok {
			walk.Walk(with.Value)
			return true
		}
		ref, ok := node.(ast.Ref)
		if !ok || !ref[0].Equal(ast.DefaultRootDocument) {
			return false
		}
		if len(ref) < 2 {
			addDoc(ref.String())
		} else if key, ok := ref[1].Value.(ast.String); !ok {
			addDoc(ref[:2].String())
		} else if string(key) != "defenseclaw" {
			addDoc("data." + string(key))
			return true
		}
		refs = append(refs, ref)
		return false
	})
	for _, imp := range mod.Imports {
		walk.Walk(imp)
	}
	for _, rule := range mod.Rules {
		walk.Walk(rule)
	}
	return refs, docs
}

// refOverlaps reports whether ref can read the document of the package at
// path: one is a prefix of the other, and a variable key matches any key.
func refOverlaps(ref, path ast.Ref) bool {
	for i := 1; i < len(ref) && i < len(path); i++ {
		if _, ok := ref[i].Value.(ast.String); !ok {
			return true
		}
		if !ref[i].Equal(path[i]) {
			return false
		}
	}
	return true
}
