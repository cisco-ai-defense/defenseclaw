// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package fullconfig links the parts of internal/config that need heavy
// libraries: the v8 schema check (internal/config/v8schema), the SQLite
// driver the v9 migration opens the audit store with, and the Rego parser of
// the migration's module refresh. Every program that links internal/config
// imports it, except the hook, which reads config.yaml but never validates a
// v8 document or migrates a config (TestEveryConfigProgramLinksTheFullConfig
// in cmd/defenseclaw-hook).
package fullconfig

import (
	"github.com/open-policy-agent/opa/ast" //nolint:staticcheck // The v8/v9 migration shares the legacy AST type with regodata until 1.1.
	// The audit store's driver, which the v9 migration opens by name.
	_ "modernc.org/sqlite"

	"github.com/defenseclaw/defenseclaw/internal/config"
	_ "github.com/defenseclaw/defenseclaw/internal/config/v8schema"
	"github.com/defenseclaw/defenseclaw/internal/policy/regodata"
)

func init() {
	config.RegisterV9RegoReads(config.V9RegoReads{Parse: parseRegoModule, Reads: regoModuleReads})
}

func parseRegoModule(name string, source []byte) (any, error) {
	return ast.ParseModuleWithOpts(name, string(source), ast.ParserOptions{RegoVersion: ast.RegoV1})
}

func regoModuleReads(parsed map[string]any, vendor []string) map[string][]string {
	modules := make(map[string]*ast.Module, len(parsed))
	for name, module := range parsed {
		modules[name], _ = module.(*ast.Module)
	}
	reads := map[string][]string{}
	for _, read := range regodata.OutsideReads(modules, "data.defenseclaw.admission", "data.defenseclaw.guardrail") {
		reads[read.Module] = read.Docs
	}
	for _, name := range vendor {
		if module := modules[name]; module != nil && reads[name] == nil {
			if _, docs := regodata.ModuleReads(module); len(docs) > 0 {
				reads[name] = docs
			}
		}
	}
	return reads
}
