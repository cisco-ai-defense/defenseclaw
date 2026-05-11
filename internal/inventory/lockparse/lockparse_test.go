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

package lockparse

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLockFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func find(t *testing.T, components []Component, name string) Component {
	t.Helper()
	for _, c := range components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %q not found in %+v", name, components)
	return Component{}
}

func TestParsePackageJSON_extractsAllDependencyGroups(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "package.json", `{
  "name": "demo",
  "dependencies": {"openai": "^1.45.0", "@anthropic-ai/sdk": "0.30.0"},
  "devDependencies": {"langchain": "~0.2.16"},
  "peerDependencies": {"react": "*"},
  "optionalDependencies": {"sharp": "0.33.5"}
}`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 5 {
		t.Fatalf("expected 5 components, got %d: %+v", len(out), out)
	}
	if got := find(t, out, "openai").Version; got != "1.45.0" {
		t.Fatalf("openai version = %q, want 1.45.0", got)
	}
	if got := find(t, out, "@anthropic-ai/sdk").Version; got != "0.30.0" {
		t.Fatalf("@anthropic-ai/sdk version = %q, want 0.30.0", got)
	}
	if got := find(t, out, "langchain").Version; got != "0.2.16" {
		t.Fatalf("langchain version = %q, want 0.2.16", got)
	}
}

func TestParsePackageLockJSON_v3layout(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo"},
    "node_modules/openai": {"version": "1.45.0"},
    "node_modules/@anthropic-ai/sdk": {"version": "0.30.0"},
    "node_modules/openai/node_modules/@types/node": {"version": "20.0.0"}
  }
}`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := find(t, out, "openai").Version; got != "1.45.0" {
		t.Fatalf("openai = %q", got)
	}
	if got := find(t, out, "@anthropic-ai/sdk").Version; got != "0.30.0" {
		t.Fatalf("scoped = %q", got)
	}
	if got := find(t, out, "@types/node").Version; got != "20.0.0" {
		t.Fatalf("nested leaf = %q", got)
	}
}

func TestParseRequirementsTxt_handlesAllSpecifierForms(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "requirements.txt", `# top comment
openai==1.45.0
anthropic >= 0.30.0
langchain~=0.2.16  # inline comment
llama-index-core != 0.10.0
crewai
litellm @ git+https://github.com/BerriAI/litellm.git@v1.50.0
pydantic[email] >= 2.0
some_pkg==2.0.0; python_version >= "3.10"
-e ./local-package
-r other-requirements.txt
`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := find(t, out, "openai").Version; got != "1.45.0" {
		t.Fatalf("openai = %q", got)
	}
	if got := find(t, out, "anthropic").Version; got != "0.30.0" {
		t.Fatalf("anthropic = %q", got)
	}
	if got := find(t, out, "langchain").Version; got != "0.2.16" {
		t.Fatalf("langchain = %q", got)
	}
	if got := find(t, out, "llama-index-core").Version; got != "0.10.0" {
		t.Fatalf("llama-index-core = %q", got)
	}
	if got := find(t, out, "crewai").Version; got != "" {
		t.Fatalf("crewai (bare) version = %q, want empty", got)
	}
	// Environment marker stripped, version preserved.
	if got := find(t, out, "some-pkg").Version; got != "2.0.0" {
		t.Fatalf("some-pkg = %q", got)
	}
	// PEP 508 git+ specifier: name resolved, version empty.
	if got := find(t, out, "litellm").Name; got != "litellm" {
		t.Fatalf("litellm not parsed: %+v", out)
	}
	// `-e` and `-r` lines must be skipped.
	for _, c := range out {
		if c.Name == "-e" || c.Name == "-r" {
			t.Fatalf("requirement directive leaked into components: %+v", c)
		}
	}
}

func TestParsePyprojectToml_pep621AndPoetry(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "pyproject.toml", `[project]
name = "demo"
version = "0.1.0"
dependencies = [
  "openai>=1.45.0",
  "anthropic ==0.30.0",
  "langchain",
]

[tool.poetry.dependencies]
python = "^3.10"
llama-index = "^0.10.0"
crewai = { version = "0.30.0", optional = true }
`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := find(t, out, "openai").Version; got != "1.45.0" {
		t.Fatalf("openai = %q", got)
	}
	if got := find(t, out, "anthropic").Version; got != "0.30.0" {
		t.Fatalf("anthropic = %q", got)
	}
	if got := find(t, out, "llama-index").Version; got != "0.10.0" {
		t.Fatalf("llama-index = %q", got)
	}
	if got := find(t, out, "crewai").Version; got != "0.30.0" {
		t.Fatalf("crewai inline-table version = %q", got)
	}
	for _, c := range out {
		if c.Name == "python" {
			t.Fatalf("python entry leaked from poetry deps")
		}
	}
}

func TestParsePoetryStyleLock_extractsNameVersionPairs(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "poetry.lock", `# Comment
[[package]]
name = "openai"
version = "1.45.0"
description = "OpenAI Python SDK"

[[package]]
name = "langchain"
version = "0.2.16"

[metadata]
lock-version = "2.0"
`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := find(t, out, "openai").Version; got != "1.45.0" {
		t.Fatalf("openai = %q", got)
	}
	if got := find(t, out, "langchain").Version; got != "0.2.16" {
		t.Fatalf("langchain = %q", got)
	}
}

func TestParseCargoLockUsesCargoEcosystem(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "Cargo.lock", `# This file is automatically @generated by Cargo.
[[package]]
name = "async-openai"
version = "0.25.0"

[[package]]
name = "rig-core"
version = "0.6.0"
`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	asyncOpenAI := find(t, out, "async-openai")
	if asyncOpenAI.Ecosystem != "cargo" {
		t.Fatalf("async-openai ecosystem = %q, want cargo", asyncOpenAI.Ecosystem)
	}
	if asyncOpenAI.Version != "0.25.0" {
		t.Fatalf("async-openai version = %q, want 0.25.0", asyncOpenAI.Version)
	}
	if got := find(t, out, "rig-core").Ecosystem; got != "cargo" {
		t.Fatalf("rig-core ecosystem = %q, want cargo", got)
	}
}

func TestParseGoMod_extractsRequireBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "go.mod", `module example.com/demo

go 1.22

require (
	github.com/openai/openai-go v0.45.0
	github.com/anthropics/anthropic-sdk-go v0.5.0 // indirect
)

require github.com/tmc/langchaingo v0.1.10
`)
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := find(t, out, "github.com/openai/openai-go").Version; got != "v0.45.0" {
		t.Fatalf("openai-go = %q", got)
	}
	if got := find(t, out, "github.com/anthropics/anthropic-sdk-go").Version; got != "v0.5.0" {
		t.Fatalf("anthropic-sdk-go = %q", got)
	}
	if got := find(t, out, "github.com/tmc/langchaingo").Version; got != "v0.1.10" {
		t.Fatalf("langchaingo = %q", got)
	}
}

func TestParse_unknownExtensionReturnsNoError(t *testing.T) {
	dir := t.TempDir()
	path := writeLockFile(t, dir, "exotic.lock", "totally unknown\n")
	out, err := Parse(path, MaxFileBytes)
	if err != nil {
		t.Fatalf("unknown file should not error, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("unknown file should yield 0 components, got %+v", out)
	}
}

func TestParse_oversizedFilesAreSkippedNotErrored(t *testing.T) {
	dir := t.TempDir()
	// Build a 1 KB body so we can set maxBytes lower than the file
	// size but higher than 0 to trigger the "file too large" branch.
	body := make([]byte, 1024)
	for i := range body {
		body[i] = '\n'
	}
	path := writeLockFile(t, dir, "package.json", string(body))
	out, err := Parse(path, 256)
	if err != nil {
		t.Fatalf("oversized file should not error, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("oversized file should yield 0 components, got %d", len(out))
	}
}

func TestEcosystem_recognizesCommonBasenames(t *testing.T) {
	cases := map[string]string{
		"package.json":      "npm",
		"package-lock.json": "npm",
		"pnpm-lock.yaml":    "npm",
		"yarn.lock":         "npm",
		"requirements.txt":  "pypi",
		"pyproject.toml":    "pypi",
		"poetry.lock":       "pypi",
		"Cargo.lock":        "cargo",
		"go.sum":            "go",
		"Gemfile.lock":      "rubygems",
		"composer.lock":     "composer",
		"unknown.txt":       "",
	}
	for basename, want := range cases {
		if got := Ecosystem(basename); got != want {
			t.Errorf("Ecosystem(%q) = %q, want %q", basename, got, want)
		}
	}
}

func TestIndexByName_perEcosystemFiltering(t *testing.T) {
	components := []Component{
		{Ecosystem: "pypi", Name: "openai", Version: "1.45.0"},
		{Ecosystem: "npm", Name: "openai", Version: "4.55.0"},
		{Ecosystem: "pypi", Name: "Langchain", Version: "0.2.16"},
	}
	pypi := IndexByName(components, "pypi")
	if pypi["openai"] != "1.45.0" {
		t.Fatalf("pypi openai version = %q", pypi["openai"])
	}
	if pypi["langchain"] != "0.2.16" {
		t.Fatalf("name lookup is case-insensitive: pypi['langchain'] = %q", pypi["langchain"])
	}
	npm := IndexByName(components, "npm")
	if npm["openai"] != "4.55.0" {
		t.Fatalf("npm openai version = %q", npm["openai"])
	}
}
