// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

// runEmitPayloadMetadata emits payload-metadata.json for the build
// kit. Unlike manifest.json (which describes hashed signed inner
// files), payload-metadata.json describes what AVC's pipeline should
// EXPECT to see in the payload directory after signing: version tag,
// source commit, the CMID pseudo-version pinned into the vendored
// tree, and the exact filename list. It gives AVC a stable pre-check
// they can run before invoking assemble.sh.
func runEmitPayloadMetadata(args []string) error {
	fs := flag.NewFlagSet("emit-payload-metadata", flag.ContinueOnError)
	version := fs.String("version", "", "release version, e.g. 0.9.0")
	sourceCommit := fs.String("source-commit", "", "40-char lowercase git commit sha")
	cmidPseudoVersion := fs.String("cmid-pseudo-version", "", "vendored ai-common cmid module pseudo-version")
	expectedFilenames := fs.String("expected-filenames", "", "comma-separated list of expected filenames under payload/")
	out := fs.String("out", "", "output path for payload-metadata.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireFlags(map[string]string{
		"version":             *version,
		"source-commit":       *sourceCommit,
		"cmid-pseudo-version": *cmidPseudoVersion,
		"expected-filenames":  *expectedFilenames,
		"out":                 *out,
	}); err != nil {
		return err
	}
	if err := validateSourceCommit(*sourceCommit); err != nil {
		return err
	}

	names := splitAndSortFilenames(*expectedFilenames)
	if len(names) == 0 {
		return fmt.Errorf("--expected-filenames produced no non-empty entries")
	}
	// Convert to []any so encoding/json preserves the sorted slice
	// order in the output rather than emitting a heterogeneous mix.
	nameList := make([]any, 0, len(names))
	for _, n := range names {
		nameList = append(nameList, n)
	}

	doc := map[string]any{
		"cmid_pseudo_version": *cmidPseudoVersion,
		"expected_filenames":  nameList,
		"schema_version":      1,
		"source_commit":       *sourceCommit,
		"version":             *version,
	}
	return writeSortedJSON(*out, doc)
}

// splitAndSortFilenames breaks a comma-separated CLI flag into a
// deduplicated, sorted list. Whitespace around each entry is trimmed;
// empty entries are dropped. Sorting keeps the emitted JSON stable
// across caller invocations that pass the same names in different
// orders.
func splitAndSortFilenames(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
