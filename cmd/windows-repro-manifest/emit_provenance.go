// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// runEmitProvenance emits provenance.json for a built outer Setup EXE.
// This is the last artefact the assemble step produces: it records the
// version, source commit, and the SHA-256 of the outer
// DefenseClawSetup-Enterprise-x64.exe so AVC (or a downstream verifier)
// can bind the outer binary back to the exact source it was built from.
//
// Two emit modes:
//
//	Default: hash the file at --setup-exe and write setup_sha256/
//	setup_size to those values. Meant for callers who own the final
//	artefact — e.g. spec 001's byte-identity CI gate, which emits
//	provenance for an already-final EXE.
//
//	--setup-sha256-placeholder: skip hashing, emit setup_sha256 as ""
//	and setup_size as 0. Used by spec 002's assemble.{sh,ps1} because
//	the outer EXE has NOT been signed yet at emit-provenance time —
//	the signed EXE hash can only be produced after AVC's step-3
//	signtool sign. AVC (or the optional finalize.{sh,ps1} helper)
//	populates the placeholder in place. --setup-exe is optional in
//	placeholder mode. See
//	docs/specs/002-windows-avc-packaging/design.md § Decisions.
func runEmitProvenance(args []string) error {
	fs := flag.NewFlagSet("emit-provenance", flag.ContinueOnError)
	version := fs.String("version", "", "release version, e.g. 0.9.0")
	sourceCommit := fs.String("source-commit", "", "40-char lowercase git commit sha")
	setupExe := fs.String("setup-exe", "", "path to the built DefenseClawSetup-Enterprise-x64.exe (required unless --setup-sha256-placeholder)")
	out := fs.String("out", "", "output path for provenance.json")
	distributionFlavor := fs.String("distribution-flavor", defaultDistributionFlavor, "distribution flavor tag")
	unsigned := fs.Bool("unsigned", false, "mark this provenance as belonging to an unsigned developer build")
	placeholder := fs.Bool("setup-sha256-placeholder", false, "emit setup_sha256=\"\" and setup_size=0; AVC or finalize.* fills them in after step-3 signing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	required := map[string]string{
		"version":       *version,
		"source-commit": *sourceCommit,
		"out":           *out,
	}
	if !*placeholder {
		// Only require --setup-exe when we're actually going to hash it.
		required["setup-exe"] = *setupExe
	}
	if err := requireFlags(required); err != nil {
		return err
	}
	// If a caller passes both --setup-sha256-placeholder AND --setup-exe,
	// the setup-exe path is silently ignored — we emit setup_sha256=""
	// regardless. That is a caller-side mistake that should be loud:
	// fail with a diagnostic instead of accepting the conflicting args.
	if *placeholder && strings.TrimSpace(*setupExe) != "" {
		return fmt.Errorf("--setup-sha256-placeholder is exclusive with --setup-exe; drop one")
	}
	if err := validateSourceCommit(*sourceCommit); err != nil {
		return err
	}

	var (
		digest string
		size   int64
	)
	if *placeholder {
		digest = ""
		size = 0
	} else {
		info, err := os.Stat(*setupExe)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return &os.PathError{Op: "stat", Path: *setupExe, Err: os.ErrInvalid}
		}
		digest, err = sha256File(*setupExe)
		if err != nil {
			return err
		}
		size = info.Size()
	}

	// Detect whether --distribution-flavor was passed explicitly. See
	// emit_manifest.go for the fs.Visit rationale — an explicit
	// `--distribution-flavor managed-enterprise --unsigned` must stay
	// `managed-enterprise`, not be re-suffixed.
	explicitFlavor := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "distribution-flavor" {
			explicitFlavor = true
		}
	})
	// Shares resolveDistributionFlavor with emit-manifest so a change
	// to the default or the -unsigned suffix flows through both
	// emitters in one edit (cmd/windows-repro-manifest/flavor.go).
	flavor := resolveDistributionFlavor(*distributionFlavor, *unsigned, explicitFlavor)
	doc := map[string]any{
		"distribution_flavor": flavor,
		"schema_version":      1,
		"setup_sha256":        digest,
		"setup_size":          size,
		"source_commit":       *sourceCommit,
		"unsigned":            *unsigned,
		"version":             *version,
	}
	return writeSortedJSON(*out, doc)
}
