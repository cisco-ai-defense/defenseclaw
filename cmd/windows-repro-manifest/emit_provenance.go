// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
)

// runEmitProvenance emits provenance.json for a built outer Setup EXE.
// This is the last artefact the assemble step produces: it records the
// version, source commit, and the SHA-256 of the outer
// DefenseClawSetup-Enterprise-x64.exe so AVC (or a downstream verifier)
// can bind the outer binary back to the exact source it was built from.
//
// Emitted BEFORE AVC signs the outer EXE, so setup_sha256 refers to
// the unsigned outer binary. AVC's post-sign step can either re-emit
// provenance.json with the signed hash or ship a separate .signed
// provenance record; that finalisation is documented in the AVC
// handoff, not implemented here.
func runEmitProvenance(args []string) error {
	fs := flag.NewFlagSet("emit-provenance", flag.ContinueOnError)
	version := fs.String("version", "", "release version, e.g. 0.9.0")
	sourceCommit := fs.String("source-commit", "", "40-char lowercase git commit sha")
	setupExe := fs.String("setup-exe", "", "path to the built DefenseClawSetup-Enterprise-x64.exe")
	out := fs.String("out", "", "output path for provenance.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireFlags(map[string]string{
		"version":       *version,
		"source-commit": *sourceCommit,
		"setup-exe":     *setupExe,
		"out":           *out,
	}); err != nil {
		return err
	}
	if err := validateSourceCommit(*sourceCommit); err != nil {
		return err
	}

	info, err := os.Stat(*setupExe)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return &os.PathError{Op: "stat", Path: *setupExe, Err: os.ErrInvalid}
	}
	digest, err := sha256File(*setupExe)
	if err != nil {
		return err
	}

	doc := map[string]any{
		"schema_version": 1,
		"setup_sha256":   digest,
		"setup_size":     info.Size(),
		"source_commit":  *sourceCommit,
		"version":        *version,
	}
	return writeSortedJSON(*out, doc)
}
