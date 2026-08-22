// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package main implements windows-repro-manifest — the byte-stable JSON
// emitter for the Windows managed-enterprise AVC packaging handoff.
//
// It exists so that the three JSON artifacts produced during the outer
// DefenseClawSetup-Enterprise-x64.exe assembly step (manifest.json,
// payload-metadata.json, provenance.json) are byte-identical across
// bash and pwsh script hosts and across Linux/macOS build agents.
// Shell-native serializers (printf, ConvertTo-Json) differ on key
// ordering, whitespace, and escaping — this binary removes that
// variance.
//
// Design lives in docs/specs/001-windows-deterministic-build/design.md.
// The three subcommands each build a JSON object as a map (so
// encoding/json sorts keys) and write it with LF line endings,
// two-space indent, and a final trailing LF.
//
// Supply-chain contract: this binary depends only on the Go stdlib.
// Enforced by cmd/windows-repro-manifest/deps_test.go.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const usageText = `windows-repro-manifest — byte-stable JSON emitter for the Windows AVC handoff

Usage:
  windows-repro-manifest <subcommand> [flags]

Subcommands:
  emit-manifest           Emit manifest.json for a signed payload directory.
  emit-payload-metadata   Emit payload-metadata.json for the build kit.
  emit-provenance         Emit provenance.json for a built outer Setup EXE.

Run any subcommand with -h for its flags.

See docs/specs/001-windows-deterministic-build/ for the reproducibility
contract this tool implements.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	// Common help handling — a subcommand of -h/--help/help prints the
	// top-level usage. Anything unrecognised also prints usage and
	// exits with 2 so a scripted caller can distinguish it from a
	// per-subcommand flag error.
	switch sub {
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
		return
	case "emit-manifest":
		if err := runEmitManifest(args); err != nil {
			exitSubcommand("emit-manifest", err)
		}
	case "emit-payload-metadata":
		if err := runEmitPayloadMetadata(args); err != nil {
			exitSubcommand("emit-payload-metadata", err)
		}
	case "emit-provenance":
		if err := runEmitProvenance(args); err != nil {
			exitSubcommand("emit-provenance", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", sub)
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
}

// exitSubcommand terminates the process with the conventional exit
// codes for a subcommand error:
//   - flag.ErrHelp (raised by fs.Parse when the user passes -h) is a
//     successful help print, not a real error; exit 0 without a diagnostic
//     to keep `subcommand -h` scriptable.
//   - anything else is a real error; write the diagnostic and exit 1.
func exitSubcommand(sub string, err error) {
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "windows-repro-manifest %s: %s\n", sub, err)
	os.Exit(1)
}
