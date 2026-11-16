// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

// runPayloadBinding prints the setuppayload.PayloadBinding of a payload
// directory: the value build-setup.sh links into the outer standalone Setup
// image (-X main.standalonePayloadBinding) so the Setup stages only the
// payload, and acts only on the manifest identity, it was built with.
// --distribution-flavor, --version and --source-commit must be the values
// the assembler records in the trailer manifest.
func runPayloadBinding(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("payload-binding", flag.ContinueOnError)
	flavor := fs.String("distribution-flavor", "", "distribution flavor the trailer manifest records")
	version := fs.String("version", "", "release version the trailer manifest records")
	sourceCommit := fs.String("source-commit", "", "source commit the trailer manifest records")
	payloadDir := fs.String("payload-dir", "", "directory whose regular-file children are the payload")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := requireFlags(map[string]string{
		"distribution-flavor": *flavor,
		"version":             *version,
		"source-commit":       *sourceCommit,
		"payload-dir":         *payloadDir,
	}); err != nil {
		return err
	}
	if err := validateSourceCommit(*sourceCommit); err != nil {
		return err
	}
	files, err := hashPayloadDir(*payloadDir)
	if err != nil {
		return fmt.Errorf("hash payload dir %s: %w", *payloadDir, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("payload dir %s contains no regular files", *payloadDir)
	}
	digests := make(map[string]string, len(files))
	for _, file := range files {
		digests[file.name] = file.sha256
	}
	identity := setuppayload.PayloadIdentity{DistributionFlavor: *flavor, Version: *version, SourceCommit: *sourceCommit}
	_, err = fmt.Fprintln(stdout, setuppayload.PayloadBinding(identity, digests))
	return err
}
