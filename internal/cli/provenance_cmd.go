// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Print binary and config provenance (v7 quartet)",
}

var provenanceShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show schema_version, content_hash, generation, and binary_version",
	RunE:  runProvenanceShow,
}

func init() {
	provenanceCmd.AddCommand(provenanceShowCmd)
	rootCmd.AddCommand(provenanceCmd)
}

func runProvenanceShow(cmd *cobra.Command, _ []string) error {
	version.SetBinaryVersion(appVersion)
	p := version.Current()
	var out io.Writer = os.Stdout
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	fmt.Fprintf(out, "schema_version: %d\n", p.SchemaVersion)
	fmt.Fprintf(out, "content_hash: %s\n", p.ContentHash)
	fmt.Fprintf(out, "generation: %d\n", p.Generation)
	fmt.Fprintf(out, "binary_version: %s\n", p.BinaryVersion)
	return nil
}
