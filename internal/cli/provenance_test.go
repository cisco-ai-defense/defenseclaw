// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestProvenanceShowOutput(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("9.9.9-test")
	version.SetContentHash([]byte("abc"))

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	appVersion = "9.9.9-test"
	if err := runProvenanceShow(cmd, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, s := range []string{"schema_version:", "content_hash:", "generation:", "binary_version:"} {
		if !bytes.Contains([]byte(out), []byte(s)) {
			t.Fatalf("stdout missing %q: %s", s, out)
		}
	}
}
