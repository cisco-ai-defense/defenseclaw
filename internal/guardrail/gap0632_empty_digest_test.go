// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// config cannot import guardrail; its empty-file-set pin must be the loader's.
func TestGAP0632EmptyRulePackFilesDigestMatchesLoader(t *testing.T) {
	if got := "sha256:" + filesDigest(nil); got != config.EmptyRulePackFilesDigest {
		t.Fatalf("empty files digest = %s, config has %s", got, config.EmptyRulePackFilesDigest)
	}
	if got := "sha256:" + (*RulePack)(nil).FilesDigest(); got != config.EmptyRulePackFilesDigest {
		t.Fatalf("nil pack files digest = %s", got)
	}
}
