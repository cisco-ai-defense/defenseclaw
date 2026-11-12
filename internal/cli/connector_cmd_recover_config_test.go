// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The installers name `connector recover-config` when a rollback is refused
// for recovery files an interrupted agent config change left. On a data folder
// with none it finishes nothing and succeeds, so the command is safe to run
// before every retry.
func TestConnectorRecoverConfigOnAFolderWithNoRecoveryFilesFinishesNothing(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	stdout, stderr, code := runConnectorCmd(t, "recover-config", "--data-dir", dataDir, "--json")
	if code != 0 || strings.TrimSpace(stderr) != "" {
		t.Fatalf("recover-config exit %d, stderr %q", code, stderr)
	}
	var got struct {
		OK        bool `json:"ok"`
		Recovered int  `json:"recovered"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || !got.OK || got.Recovered != 0 {
		t.Fatalf("recover-config output %q: %+v, %v", stdout, got, err)
	}
}
