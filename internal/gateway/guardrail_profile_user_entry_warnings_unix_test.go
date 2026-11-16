// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0197: a candidate whose users entry is the bare name of a local
// account is reported by the call config validate makes, with the spellings
// that select the account; the uid and .\name entries are not.
func TestProfileUserEntryWarningsNameTheLocalAccountSpelling(t *testing.T) {
	account, facts := profileExplainAccount, profileExplainDirectoryFacts
	t.Cleanup(func() { profileExplainAccount, profileExplainDirectoryFacts = account, facts })
	profileExplainAccount = func(name string) (string, string, error) {
		if name == "e7local" || name == "1601" {
			return "1601", "e7local", nil
		}
		return "", "", unixidentity.ErrNotFound
	}
	profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles, ResolvedAt: time.Now()}, nil
	}
	got := ProfileUserEntryWarnings(context.Background(), []config.ProfileAssignment{
		{Profile: "devs", Match: config.ProfileMatch{Users: []string{"e7local"}}},
		{Profile: "devs", Match: config.ProfileMatch{Users: []string{`.\e7local`, "1601"}}},
	})
	if len(got) != 1 || !strings.HasPrefix(got[0], `assignment 1: users entry "e7local" names the local account e7local (uid 1601)`) ||
		!strings.Contains(got[0], `write .\e7local or the uid`) {
		t.Fatalf("warnings = %q", got)
	}
}
