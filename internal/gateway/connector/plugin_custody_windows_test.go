// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// GAP-0731: a foreign entry inherited by the plugin folder is removed where it
// is set, with one icacls command that names the account.
func TestGAP0731RefusalNamesTheCarrierAndTheIcaclsCommand(t *testing.T) {
	cause := &safefile.UnsafePrivateDACLError{
		Path:    `C:\Users\lane\.config\opencode\plugins`,
		Carrier: `C:\Users\lane\.config\opencode`,
		Trustee: `HOST\other`,
	}
	err := explainPluginArtifactRefusal(`C:\Users\lane\.config\opencode\plugins\defenseclaw.js`, cause)
	if !errors.Is(err, ErrPluginFolderCustody) || !errors.Is(err, cause) {
		t.Fatalf("err=%v", err)
	}
	want := `fix: icacls "C:\Users\lane\.config\opencode" /remove:g "HOST\other"`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("message lacks %q:\n%v", want, err)
	}
	cause.Deny = true
	if got := explainPluginArtifactRefusal("", cause).Error(); !strings.Contains(got, `/remove:d "HOST\other"`) {
		t.Fatalf("a deny entry is removed with :d: %s", got)
	}

	// Benign twins: a refusal naming no single entry, and any other cause,
	// are returned as they were.
	for _, other := range []error{
		&safefile.UnsafePrivateDACLError{Path: cause.Path},
		errors.New("plugin target must be a regular file"),
	} {
		if got := explainPluginArtifactRefusal("", other); got != other {
			t.Fatalf("changed an unrelated refusal: %v", got)
		}
	}
}
