// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelaxAncestorTrustVerdictKeepsLeafFatal(t *testing.T) {
	verdict := errors.New("untrusted principal")
	captured := captureTrustAdvisories(t)

	if err := relaxAncestorTrustVerdict(false, `C:\ProgramData\Cisco`, "managed config", verdict); err == nil {
		t.Fatal("leaf verdict was relaxed")
	}
	if len(*captured) != 0 {
		t.Fatalf("leaf verdict reported an advisory: %v", *captured)
	}
}

func TestRelaxAncestorTrustVerdictWarnsAndContinuesForAncestors(t *testing.T) {
	captured := captureTrustAdvisories(t)

	err := relaxAncestorTrustVerdict(
		true,
		`C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`,
		"managed config",
		errors.New("untrusted Windows principal S-1-5-21-1-2-3-1001 has write-like access mask 0x1f01ff"),
	)
	if err != nil {
		t.Fatalf("ancestor verdict was fatal: %v", err)
	}
	if len(*captured) != 1 {
		t.Fatalf("advisories = %v, want exactly one", *captured)
	}
	advisory := (*captured)[0]
	if !strings.Contains(advisory, "DefenseClaw") ||
		!strings.Contains(advisory, "managed config") ||
		!strings.Contains(advisory, "0x1f01ff") {
		t.Fatalf("advisory %q lost the path, label, or reason", advisory)
	}
}

func TestRelaxAncestorTrustVerdictHonoursStrictPin(t *testing.T) {
	for _, value := range []string{"1", "true", "YES", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, value)
			captured := captureTrustAdvisories(t)
			if err := relaxAncestorTrustVerdict(true, "/opt/cisco", "managed config", errors.New("boom")); err == nil {
				t.Fatal("strict pin relaxed an ancestor verdict")
			}
			if len(*captured) != 0 {
				t.Fatalf("strict pin reported an advisory: %v", *captured)
			}
		})
	}
	t.Run("off", func(t *testing.T) {
		t.Setenv(TrustStrictAncestorsEnv, "0")
		captureTrustAdvisories(t)
		if err := relaxAncestorTrustVerdict(true, "/opt/cisco", "managed config", errors.New("boom")); err != nil {
			t.Fatalf("explicit off value kept the ancestor verdict fatal: %v", err)
		}
	})
}

// Structural and OS API failures never become advisories, even for an ancestor:
// only judgements tagged as trustVerdict are downgradable.
func TestRelaxAncestorTrustJudgementPassesThroughNonVerdicts(t *testing.T) {
	captured := captureTrustAdvisories(t)

	structural := errors.New("/opt/cisco: no such file or directory")
	if err := relaxAncestorTrustJudgement(true, "/opt/cisco", "managed config", structural); !errors.Is(err, structural) {
		t.Fatalf("relaxAncestorTrustJudgement error = %v, want the structural failure", err)
	}
	if len(*captured) != 0 {
		t.Fatalf("structural failure reported an advisory: %v", *captured)
	}

	judgement := newTrustVerdict("/opt/cisco has write-capable macOS ACL entry")
	if err := relaxAncestorTrustJudgement(true, "/opt/cisco", "managed config", judgement); err != nil {
		t.Fatalf("ancestor judgement was fatal: %v", err)
	}
	if len(*captured) != 1 {
		t.Fatalf("advisories = %v, want exactly one", *captured)
	}
	if err := relaxAncestorTrustJudgement(false, "/opt/cisco", "managed config", judgement); err == nil {
		t.Fatal("leaf judgement was relaxed")
	}
}

func captureTrustAdvisories(t *testing.T) *[]string {
	t.Helper()
	advisories := make([]string, 0, 4)
	previous := ReportTrustAdvisory
	ReportTrustAdvisory = func(path, label, reason string) {
		advisories = append(advisories, strings.Join([]string{path, label, reason}, " | "))
	}
	t.Cleanup(func() { ReportTrustAdvisory = previous })
	return &advisories
}

func TestPlatformInstallerOwnedPath(t *testing.T) {
	roots := PlatformInstallerOwnedRoots()
	if len(roots) == 0 {
		t.Fatal("no platform installer roots for this GOOS")
	}
	for _, root := range roots {
		if !PlatformInstallerOwnedPath(root) {
			t.Errorf("PlatformInstallerOwnedPath(%q) = false for its own root", root)
		}
		child := filepath.Join(root, "Cisco Secure Client", "DefenseClaw")
		if !PlatformInstallerOwnedPath(child) {
			t.Errorf("PlatformInstallerOwnedPath(%q) = false, want true", child)
		}
		// A sibling that merely shares the root's prefix is not inside it.
		if PlatformInstallerOwnedPath(root + "-evil") {
			t.Errorf("PlatformInstallerOwnedPath(%q) = true for a prefix sibling", root+"-evil")
		}
		if parent := filepath.Dir(root); PlatformInstallerOwnedPath(parent) {
			t.Errorf("PlatformInstallerOwnedPath(%q) = true for the root's own parent", parent)
		}
	}
	if PlatformInstallerOwnedPath("") {
		t.Error("empty path reported as platform-installer owned")
	}
}

func TestRelaxAncestorTrustJudgementOnlyDowngradesTaggedVerdicts(t *testing.T) {
	advisories := captureTrustAdvisories(t)
	// A judgement from a helper that also reports exec failures.
	if err := RelaxAncestorTrustJudgement(true, "/opt/cisco", "hook API token path",
		NewTrustVerdict("/opt/cisco has write-capable macOS ACL entry")); err != nil {
		t.Fatalf("tagged verdict was not downgraded: %v", err)
	}
	if len(*advisories) != 1 {
		t.Fatalf("advisories = %v, want exactly one", *advisories)
	}
	// An exec/read failure from the same helper must survive.
	execFailure := errors.New("inspect macOS ACL for /opt/cisco: signal: killed")
	if err := RelaxAncestorTrustJudgement(true, "/opt/cisco", "hook API token path", execFailure); err == nil {
		t.Fatal("exec failure was swallowed as an advisory")
	}
	if len(*advisories) != 1 {
		t.Fatalf("exec failure emitted an advisory: %v", *advisories)
	}
}
