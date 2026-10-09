// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"errors"
	"log"
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

// TestReportTrustAdvisoryDedupesRepeatedTuplesOnDefaultLog pins the
// dedupe-per-(path, label, reason) contract on the default log path. The
// hook-guardian reconciles every 5 s; without dedupe the same
// managed_trust_ancestor_advisory line would appear 12 times per minute for
// every host whose /opt/cisco is 0775. Emit each unique tuple once, swallow
// the rest, until either the tuple changes (reason differs) or the process
// restarts (dedupe state is process-scoped).
func TestReportTrustAdvisoryDedupesRepeatedTuplesOnDefaultLog(t *testing.T) {
	// Force the default log path (no embedder hook).
	prevHook := ReportTrustAdvisory
	ReportTrustAdvisory = nil
	t.Cleanup(func() { ReportTrustAdvisory = prevHook })

	advisoryLogDedupe.reset()
	t.Cleanup(func() { advisoryLogDedupe.reset() })

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0) // strip timestamp for stable line counts
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	same := func() { reportTrustAdvisory("/opt/cisco", "managed config", "group/other writable 0775") }

	// First call emits.
	same()
	firstCount := strings.Count(buf.String(), TrustAdvisoryMarker)
	if firstCount != 1 {
		t.Fatalf("first emission count = %d, want 1", firstCount)
	}

	// Repeated calls with the SAME tuple are swallowed.
	for i := 0; i < 10; i++ {
		same()
	}
	if got := strings.Count(buf.String(), TrustAdvisoryMarker); got != 1 {
		t.Fatalf("after 10 repeated tuples: emission count = %d, want 1 (dedupe leaked %d extras)", got, got-1)
	}

	// A DIFFERENT path is a distinct tuple — emits.
	reportTrustAdvisory("/opt/cisco/secureclient", "managed config", "group/other writable 0775")
	if got := strings.Count(buf.String(), TrustAdvisoryMarker); got != 2 {
		t.Fatalf("distinct-path emission count = %d, want 2", got)
	}

	// A DIFFERENT label is a distinct tuple — emits.
	reportTrustAdvisory("/opt/cisco", "audit store database directory", "group/other writable 0775")
	if got := strings.Count(buf.String(), TrustAdvisoryMarker); got != 3 {
		t.Fatalf("distinct-label emission count = %d, want 3", got)
	}

	// A DIFFERENT reason (mode drifted 0775 -> 0777) is a distinct tuple — emits.
	reportTrustAdvisory("/opt/cisco", "managed config", "group/other writable 0777")
	if got := strings.Count(buf.String(), TrustAdvisoryMarker); got != 4 {
		t.Fatalf("distinct-reason emission count = %d, want 4 (state-change advisories MUST re-emit)", got)
	}

	// Reset simulates a process restart — the first fire after reset emits again.
	advisoryLogDedupe.reset()
	same()
	if got := strings.Count(buf.String(), TrustAdvisoryMarker); got != 5 {
		t.Fatalf("post-reset emission count = %d, want 5 (process restart MUST re-emit)", got)
	}
}

// TestReportTrustAdvisoryEmbedderHookBypassesDedupe pins that a custom
// ReportTrustAdvisory hook sees EVERY occurrence — the default-log dedupe is
// only for the process's own line-oriented output. Embedders (structured log,
// telemetry) have richer context and are expected to dedupe themselves if
// they want to.
func TestReportTrustAdvisoryEmbedderHookBypassesDedupe(t *testing.T) {
	advisoryLogDedupe.reset()
	t.Cleanup(func() { advisoryLogDedupe.reset() })

	advisories := captureTrustAdvisories(t)
	for i := 0; i < 5; i++ {
		reportTrustAdvisory("/opt/cisco", "managed config", "group/other writable 0775")
	}
	if len(*advisories) != 5 {
		t.Fatalf("embedder hook saw %d advisories, want 5 (hook path must NOT be deduped)", len(*advisories))
	}
}
