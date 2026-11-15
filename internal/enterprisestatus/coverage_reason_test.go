// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0812: a managed Windows ensure reported coverage_complete
// false with no reason (enrollment_failed was recorded, but Finish named
// coverage reasons only on Linux and macOS). Every OS names them now.
func TestFinishNamesWhyCoverageIsIncompleteOnEveryOS(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		r := New("ensure", "standalone", goos, "1.0.10")
		r.Installed = true
		r.ResetCompleteness()
		r.MarkCoverageIncomplete("enrollment_failed")
		r.MarkCoverageIncomplete("machine_policy_not_covered")
		r.Finish(goos, 0)
		if r.CoverageComplete || len(r.CoverageReasons()) != 2 {
			t.Fatalf("%s: coverage %t reasons %q", goos, r.CoverageComplete, r.CoverageReasons())
		}
		named := ""
		for _, warning := range r.Warnings {
			if strings.Contains(warning.Message, "coverage_complete is false because of: enrollment_failed, machine_policy_not_covered") {
				named = warning.Code
			}
		}
		want := CodeSecurityIncomplete
		if goos == "windows" {
			want = CodeCoverageIncomplete
		}
		if named != want {
			t.Fatalf("%s: warnings %+v, want %s to name the coverage reasons", goos, r.Warnings, want)
		}
		// Finishing again (Setup re-encodes a child result) keeps one line.
		r.Finish(goos, 0)
		count := 0
		for _, warning := range r.Warnings {
			if warning.Code == want {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: %d %s warnings after a second Finish", goos, count, want)
		}
	}
	// A complete result, and one that is not installed (installed:false
	// says why), carry no coverage_incomplete line.
	complete := New("status", "standalone", "windows", "1.0.10")
	complete.Installed = true
	complete.ResetCompleteness()
	complete.Finish("windows", 0)
	absent := New("status", "standalone", "windows", "1.0.10")
	absent.ResetCompleteness()
	absent.MarkCoverageIncomplete("DefenseClaw is not installed")
	absent.Finish("windows", 0)
	for _, r := range []*Result{complete, absent} {
		for _, warning := range r.Warnings {
			if warning.Code == CodeCoverageIncomplete {
				t.Fatalf("unexpected coverage_incomplete: %+v", r)
			}
		}
	}
}

// coverage_complete is set false only by MarkCoverageIncomplete, which
// records the reason: a direct assignment outside this file is how a false
// with no reason came back (GAP-0812). The check reads every non-test Go
// file of internal/ and cmd/.
func TestCoverageCompleteIsSetFalseOnlyWithAReason(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	assignment := regexp.MustCompile(`\.CoverageComplete\s*(,\s*[\w.]+\s*)*=[^=]|CoverageComplete:\s*false`)
	var offenders []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				path == filepath.Join(root, "internal", "enterprisestatus", "result.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for number, line := range strings.Split(string(data), "\n") {
				if assignment.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel+":"+strconv.Itoa(number+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("coverage_complete set outside MarkCoverageIncomplete/ResetCompleteness, so a false names no reason:\n%s", strings.Join(offenders, "\n"))
	}
}
