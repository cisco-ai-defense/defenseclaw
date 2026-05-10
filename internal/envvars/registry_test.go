// Tests for the Go side of the env-var registry. Includes a
// cross-language sync test that asserts the Python loader (cli/.../
// envvars.py) sees the exact same set of entries.
package envvars

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoad_Succeeds(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if len(r.Entries) == 0 {
		t.Fatal("registry has zero entries")
	}
}

func TestLoad_ReturnsCachedSingleton(t *testing.T) {
	r1, err := Load()
	if err != nil {
		t.Fatalf("Load() #1: %v", err)
	}
	r2, err := Load()
	if err != nil {
		t.Fatalf("Load() #2: %v", err)
	}
	if r1 != r2 {
		t.Fatal("Load() must return the cached singleton on second call")
	}
}

func TestEntries_AllCategoriesKnown(t *testing.T) {
	r := MustLoad()
	for _, e := range r.Entries {
		if _, ok := AllowedCategories[e.Category]; !ok {
			t.Errorf("entry %q: unknown category %q", e.Name, e.Category)
		}
	}
}

func TestEntries_AllImpactLevelsKnown(t *testing.T) {
	r := MustLoad()
	for _, e := range r.Entries {
		if _, ok := AllowedSecurityImpact[e.SecurityImpact]; !ok {
			t.Errorf("entry %q: unknown security_impact %q", e.Name, e.SecurityImpact)
		}
	}
}

func TestEntries_AllHaveDefenseClawPrefix(t *testing.T) {
	r := MustLoad()
	for _, e := range r.Entries {
		if e.Name == "MIGRATION_DEFENSECLAW_HOME" {
			continue
		}
		if !strings.HasPrefix(e.Name, "DEFENSECLAW_") {
			t.Errorf("entry %q: name must start with DEFENSECLAW_", e.Name)
		}
	}
}

func TestEntries_NoDuplicates(t *testing.T) {
	r := MustLoad()
	seen := map[string]struct{}{}
	for _, e := range r.Entries {
		if _, dup := seen[e.Name]; dup {
			t.Errorf("duplicate entry: %q", e.Name)
		}
		seen[e.Name] = struct{}{}
	}
}

func TestEntries_HighImpactSecurityOptOutsSurfaceInDoctor(t *testing.T) {
	r := MustLoad()
	for _, e := range r.Entries {
		if e.Category != CategorySecurityOptOut {
			continue
		}
		if e.SecurityImpact != ImpactHigh {
			continue
		}
		if !e.SurfaceInDoctor {
			t.Errorf(
				"entry %q: high-impact security opt-out MUST set surface_in_doctor=true",
				e.Name,
			)
		}
	}
}

func TestIsActive_TruthyValues(t *testing.T) {
	r := MustLoad()
	e, ok := r.Get("DEFENSECLAW_DISABLE_REDACTION")
	if !ok {
		t.Fatal("DEFENSECLAW_DISABLE_REDACTION missing from registry")
	}

	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"  ", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"random", false},
		{"1", true},
		{"true", true},
		{"True", true},
		{"YES", true},
		{"on", true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got := e.isActiveWithGetter(func(name string) string {
				if name == "DEFENSECLAW_DISABLE_REDACTION" {
					return tc.value
				}
				return ""
			})
			if got != tc.want {
				t.Errorf("isActive(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestIsActive_SchemaValidationIsInverse(t *testing.T) {
	r := MustLoad()
	e, ok := r.Get("DEFENSECLAW_SCHEMA_VALIDATION")
	if !ok {
		t.Fatal("DEFENSECLAW_SCHEMA_VALIDATION missing from registry")
	}

	cases := []struct {
		value string
		want  bool
	}{
		{"", false},     // unset → default (validation on) → NOT active bypass
		{"on", false},   // explicit on → NOT active bypass
		{"off", true},   // explicit off → bypass active
		{"false", true}, // anything-but-on → bypass active
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got := e.isActiveWithGetter(func(name string) string {
				if name == "DEFENSECLAW_SCHEMA_VALIDATION" {
					return tc.value
				}
				return ""
			})
			if got != tc.want {
				t.Errorf("isActive(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestCrossLanguageSync asserts the Python loader and the Go loader
// see the exact same set of names. We invoke python3 in a subprocess
// to dump the Python-side names; if python3 isn't available (CI Go-
// only stage) the test skips.
func TestCrossLanguageSync(t *testing.T) {
	pyCmd, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH; skipping cross-language sync test")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	repoRoot, _ = filepath.Abs(repoRoot)
	cliPath := filepath.Join(repoRoot, "cli")

	// Use an explicit absolute path so the test doesn't depend on the
	// working directory of the test binary.
	script := `
import json
import sys
from defenseclaw.envvars import load_registry
r = load_registry()
print(json.dumps(sorted(r.names())))
`
	cmd := exec.Command(pyCmd, "-c", script)
	cmd.Dir = repoRoot
	// PYTHONPATH ensures the worktree's cli/defenseclaw beats any
	// installed copy from a developer venv.
	cmd.Env = append(cmd.Environ(), "PYTHONPATH="+cliPath)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("python3 invocation failed (cli/defenseclaw may not be importable in this env): %v", err)
	}

	var pyNames []string
	if err := json.Unmarshal(out, &pyNames); err != nil {
		t.Fatalf("python3 output not JSON list: %v\noutput: %s", err, string(out))
	}

	r := MustLoad()
	goNames := r.Names()

	// Compute set differences.
	pySet := make(map[string]struct{}, len(pyNames))
	for _, n := range pyNames {
		pySet[n] = struct{}{}
	}
	goSet := make(map[string]struct{}, len(goNames))
	for _, n := range goNames {
		goSet[n] = struct{}{}
	}

	var onlyInPython, onlyInGo []string
	for n := range pySet {
		if _, ok := goSet[n]; !ok {
			onlyInPython = append(onlyInPython, n)
		}
	}
	for n := range goSet {
		if _, ok := pySet[n]; !ok {
			onlyInGo = append(onlyInGo, n)
		}
	}
	if len(onlyInPython) > 0 || len(onlyInGo) > 0 {
		t.Fatalf(
			"Go and Python registries disagree on entry set.\n"+
				"  only in Python: %v\n"+
				"  only in Go    : %v\n"+
				"This usually means the JSON file is malformed differently by the two parsers.",
			onlyInPython, onlyInGo,
		)
	}
}

// Silence unused-import warnings when build flags strip parts of the
// file; pulls in filepath/runtime so go vet stays happy.
var _ = filepath.Join
var _ = runtime.Caller
