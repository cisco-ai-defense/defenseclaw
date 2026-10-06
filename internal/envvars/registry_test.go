// Tests for the Go side of the env-var registry. Includes a
// cross-language sync test that asserts the Python loader (cli/.../
// envvars.py) sees the exact same set of entries.
package envvars

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		if e.Deprecated {
			if e.Category == CategorySecurityOptOut && e.SecurityImpact == ImpactHigh &&
				!e.SurfaceInDoctor && !e.MigrationOnly {
				t.Errorf(
					"deprecated entry %q: high-impact opt-out must be migration-only or surfaced in doctor",
					e.Name,
				)
			}
			continue
		}
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

// TestIsActive_NonEmptyValues covers the variables that carry a value rather
// than a switch (activeWhenNonEmpty; Python: _ACTIVE_WHEN_NONEMPTY).
func TestIsActive_NonEmptyValues(t *testing.T) {
	r := MustLoad()
	for name, value := range map[string]string{
		"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.50.2.100,172.16.0.5",
		"DEFENSECLAW_SANDBOX_ID":              "dcmarker-binding",
	} {
		e, ok := r.Get(name)
		if !ok {
			t.Fatalf("%s missing from registry", name)
		}
		for _, tc := range []struct {
			value string
			want  bool
		}{{"", false}, {"  ", false}, {value, true}} {
			got := e.isActiveWithGetter(func(string) string { return tc.value })
			if got != tc.want {
				t.Errorf("%s: isActive(%q) = %v, want %v", name, tc.value, got, tc.want)
			}
		}
	}
}

// A planted DEFENSECLAW_SANDBOX_ID turns sandboxing off, so doctor reports it.
func TestSandboxIDSurfacesAsSecurityOverride(t *testing.T) {
	for _, name := range MustLoad().Names() {
		t.Setenv(name, "")
	}
	t.Setenv("DEFENSECLAW_SANDBOX_ID", "dcmarker-binding")
	var names []string
	for _, e := range MustLoad().ActiveSecurityOverrides(false) {
		names = append(names, e.Name)
	}
	if len(names) != 1 || names[0] != "DEFENSECLAW_SANDBOX_ID" {
		t.Fatalf("active overrides = %v, want [DEFENSECLAW_SANDBOX_ID]", names)
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

// TestManagedIgnoredOptOutsAreReadThroughLookup keeps the managed-mode
// policy enforceable: a security opt-out that a managed standalone host
// ignores must be read with envvars.Getenv/Lookup, never os.Getenv.
func TestManagedIgnoredOptOutsAreReadThroughLookup(t *testing.T) {
	SetManagedStandalone(true)
	t.Cleanup(func() { SetManagedStandalone(false) })
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "closed")
	if got := Getenv("DEFENSECLAW_REVEAL_PII"); got != "" {
		t.Fatalf("an ignored opt-out read %q on a managed host", got)
	}
	if got := Getenv("DEFENSECLAW_FAIL_MODE"); got != "closed" {
		t.Fatalf("a tighten_only variable read %q, want the raw value", got)
	}
	if names := IgnoredNames(); len(names) != 1 || names[0] != "DEFENSECLAW_REVEAL_PII" {
		t.Fatalf("IgnoredNames = %v", names)
	}

	var ignored []string
	for _, e := range MustLoad().ByCategory(CategorySecurityOptOut) {
		if e.Managed == ManagedIgnore {
			ignored = append(ignored, regexp.QuoteMeta(e.Name))
		}
	}
	direct := regexp.MustCompile(`os\.(Getenv|LookupEnv)\("(` + strings.Join(ignored, "|") + `)"\)`)
	_, thisFile, _, _ := runtime.Caller(0)
	root, _ := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr == nil && direct.Match(raw) {
				t.Errorf("%s reads a managed-ignored opt-out with os.Getenv; use envvars.Getenv", path)
			}
			return nil
		})
	}
}

// Silence unused-import warnings when build flags strip parts of the
// file; pulls in filepath/runtime so go vet stays happy.
var _ = filepath.Join
var _ = runtime.Caller
