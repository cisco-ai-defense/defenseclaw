package setup

import (
	"errors"
	"strings"
	"testing"
)

// GAP-0882: a gate on a box without helm ran every chart test as a skip and
// looked green. With DEFENSECLAW_HELM_REQUIRED=1 a missing or unpinned helm
// fails; without it the skip says so loudly.
func TestResolveHelmFailsWhenRequiredAndSkipsLoudlyOtherwise(t *testing.T) {
	missing := func(string) (string, error) { return "", errors.New("not found") }
	found := func(string) (string, error) { return "/usr/bin/helm", nil }
	pinned := func(string) (string, error) { return helmPinnedVersion + "\n", nil }
	other := func(string) (string, error) { return "v3.12.0", nil }
	broken := func(string) (string, error) { return "", errors.New("exec failed") }
	for _, tc := range []struct {
		name       string
		required   bool
		explicit   string
		lookPath   func(string) (string, error)
		version    func(string) (string, error)
		path       string
		fail, skip bool
	}{
		{"no helm, required", true, "", missing, pinned, "", true, false},
		{"no helm, not required", false, "", missing, pinned, "", false, true},
		{"unpinned helm, required", true, "", found, other, "", true, false},
		{"unpinned helm, not required", false, "", found, other, "", false, true},
		{"helm that cannot run, required", true, "", found, broken, "", true, false},
		{"helm that cannot run, not required", false, "", found, broken, "", false, true},
		{"pinned helm", true, "", found, pinned, "/usr/bin/helm", false, false},
		{"pinned helm, not required", false, "", found, pinned, "/usr/bin/helm", false, false},
		{"explicit helm skips the lookup", true, "/opt/helm", missing, pinned, "/opt/helm", false, false},
		{"explicit helm that is unpinned, required", true, "/opt/helm", missing, other, "", true, false},
	} {
		got := resolveHelm(tc.required, tc.explicit, tc.lookPath, tc.version)
		if got.path != tc.path || (got.fail != "") != tc.fail || (got.skip != "") != tc.skip {
			t.Errorf("%s: %+v, want path=%q fail=%v skip=%v", tc.name, got, tc.path, tc.fail, tc.skip)
		}
		if tc.skip && !strings.Contains(got.skip, "DEFENSECLAW_HELM_REQUIRED=1") {
			t.Errorf("%s: the skip does not name DEFENSECLAW_HELM_REQUIRED=1: %q", tc.name, got.skip)
		}
	}
}

// The registry and the docs say the variable is 1 or unset: "0" must not make
// helm required.
func TestHelmRequiredMeansExactlyOne(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "0": false, "": false, "true": false} {
		t.Setenv("DEFENSECLAW_HELM_REQUIRED", value)
		if got := helmRequiredFromEnv(); got != want {
			t.Errorf("DEFENSECLAW_HELM_REQUIRED=%q: required = %v, want %v", value, got, want)
		}
	}
}
