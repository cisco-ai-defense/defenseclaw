//go:build !windows

package enterpriseunix

import "testing"

func TestCompareProductVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.1", "1.0.1", 0},
		{"1.0.1", "1.0.2", -1},
		{"1.10.0", "1.9.9", 1},
		{"1.0.1-m10b.8", "1.0.1-m10b.10", -1},
		{"1.0.1-rc1", "1.0.1", -1},
		{"v2.0.0+build.7", "2.0.0", 0},
	} {
		if got := compareProductVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// Installing a payload older than the recorded deployment is refused unless
// the administrator asks for a deliberate rollback.
func TestDowngradeIsRefusedWithoutAllowDowngrade(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}))
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.1")}), codeDowngrade)
			requireError(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}), codeDowngrade)
			record, _ := h.env.loadDeployment()
			if record.ProductVersion != "1.0.2" {
				t.Fatalf("refused downgrade changed the record: %s", record.ProductVersion)
			}
			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.1"), AllowDowngrade: true})
			requireOK(t, r)
			if r.InstalledVersion != "1.0.1" {
				t.Fatalf("deliberate rollback installed %q", r.InstalledVersion)
			}
		})
	}
}
