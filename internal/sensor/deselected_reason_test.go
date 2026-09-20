package sensor

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

// TestDeselectedReasonNamesTheShutGate covers the configuration an operator
// most plausibly writes by hand: plane c listed, enable_host_plane left at its
// default. EffectivePlanes drops c, and the health surface has to say why in a
// way that points at the setting that is actually off.
func TestDeselectedReasonNamesTheShutGate(t *testing.T) {
	service := &Service{options: Options{Config: config.AIRuntimeConfig{
		Enabled: true,
		Planes:  []string{"a", "b", "c"},
		// EnableHostPlane deliberately false.
	}}}

	reason := service.deselectedReason(platform.PlaneC)

	if !strings.Contains(reason, "enable_host_plane") {
		t.Fatalf("reason does not name the gate that is shut: %q", reason)
	}
	if reason == "not selected in ai_discovery.runtime.planes" {
		t.Fatal("reason sends the operator to a list that already contains \"c\"")
	}
}

// TestDeselectedReasonWhenTrulyUnlisted keeps the original message for the
// case it was always right about.
func TestDeselectedReasonWhenTrulyUnlisted(t *testing.T) {
	service := &Service{options: Options{Config: config.AIRuntimeConfig{
		Enabled: true,
		Planes:  []string{"a", "b"},
	}}}

	if got, want := service.deselectedReason(platform.PlaneC), "not selected in ai_discovery.runtime.planes"; got != want {
		t.Fatalf("deselectedReason = %q, want %q", got, want)
	}
}

// TestDeselectedReasonPlaneAUnaffected pins that the new branch is plane-c
// specific; a and b have one gate each.
func TestDeselectedReasonPlaneAUnaffected(t *testing.T) {
	service := &Service{options: Options{Config: config.AIRuntimeConfig{
		Enabled: true,
		Planes:  []string{"b", "c"},
	}}}

	if got, want := service.deselectedReason(platform.PlaneA), "not selected in ai_discovery.runtime.planes"; got != want {
		t.Fatalf("deselectedReason(a) = %q, want %q", got, want)
	}
}

// TestHostPlaneRequestedWithoutOptIn pins the config predicate directly,
// including the case where the opt-in is on and nothing is misreported.
func TestHostPlaneRequestedWithoutOptIn(t *testing.T) {
	for _, test := range []struct {
		name   string
		config config.AIRuntimeConfig
		want   bool
	}{
		{name: "listed without opt-in", config: config.AIRuntimeConfig{Planes: []string{"a", "c"}}, want: true},
		{name: "listed with opt-in", config: config.AIRuntimeConfig{Planes: []string{"a", "c"}, EnableHostPlane: true}, want: false},
		{name: "not listed", config: config.AIRuntimeConfig{Planes: []string{"a", "b"}}, want: false},
		{name: "empty selection", config: config.AIRuntimeConfig{}, want: false},
		{name: "mixed case and spacing", config: config.AIRuntimeConfig{Planes: []string{" C "}}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.config.HostPlaneRequestedWithoutOptIn(); got != test.want {
				t.Fatalf("HostPlaneRequestedWithoutOptIn() = %v, want %v", got, test.want)
			}
		})
	}
}
