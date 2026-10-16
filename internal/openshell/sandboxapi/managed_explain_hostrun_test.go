package sandboxapi_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestManagedExplainHostRunRefusedTruthTable pins the host-run answer for
// every gate and exemption combination: the gate wins when the gateway sent
// one, an older explain with no gate falls back to its exemption field, and a
// connector that is not listed is never refused.
func TestManagedExplainHostRunRefusedTruthTable(t *testing.T) {
	cases := []struct {
		gate     string
		exempt   bool
		listed   bool
		expected bool
	}{
		{"", false, true, true},
		{"", true, true, false},
		{"exempt", false, true, false},
		{"exempt", true, true, false},
		{"refused", false, true, true},
		{"refused", true, true, true},
		{"", false, false, false},
		{"refused", false, false, false},
	}
	for _, c := range cases {
		m := &sandboxapi.ManagedExplain{HostRunGate: c.gate, EnrollmentExempt: c.exempt}
		if c.listed {
			m.RequiredFor = []string{"claudecode"}
		}
		if got := m.HostRunRefused("claudecode"); got != c.expected {
			t.Errorf("gate=%q exempt=%v listed=%v: HostRunRefused=%v, want %v", c.gate, c.exempt, c.listed, got, c.expected)
		}
	}
	var nilExplain *sandboxapi.ManagedExplain
	if nilExplain.HostRunRefused("claudecode") {
		t.Error("a nil explain must not refuse")
	}
}
