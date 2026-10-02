package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// A fix whose command is "doctor --fix" names it once (GAP-1654).
func TestPrintDoctorNamesTheFixCommandOnce(t *testing.T) {
	ta := newTestApp(t, "")
	ta.printDoctor(&openshell.DoctorReport{Checks: []openshell.Check{
		{Title: "Gateway compute driver", Status: openshell.StatusFail, Detail: `this gateway runs "podman"`,
			Fix: &openshell.Fix{Summary: "switch the gateway to the docker compute driver", Command: CommandName + " doctor --fix", Automatic: true}},
		{Title: "Gateway", Status: openshell.StatusWarn, Detail: "stale",
			Fix: &openshell.Fix{Summary: "restart the gateway", Command: "systemctl --user restart openshell-gateway", Automatic: true}},
	}})
	out := ta.output()
	has(t, out, "→ switch the gateway to the docker compute driver: defenseclaw sandbox doctor --fix",
		"restart the gateway: systemctl --user restart openshell-gateway  (defenseclaw sandbox doctor --fix)")
	if n := strings.Count(out, "doctor --fix"); n != 2 {
		t.Errorf("doctor --fix named %d times, want 2:\n%s", n, out)
	}
}
