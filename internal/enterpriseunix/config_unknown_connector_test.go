//go:build linux || darwin

package enterpriseunix

import (
	"strings"
	"testing"
)

// GAP-2337: Linux ensure applied a guardrail.connectors key that names no
// connector (a misspelled agent) with ok true and no warning, so the
// administrator believed that agent was protected. It is refused with
// config_invalid before anything changes, as Windows Setup does (GAP-0723);
// real connector names, their aliases and a retired connector the loader
// drops still apply.
func TestEnsureRefusesAGuardrailConnectorThatNamesNoConnector(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			for name, block := range map[string]string{
				"nosuchagent": "  mode: observe\n  connectors:\n    codex: {}\n    nosuchagent: {}\n",
				"claudcode":   "  mode: observe\n  connectors:\n    claudcode: {}\n",
				"cursorr":     "  mode: observe\n  connector: cursorr\n",
			} {
				cfg := writeChangedConfig(t, h, "  mode: observe\n", block)
				r := h.run(Options{Action: ActionEnsure, ConfigFile: cfg})
				requireError(t, r, codeConfig)
				msg := r.Errors[len(r.Errors)-1].Message
				if !strings.Contains(msg, `guardrail connector "`+name+`" is not a DefenseClaw connector`) || !strings.Contains(msg, cfg) || !strings.Contains(msg, "claudecode, codex") {
					t.Fatalf("%s: the refusal must name the entry, the file and the real names: %q", name, msg)
				}
				if strings.Contains(h.read(h.env.Layout.ConfigPath), name) {
					t.Fatalf("%s: the config with the unknown connector was installed", name)
				}
			}
			good := writeChangedConfig(t, h, "  mode: observe\n", "  mode: observe\n  connectors:\n    claude-code: {}\n    codex: {}\n    openhands: {}\n")
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: good}))
		})
	}
}
