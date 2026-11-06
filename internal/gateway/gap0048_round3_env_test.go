package gateway

import (
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"testing"
)

func TestGAP0048Round3OrdinaryEnvironment(t *testing.T) {
	for _, key := range []string{"PATH", "HOME", "PYTHONPATH", "NODE_PATH"} {
		before := `{"env":{"DEBUG":"1"}}`
		after := `{"env":{"DEBUG":"1","` + key + `":"/tmp/ordinary"}}`
		if got := agentHookConfigTurnsOff(gatewayconnector.AgentHookConfigClaudeSettings, []byte(before), true, []byte(after), true); got != "" {
			t.Errorf("%s: ordinary env edit graded as Named: %s", key, got)
		}
	}
}

func TestGAP0048Round3ObjectValues(t *testing.T) {
	rows := []struct{ name, format, before, after string }{
		{"Claude object env", gatewayconnector.AgentHookConfigClaudeSettings, `{"env":{"PATH":{"a":1}}}`, `{"env":{"PATH":{"a":1}},"model":"y"}`},
		{"Kiro object agent", gatewayconnector.AgentHookConfigKiroSettings, `{"chat.defaultAgent":{"a":1}}`, `{"chat.defaultAgent":{"a":1},"x":1}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := agentHookConfigTurnsOff(row.format, []byte(row.before), true, []byte(row.after), true); got != "" {
				t.Errorf("ordinary edit graded as disabling: %s", got)
			}
		})
	}
}
