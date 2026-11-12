package gateway

import (
	"testing"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestAgentHookConfigObjectValuesCompareWithoutPanic(t *testing.T) {
	for _, c := range []struct{ name, format, before, after string }{
		{"claude env map value", gatewayconnector.AgentHookConfigClaudeSettings, `{"env":{"PATH":{"a":1}}}`, `{"env":{"PATH":{"a":1}},"model":"y"}`},
		{"kiro defaultAgent map value", gatewayconnector.AgentHookConfigKiroSettings, `{"chat.defaultAgent":{"a":1}}`, `{"chat.defaultAgent":{"a":1},"x":1}`},
	} {
		got := agentHookConfigTurnsOff(c.format, []byte(c.before), true, []byte(c.after), true)
		if got != "" {
			t.Errorf("%s: ordinary edit was classified as disabling: %s", c.name, got)
		}
	}
}
