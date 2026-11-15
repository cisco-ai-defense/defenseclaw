// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// Text that is not typed by the user; none of it may reach the router.
var routeContextForbidden = []string{"SECRET_ARG", "TOOL_OUTPUT", "REMINDER", "FILE_CONTENTS", "SYSTEM_PROMPT", "ASSISTANT_TEXT"}

func routeContextTestConfig(c config.RoutingContextConfig) *config.Config {
	cfg := &config.Config{}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules, Context: c,
		Models: []config.RoutingModelBackend{
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
			{Name: "big", Provider: "ollama", Model: "qwen3", BaseURL: "http://127.0.0.1:11434"},
		},
		Signals: config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "deploy", Keywords: []string{"deploy"}}}},
		Decisions: []config.RoutingDecisionRule{
			{Name: "deploy", Priority: 10, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "deploy"}}, ModelRefs: []string{"big"}},
			{Name: "default", ModelRefs: []string{"local"}},
		},
	}
	return cfg
}

func routeContextEngine(t *testing.T, c config.RoutingContextConfig) *engine.Engine {
	t.Helper()
	cfg := routeContextTestConfig(c)
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, engine.Options{})
	if err != nil || eng == nil {
		t.Fatalf("engine.New = %v, %v", eng, err)
	}
	return eng
}

var allContext = config.RoutingContextConfig{RecentUserTurns: 2, IncludeFirstUserTurn: true, IncludeToolNames: true}

func TestRouteContextReadsOnlyHumanTextAndToolNames(t *testing.T) {
	eng := routeContextEngine(t, allContext)
	for _, tc := range []struct {
		name, family, body string
		older, tools       []string
	}{
		{"messages", config.RoutingAPIMessages, `{"system":"SYSTEM_PROMPT","messages":[
{"role":"user","content":"first task: deploy api"},
{"role":"assistant","content":[{"type":"text","text":"ASSISTANT_TEXT"},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"SECRET_ARG"}}]},
{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"TOOL_OUTPUT"}]},
{"role":"user","content":[{"type":"text","text":"<system-reminder>REMINDER</system-reminder>second ask"}]},
{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{}}]},
{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"FILE_CONTENTS"}]}]},
{"role":"user","content":"third ask"}]}`, []string{"second ask", "first task: deploy api"}, []string{"Bash", "Read"}},
		{"chat", config.RoutingAPIChat, `{"messages":[{"role":"system","content":"SYSTEM_PROMPT"},{"role":"user","content":"first task"},
{"role":"assistant","content":"ASSISTANT_TEXT","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SECRET_ARG\"}"}}]},
{"role":"tool","tool_call_id":"c1","content":"TOOL_OUTPUT"},{"role":"user","content":"newest"}]}`, []string{"first task"}, []string{"get_weather"}},
		{"responses", config.RoutingAPIResponses, `{"instructions":"SYSTEM_PROMPT","input":[{"type":"message","role":"developer","content":"SYSTEM_PROMPT"},
{"type":"message","role":"user","content":[{"type":"input_text","text":"first task"}]},
{"type":"function_call","name":"shell","arguments":"SECRET_ARG","call_id":"c1"},
{"type":"function_call_output","call_id":"c1","output":"TOOL_OUTPUT"},
{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ASSISTANT_TEXT"}]},
{"role":"user","content":"newest"}]}`, []string{"first task"}, []string{"shell"}},
		{"converse", config.RoutingAPIConverse, `{"system":[{"text":"SYSTEM_PROMPT"}],"messages":[{"role":"user","content":[{"text":"first task"}]},
{"role":"assistant","content":[{"text":"ASSISTANT_TEXT"},{"toolUse":{"toolUseId":"1","name":"lookup","input":{"q":"SECRET_ARG"}}}]},
{"role":"user","content":[{"toolResult":{"toolUseId":"1","content":[{"text":"TOOL_OUTPUT"}]}}]},
{"role":"user","content":[{"text":"newest"}]}]}`, []string{"first task"}, []string{"lookup"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &ModelRouterInput{APIFamily: tc.family, Body: []byte(tc.body)}
			req := engineRequest(in)
			routeContext(eng, in, &req)
			checkRouteContext(t, req, tc.older, tc.tools)
			if tc.family != config.RoutingAPIChat {
				return
			}
			// The chat route hands the parsed messages instead of the body.
			var parsed struct {
				Messages []ChatMessage `json:"messages"`
			}
			if err := json.Unmarshal([]byte(tc.body), &parsed); err != nil {
				t.Fatal(err)
			}
			in = &ModelRouterInput{Messages: parsed.Messages}
			req = engineRequest(in)
			routeContext(eng, in, &req)
			checkRouteContext(t, req, tc.older, tc.tools)
		})
	}
}

func TestRouteDetailedUsesTheRoutingContext(t *testing.T) {
	in := func() *ModelRouterInput {
		return &ModelRouterInput{Model: "m", RequestModel: "m", Messages: []ChatMessage{
			{Role: "user", Content: "please deploy the api"}, {Role: "assistant", Content: "ok"}, {Role: "user", Content: "yes, go ahead"},
		}}
	}
	alias := func(o SemanticRouteOutcome) string {
		if o.Route == nil || o.Route.Backend == nil {
			return ""
		}
		return o.Route.Backend.Alias
	}
	off := newEngineRouter(routeContextTestConfig(config.RoutingContextConfig{}), nil, "")
	if got := alias(off.RouteDetailed(context.Background(), in())); got != "local" {
		t.Fatalf("context off routed to %q, want local (newest turn only)", got)
	}
	on := newEngineRouter(routeContextTestConfig(config.RoutingContextConfig{RecentUserTurns: 1}), nil, "")
	if got := alias(on.RouteDetailed(context.Background(), in())); got != "big" {
		t.Fatalf("context on routed to %q, want big from the older turn", got)
	}
	cut := newEngineRouter(routeContextTestConfig(config.RoutingContextConfig{RecentUserTurns: 1, MaxBytes: 16, PerTurnBytes: 16}), nil, "")
	out := cut.RouteDetailed(context.Background(), in())
	if out.Route == nil || !slices.Contains(out.Route.Warnings, "context_truncated:bytes") {
		t.Fatalf("a cut context records no warning: %+v", out.Route)
	}
}

func TestRouteContextOffCostsNothing(t *testing.T) {
	eng := routeContextEngine(t, config.RoutingContextConfig{MaxBytes: 4096})
	if eng.ContextCollector() != nil {
		t.Fatal("an inactive routing.context hands out a collector")
	}
	in := &ModelRouterInput{APIFamily: config.RoutingAPIMessages, Body: []byte(`{"messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`)}
	req := engineRequest(in)
	if allocs := testing.AllocsPerRun(100, func() { routeContext(eng, in, &req) }); allocs != 0 {
		t.Fatalf("routeContext with routing.context off allocates %v times", allocs)
	}
	if req.ContextTurns != nil || req.ToolLoop || req.FirstTurn != "" || req.ToolNames != nil {
		t.Fatalf("routing.context off filled %+v", req)
	}
}

// Agent-injected user-role text (instruction files, environment context,
// command output, compaction summaries, IDE context, the OpenClaw context
// message) never reaches the router text or the signal matcher. Every
// injected text says deploy; only typed text may decide.
func TestRouteContextSkipsInjectedUserText(t *testing.T) {
	cfg := routeContextTestConfig(config.RoutingContextConfig{RecentUserTurns: 8, IncludeFirstUserTurn: true})
	eng, err := engine.New(cfg, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	injected := []string{
		"# AGENTS.md instructions for /repo\n<INSTRUCTIONS>deploy</INSTRUCTIONS>",
		"<environment_context>\n<cwd>/deploy</cwd>\n</environment_context>",
		"<user_instructions>deploy</user_instructions>",
		"This session is being continued from a previous conversation. Summary: deploy",
		"Caveat: The messages below were generated by the user while running local commands. deploy",
		"<command-name>/deploy</command-name>", "<local-command-stdout>deploy</local-command-stdout>",
		"<bash-stdout>deploy</bash-stdout>", "<user-prompt-submit-hook>deploy</user-prompt-submit-hook>",
		"Contents of /repo/CLAUDE.md:\ndeploy", "<ide_selection>deploy</ide_selection>",
		"<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>deploy<<<END_OPENCLAW_INTERNAL_CONTEXT>>>",
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	var chat, msgs, resp, conv []string
	for _, s := range injected {
		chat = append(chat, `{"role":"user","content":`+q(s)+`}`)
		msgs = append(msgs, `{"role":"user","content":[{"type":"text","text":`+q(s)+`},{"type":"text","text":"<system-reminder>deploy</system-reminder>"}]}`)
		resp = append(resp, `{"type":"message","role":"user","content":[{"type":"input_text","text":`+q(s)+`}]}`)
		conv = append(conv, `{"role":"user","content":[{"text":`+q(s)+`}]}`)
	}
	typed := func(items []string, open, item string) string {
		all := append([]string{strings.ReplaceAll(item, "TEXT", "first typed")}, items...)
		all = append(all, strings.ReplaceAll(item, "TEXT", "hello there"))
		return open + strings.Join(all, ",") + "]}"
	}
	for _, tc := range []struct{ family, body string }{
		{config.RoutingAPIChat, typed(chat, `{"messages":[`, `{"role":"user","content":"TEXT"}`)},
		{config.RoutingAPIMessages, typed(msgs, `{"messages":[`, `{"role":"user","content":[{"type":"text","text":"TEXT"}]}`)},
		{config.RoutingAPIResponses, typed(resp, `{"input":[`, `{"type":"message","role":"user","content":[{"type":"input_text","text":"TEXT"}]}`)},
		{config.RoutingAPIConverse, typed(conv, `{"messages":[`, `{"role":"user","content":[{"text":"TEXT"}]}`)},
	} {
		in := &ModelRouterInput{APIFamily: tc.family, Body: []byte(tc.body), Text: injected[len(injected)-1]}
		req := engineRequest(in)
		routeContext(eng, in, &req)
		if req.Text != "hello there" || !slices.Equal(req.ContextTurns, []string{"first typed"}) {
			t.Fatalf("%s: text %q context %q, want only the typed turns", tc.family, req.Text, req.ContextTurns)
		}
		if d := eng.Decide(context.Background(), req); d.RuleID == "deploy" {
			t.Fatalf("%s: injected text reached the signal matcher: %+v", tc.family, d)
		}
	}
}

// P1-2: on passthrough in.Text is the guardrail extractor answer (here the
// reminder of a tool_result turn); with routing.context the newest typed
// prompt comes from the context extractor, present exactly once.
func TestRouteContextNewestTurnComesFromTheCollector(t *testing.T) {
	eng := routeContextEngine(t, config.RoutingContextConfig{RecentUserTurns: 2})
	body := `{"messages":[{"role":"user","content":"fix the deploy script"},
{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{}}]},
{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"TOOL_OUTPUT"},{"type":"text","text":"<system-reminder>REMINDER</system-reminder>"}]}]}`
	in := &ModelRouterInput{APIFamily: config.RoutingAPIMessages, Body: []byte(body), Text: "<system-reminder>REMINDER</system-reminder>"}
	req := engineRequest(in)
	if req.Text != "" {
		t.Fatalf("a reminder-only candidate reached the router text: %q", req.Text)
	}
	routeContext(eng, in, &req)
	all := strings.Join(append([]string{req.Text, req.FirstTurn}, req.ContextTurns...), "|")
	if req.Text != "fix the deploy script" || strings.Count(all, "fix the deploy script") != 1 || strings.Contains(all, "REMINDER") {
		t.Fatalf("newest %q, context %q", req.Text, req.ContextTurns)
	}
}

func checkRouteContext(t *testing.T, req engine.Request, older, tools []string) {
	t.Helper()
	if !slices.Equal(req.ContextTurns, older) || !slices.Equal(req.ToolNames, tools) || !req.ToolLoop || req.FirstTurn != "" {
		t.Fatalf("context = %q first %q tools %q loop %v, want %q %q", req.ContextTurns, req.FirstTurn, req.ToolNames, req.ToolLoop, older, tools)
	}
	seen := strings.Join(append(append(slices.Clone(req.ContextTurns), req.FirstTurn, req.Text), req.ToolNames...), "|")
	for _, bad := range routeContextForbidden {
		if strings.Contains(seen, bad) {
			t.Fatalf("router context carries %s: %q", bad, seen)
		}
	}
}
