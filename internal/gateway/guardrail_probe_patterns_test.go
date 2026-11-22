package gateway

import "testing"

// TestCanonicalProbePatternsMatchTheirSentences pins the constant probe
// patterns to OpenClaw's canonical sentences: rebuilt from the sentences with
// canonicalProbeSentence, each must be exactly the constant the gateway
// compiles. The constants exist because lazyregexp patterns may not be built
// at run time (TestEveryModulePatternCompiles).
func TestCanonicalProbePatternsMatchTheirSentences(t *testing.T) {
	heartbeat := `(?i)\bRead\s+HEARTBEAT\.md` +
		`(?:\s+if\s+it\s+exists)?(?:\s*\(workspace\s+context\))?\s*\.` +
		`(?:\s+` + canonicalProbeSentence("Follow it strictly.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("Do not infer or repeat old tasks from prior chats.") + `)?` +
		`\s+` + canonicalProbeSentence("If nothing needs attention, reply HEARTBEAT_OK") + `\b\.?`
	session := `(?i)\bA\s+new\s+session\s+was\s+started\s+via\s+/new\s+or\s+/reset` +
		`(?:\.|\s+while\s+bootstrap\s+is\s+still\s+pending\s+for\s+this\s+workspace\.)` +
		`(?:\s+` + canonicalProbeSentence("Execute your Session Startup sequence now - read the required files before responding to the user.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("If BOOTSTRAP.md exists in the provided Project Context, read it and follow its instructions first.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("Then greet the user in your configured persona, if one is provided.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("Be yourself - use your defined voice, mannerisms, and mood.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("Keep it to 1-3 sentences and ask what they want to do.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("If the runtime model differs from default_model in the system prompt, mention the default model.") + `)?` +
		`(?:\s+` + canonicalProbeSentence("Do not mention internal steps, files, tools, or reasoning.") + `)?`
	if heartbeat != heartbeatProbePattern {
		t.Fatalf("heartbeatProbePattern no longer matches its canonical sentences:\n got %s\nwant %s", heartbeatProbePattern, heartbeat)
	}
	if session != sessionStartupProbePattern {
		t.Fatalf("sessionStartupProbePattern no longer matches its canonical sentences:\n got %s\nwant %s", sessionStartupProbePattern, session)
	}
}
