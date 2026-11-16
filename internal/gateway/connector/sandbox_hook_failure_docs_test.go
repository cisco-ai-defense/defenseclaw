// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sandboxConnectorDocNames are the names the docs give each sandbox connector.
var sandboxConnectorDocNames = map[string]string{
	"amp":         "Amp",
	"antigravity": "Antigravity",
	"claudecode":  "Claude Code",
	"codex":       "Codex",
	"copilot":     "GitHub Copilot",
	"cursor":      "Cursor",
	"devin":       "Devin",
	"hermes":      "Hermes",
	"kiro":        "Kiro",
	"opencode":    "OpenCode",
}

// sandboxPlugin is a sandbox connector whose hooks are an in-agent plugin
// rather than shell hooks, with its rendered plugin source.
type sandboxPlugin struct {
	connector, name, source string
}

// sandboxPlugins renders every sandbox overlay. It checks that exactly the
// shell hooks write hook-failures.jsonl and returns the plugin connectors
// (no shell hook, no record), sorted by docs name.
func sandboxPlugins(t *testing.T) []sandboxPlugin {
	t.Helper()
	var plugins []sandboxPlugin
	for _, tc := range sandboxGoldenTargets {
		name, ok := sandboxConnectorDocNames[tc.connector]
		if !ok {
			t.Fatalf("%s: add the connector's docs name to sandboxConnectorDocNames", tc.connector)
		}
		shell, logs := false, false
		var source strings.Builder
		for _, file := range renderSandboxGolden(t, tc.provider, tc.version).Files {
			shell = shell || strings.HasSuffix(file.Path, ".sh")
			logs = logs || bytes.Contains(file.Data, []byte("hook-failures.jsonl"))
			source.Write(file.Data)
			source.WriteByte('\n')
		}
		if shell != logs {
			t.Fatalf("%s: shell hook set %v, writes hook-failures.jsonl %v: the page says only the shell hooks log", tc.connector, shell, logs)
		}
		if !logs {
			plugins = append(plugins, sandboxPlugin{connector: tc.connector, name: name, source: source.String()})
		}
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].name < plugins[j].name })
	return plugins
}

func sandboxPluginNames(plugins []sandboxPlugin) string {
	names := make([]string, len(plugins))
	for i, p := range plugins {
		names[i] = p.name
	}
	if len(names) > 1 {
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	return strings.Join(names, "")
}

func failModesPage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "fail-modes.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

// The fail-modes page says which sandbox hooks leave a hook-failures.jsonl
// record in the guest: the shell hooks do, and it names each plugin that
// does not. Both halves are read from the rendered overlays, so a shell hook
// that stops logging, or a plugin that starts, fails here until the page
// says so.
func TestFailModesDocNamesTheSandboxHooksThatLogFailures(t *testing.T) {
	plugins := sandboxPlugins(t)
	page := failModesPage(t)
	claim := "In an OpenShell sandbox the shell hooks write the same record inside the guest at `" + SandboxHookLogDir + "/hook-failures.jsonl`"
	if !strings.Contains(page, claim) {
		t.Fatalf("fail-modes.mdx must scope the sandbox log claim to shell hooks: %q", claim)
	}
	if strings.Contains(page, "Sandbox hooks write the same record") {
		t.Fatal("fail-modes.mdx promises a failure record from every sandbox hook")
	}
	const tail = " sandbox plugins write no record."
	if len(plugins) == 0 {
		if strings.Contains(page, tail) {
			t.Fatal("fail-modes.mdx names sandbox plugins that write no record, but every sandbox hook logs")
		}
		return
	}
	if want := "The " + sandboxPluginNames(plugins) + tail; !strings.Contains(page, want) {
		t.Fatalf("fail-modes.mdx must name the sandbox plugins that write no failure record: %q", want)
	}
}

// sandboxPluginPromptBlock reports how a rendered sandbox plugin could stop
// a prompt, or "" when it cannot. Every sandbox plugin connector needs an
// entry, so a new plugin is checked before the page may cover it.
var sandboxPluginPromptBlock = map[string]func(t *testing.T, src string) string{
	"amp":      ampSandboxPromptBlock,
	"opencode": openCodeSandboxPromptBlock,
}

// Amp stops a turn only by cancelling the thread (ctx.thread.cancel). The
// one cancel sits behind the standalone foreign-hook guard, which the
// sandbox render leaves empty, and agent.start ignores the verdict action,
// so an outage answer never cancels the prompt.
func ampSandboxPromptBlock(t *testing.T, src string) string {
	t.Helper()
	const guard = "if (DC_FOREIGN_GUARD && DC_HOOK_SOCKET) {"
	if strings.Contains(src, `const DC_FOREIGN_GUARD: string = ""`) {
		src = dropJSBlocks(t, src, guard)
	}
	if strings.Contains(src, "thread.cancel(") {
		return "cancels the thread outside the empty foreign-hook guard"
	}
	start := strings.Index(src, `amp.on("agent.start"`)
	if start < 0 {
		return ""
	}
	handler := src[start:]
	if end := strings.Index(handler[1:], "amp.on("); end >= 0 {
		handler = handler[:end+1]
	}
	if strings.Contains(handler, ".action") {
		return "agent.start acts on the verdict action"
	}
	return ""
}

// openCodePromptHook matches an OpenCode plugin hook that sees a prompt or
// a command before the model does.
var openCodePromptHook = regexp.MustCompile(`"(?:experimental\.)?(?:chat|command)\.[A-Za-z.]+"\s*:`)

func openCodeSandboxPromptBlock(t *testing.T, src string) string {
	t.Helper()
	if hook := openCodePromptHook.FindString(src); hook != "" {
		return "registers the prompt hook " + hook
	}
	return ""
}

// dropJSBlocks removes every brace block that opens with head.
func dropJSBlocks(t *testing.T, src, head string) string {
	t.Helper()
	for {
		start := strings.Index(src, head)
		if start < 0 {
			return src
		}
		depth := 0
		end := -1
		for i := start + len(head) - 1; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = i + 1
				break
			}
		}
		if end < 0 {
			t.Fatalf("unbalanced block after %q", head)
		}
		src = src[:start] + src[end:]
	}
}

// The page says the sandbox plugins block a tool call they cannot check and
// do not block prompts, and qualifies the next-prompt sentence: the claim
// is read from each rendered plugin, so a plugin that gains a prompt block
// fails here until the page says so.
func TestFailModesDocSaysSandboxPluginsDoNotBlockPrompts(t *testing.T) {
	plugins := sandboxPlugins(t)
	page := failModesPage(t)
	if strings.Contains(page, "sandbox plugins block those calls too") {
		t.Fatal("fail-modes.mdx says the sandbox plugins block prompts as well as tool calls")
	}
	if strings.Contains(page, "The next prompt or tool call is blocked as before.") {
		t.Fatal("fail-modes.mdx says every next prompt is blocked; not every hook can block a prompt")
	}
	stopEvents := strings.Split(strings.Split(page, "### Stop and session-end events")[1], "### ")[0]
	if want := "[gateway outage table](/docs/connectors/capability-matrix#gateway-outage)"; !strings.Contains(stopEvents, want) {
		t.Fatalf("fail-modes.mdx must link to the canonical outage table: %q", want)
	}
	var blockers []string
	for _, p := range plugins {
		check, ok := sandboxPluginPromptBlock[p.connector]
		if !ok {
			t.Fatalf("%s: add a prompt-block check to sandboxPluginPromptBlock", p.connector)
		}
		if how := check(t, p.source); how != "" {
			blockers = append(blockers, p.name+" "+how)
		}
	}
	const noPrompts = " do not block prompts."
	if len(blockers) > 0 {
		if strings.Contains(page, noPrompts) {
			t.Fatalf("fail-modes.mdx says the sandbox plugins do not block prompts, but: %s", strings.Join(blockers, "; "))
		}
		return
	}
}
