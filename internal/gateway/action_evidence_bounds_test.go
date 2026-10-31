package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// b36ManagedHookFixture is a managed user's home that the gateway cannot
// search (ProtectHome), with a project, an authorized-keys decoy and a link
// to it that only the user's hook client can see.
type b36ManagedHookFixture struct {
	homes, home, project, keys string
}

func newB36ManagedHookFixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed hook evidence")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	root := t.TempDir()
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(f.keys), filepath.Join(f.project, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(f.project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", f.home)
	t.Cleanup(func() { _ = os.Chmod(f.homes, 0o700) })
	return f
}

func (f b36ManagedHookFixture) payload(t *testing.T, command string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": f.project,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
}

// clientHeader is the real hook client's header, computed as the user.
func (f b36ManagedHookFixture) clientHeader(t *testing.T, payload []byte) string {
	t.Helper()
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	return hookpaths.Resolve(payload)
}

// post sends the hook request with the user's home hidden from the gateway.
func (f b36ManagedHookFixture) post(t *testing.T, connector string, payload []byte, header string) string {
	t.Helper()
	if err := os.Chmod(f.homes, 0); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow"
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body)
}

// TestR103B36RealBoundedHeaderKeepsTruncation is the B-36 review proof: the
// real hook client fills its bounded map with harmless redirects and omits
// the last operand, a protected write. Claude Code header scoping used to
// drop the truncation marker of a larger map, so the omitted operand counted
// as described and was allowed. Both connectors must deny it, relative or
// absolute, a direct name or a link only the client can see.
func TestR103B36RealBoundedHeaderKeepsTruncation(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for name, last := range map[string]string{
		"relative_protected": "../.ssh/authorized_keys",
		"relative_link":      "keylink",
		"absolute_link":      filepath.Join(f.project, "keylink"),
	} {
		var command strings.Builder
		command.WriteString("echo hi")
		for i := 0; i < 530; i++ {
			fmt.Fprintf(&command, " > ordinary/filler%03d", i)
		}
		command.WriteString(" > " + last)
		payload := f.payload(t, command.String())
		header := f.clientHeader(t, payload)
		targets, ok := hookpaths.Decode(header)
		if !ok || targets[hookpaths.TruncatedKey] != "1" {
			t.Fatalf("%s: real client header is not a bounded map: decoded=%t targets=%d truncated=%q reason=%q header_bytes=%d",
				name, ok, len(targets), targets[hookpaths.TruncatedKey], targets[hookpaths.UnprovenReasonKey], len(header))
		}
		if _, listed := targets[hookpaths.OperandPath(last, f.project)]; listed {
			t.Fatalf("%s: the bounded map lists the last operand; the proof needs it omitted", name)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != "block" {
				t.Errorf("%s/%s: bounded header verdict = %s, want block", connector, name, got)
			}
		}
	}
}

// TestR103B36IncompleteEvidenceNotMorePermissive compares each incomplete or
// rejected evidence form with the no-fact header of the same call: none may
// allow what the no-fact header blocks, with or without a cwd the gateway
// can validate.
func TestR103B36IncompleteEvidenceNotMorePermissive(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	report := filepath.Join(f.project, "ordinary", "report.txt")
	header := func(targets map[string]string) string { return encodeTargets(t, targets) }
	full := map[string]string{hookpaths.CWDKey: f.project, hookpaths.TruncatedKey: "1"}
	for i := 0; i < hookpaths.MaxWriteTargets; i++ {
		full[fmt.Sprintf("/tmp/b36-fill-%03d", i)] = ""
	}
	for _, command := range []string{
		"tar -C ordinary -xf pkg.tar; echo hi > ordinary/report.txt",
		"echo hi > ordinary/report.txt",
		"echo hi > " + report,
		"echo hi > ../.ssh/authorized_keys",
		"echo hi > " + f.keys,
		"echo hi > keylink",
		"echo hi > " + filepath.Join(f.project, "keylink"),
	} {
		payload := f.payload(t, command)
		real, ok := hookpaths.Decode(f.clientHeader(t, payload))
		if !ok {
			t.Fatalf("%s: client header does not decode", command)
		}
		noFact := map[string]string{}
		withMarker := map[string]string{hookpaths.TruncatedKey: "1"}
		for key, value := range real {
			if !strings.HasPrefix(key, hookpaths.OpaqueScopeFactPrefix) {
				noFact[key], withMarker[key] = value, value
			}
		}
		modes := map[string]string{
			"rejected_fact":    header(map[string]string{hookpaths.OpaqueScopeFactPrefix + report: "bad", hookpaths.CWDKey: f.project}),
			"undecodable":      "not-base64!",
			"marker_only":      header(map[string]string{hookpaths.TruncatedKey: "1"}),
			"cwd_and_marker":   header(map[string]string{hookpaths.CWDKey: f.project, hookpaths.TruncatedKey: "1"}),
			"truncated_map":    header(withMarker),
			"full_bounded_map": header(full),
		}
		for _, connector := range []string{"claudecode", "codex"} {
			baseline := f.post(t, connector, payload, header(noFact))
			if baseline != "block" {
				continue
			}
			for mode, value := range modes {
				if got := f.post(t, connector, payload, value); got != "block" {
					t.Errorf("%s/%s %q = %s, more permissive than the no-fact header", connector, mode, command, got)
				}
			}
		}
	}
}

// TestR103B36HeaderlessManagedShellCallFailsClosed is GAP-0280: a managed
// Claude Code or Codex shell hook sends no resolved-writes header when its
// resolver fails. The gateway reads that as incomplete evidence, so a write
// it cannot place is denied, and the hook route never runs the command.
func TestR103B36HeaderlessManagedShellCallFailsClosed(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	marker := filepath.Join(f.project, "marker.txt")
	for _, command := range []string{"echo hi > marker.txt", "echo hi > keylink", "echo hi > " + marker} {
		payload := f.payload(t, command)
		if f.clientHeader(t, payload) == "" {
			t.Fatalf("%s: the real client sends no header", command)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, ""); got != "block" {
				t.Errorf("%s headerless %q = %s, want block", connector, command, got)
			}
		}
	}
	// A shell call that writes nothing is unaffected.
	for _, connector := range []string{"claudecode", "codex"} {
		if got := f.post(t, connector, f.payload(t, "ls -la"), ""); got != "allow" {
			t.Errorf("%s headerless read-only call = %s, want allow", connector, got)
		}
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("the hook route ran the command or stat failed: %v", err)
	}
}

// TestCommandHookResolvedWritesScope keeps the GAP-0280 default to managed
// command-hook shell calls: evidence that is present, a non-shell tool, a
// per-user request and a sandbox request are unchanged.
func TestCommandHookResolvedWritesScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook client sends no header on Windows")
	}
	shell := actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"echo hi > a.txt"}`)}
	managed := withManagedHookPeer(context.Background(), managedHookPeer{Home: "/home/alice"})
	if got := commandHookResolvedWrites(managed, &config.Config{}, shell); got[hookpaths.TruncatedKey] != "1" || len(got) != 1 {
		t.Fatalf("headerless managed shell call = %v, want the truncation marker only", got)
	}
	sent := map[string]string{hookpaths.CWDKey: "/home/alice"}
	if got := commandHookResolvedWrites(context.WithValue(managed, resolvedWritesContextKey{}, sent), nil, shell); len(got) != 1 || got[hookpaths.CWDKey] == "" {
		t.Fatalf("client evidence = %v, want it unchanged", got)
	}
	if got := commandHookResolvedWrites(managed, nil, actionfacts.Input{Tool: "Write", Args: json.RawMessage(`{"file_path":"a"}`)}); got != nil {
		t.Fatalf("non-shell tool = %v, want nil", got)
	}
	if got := commandHookResolvedWrites(context.Background(), nil, shell); got != nil {
		t.Fatalf("per-user request = %v, want nil", got)
	}
}

// TestR103B36BoundedHeaderOmittedOperandsStayUnknown keeps every operand a
// bounded map omits unknown on a managed host. The hook client sends no
// summary of the omitted operands (owner decision 2026-10-19), so the
// review rows for 1.0.3 block for both connectors: dynamic, case-variant
// and link forms of a protected write after a full map, a Unicode HOME
// alias of the account home, and a real bounded header reused on another
// call. A large benign command whose write operands do not fit the map is
// also denied, as over the evaluation budget (ACTION-COMPOUND-LIMIT,
// GAP-0146): the documented managed known limit (rel-1-0-3 GAP-0291).
func TestR103B36BoundedHeaderOmittedOperandsStayUnknown(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh", "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../.ssh/d", filepath.Join(f.project, "a", "b")); err != nil {
		t.Fatal(err)
	}
	var filler strings.Builder
	filler.WriteString("echo hi")
	for i := 0; i < 530; i++ {
		fmt.Fprintf(&filler, " > ordinary/filler%03d", i)
	}
	bounded := func(header string) {
		t.Helper()
		targets, ok := hookpaths.Decode(header)
		if !ok || targets[hookpaths.TruncatedKey] != "1" {
			t.Fatal("real client header is not a bounded map")
		}
	}
	for name, suffix := range map[string]string{
		"dynamic_var":        `; x=keylink; echo hi > "$x"`,
		"dynamic_home":       `; x=../.ssh/authorized_keys; echo hi > "$x"`,
		"absolute_protected": " > " + f.keys,
		"parent_link":        " > dirlink/authorized_keys",
		"link_dotdot":        " > a/b/../authorized_keys",
		"ascii_case":         " > ../.SSH/AUTHORIZED_KEYS",
		"unicode_case":       " > ../.ssh/authorİzed_keys",
	} {
		payload := f.payload(t, filler.String()+suffix)
		header := f.clientHeader(t, payload)
		bounded(header)
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != "block" {
				t.Errorf("%s/%s: bounded header verdict = %s, want block", connector, name, got)
			}
		}
	}

	// A real bounded header from a benign call, reused on a protected link
	// write, and a header holding only the cwd and the marker.
	benign := f.payload(t, filler.String())
	benignHeader := f.clientHeader(t, benign)
	bounded(benignHeader)
	link := f.payload(t, "echo hi > keylink")
	markerOnly := encodeTargets(t, map[string]string{hookpaths.CWDKey: f.project, hookpaths.TruncatedKey: "1"})
	for _, connector := range []string{"claudecode", "codex"} {
		for mode, header := range map[string]string{"reused_header": benignHeader, "cwd_and_marker": markerOnly} {
			if got := f.post(t, connector, link, header); got != "block" {
				t.Errorf("%s/%s: protected link write = %s, want block", connector, mode, got)
			}
		}
		// Known limit: the omitted benign operands stay unknown.
		if got := f.post(t, connector, benign, benignHeader); got != "block" {
			t.Errorf("%s: large benign command = %s, want block (known limit)", connector, got)
		}
	}
}

// TestR103B36UnicodeHomeAliasBlocks runs the hook client with a HOME that
// differs from the account home only by a Unicode case fold, then writes a
// link to the account key after a full map. Both connectors must deny it.
func TestR103B36UnicodeHomeAliasBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed hook evidence")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	root := t.TempDir()
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "ilice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	alias := filepath.Join(f.homes, "İlice")
	for _, dir := range []string{filepath.Dir(f.keys), filepath.Join(f.project, "ordinary"), alias} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(f.project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", alias)
	t.Cleanup(func() { _ = os.Chmod(f.homes, 0o700) })
	var command strings.Builder
	command.WriteString("echo hi")
	for i := 0; i < 530; i++ {
		fmt.Fprintf(&command, " > ordinary/filler%03d", i)
	}
	command.WriteString(" > keylink")
	payload := f.payload(t, command.String())
	header := f.clientHeader(t, payload)
	for _, connector := range []string{"claudecode", "codex"} {
		if got := f.post(t, connector, payload, header); got != "block" {
			t.Errorf("%s: Unicode HOME alias verdict = %s, want block", connector, got)
		}
	}
}
