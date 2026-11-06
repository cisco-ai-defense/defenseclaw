// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX homes and shell commands; the tool-call corpus rows
// cover the Windows home spellings.

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const credentialFileWriteRule = "secrets.credential_file_write"

// credentialFileTargets is one file of every credential read rule, by its
// path under the home, and the rule that owns its writes: every leg of
// credentialFileWriteLegs, and the SSH private key, whose write leg is
// PATH-SSH-DIR (gas-ux-r1:GAP-0052).
var credentialFileTargets = []struct{ relative, rule string }{
	{".aws/credentials", credentialFileWriteRule},
	{".aws/config", credentialFileWriteRule},
	{".kube/config", credentialFileWriteRule},
	{".docker/config.json", credentialFileWriteRule},
	{".npmrc", credentialFileWriteRule},
	{".pypirc", credentialFileWriteRule},
	{".git-credentials", credentialFileWriteRule},
	{".netrc", credentialFileWriteRule},
	{".pgpass", credentialFileWriteRule},
	{".config/gcloud/application_default_credentials.json", credentialFileWriteRule},
	{".config/gh/hosts.yml", credentialFileWriteRule},
	{".azure/azureProfile.json", credentialFileWriteRule},
	{".gnupg/gpg-agent.conf", credentialFileWriteRule},
	{".ssh/id_ed25519", "PATH-SSH-DIR"},
}

// credentialFileFixture is one account: home h with every target file, and
// the project p with ordinary files, look-alikes and a link to the AWS
// credentials file.
type credentialFileFixture struct{ home, project string }

func newCredentialFileFixture(t *testing.T) credentialFileFixture {
	t.Helper()
	root := t.TempDir()
	f := credentialFileFixture{home: filepath.Join(root, "home"), project: filepath.Join(root, "home", "proj")}
	files := []string{"proj/notes.txt", "proj/.aws/credentials", "proj/fixtures/.kube/config", "proj/docker/config.json",
		"proj/.npmrc", ".aws/cli/cache/token.json", ".kube/cache/discovery.json", ".config/gcloud/configurations/config_default"}
	for _, target := range credentialFileTargets {
		files = append(files, target.relative)
	}
	for _, file := range files {
		path := filepath.Join(f.home, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"creds-link": ".aws/credentials", "key-link": ".ssh/id_ed25519"} {
		if err := os.Symlink(filepath.Join(f.home, target), filepath.Join(f.project, link)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	t.Chdir(f.project)
	return f
}

func (f credentialFileFixture) path(template string) string {
	return strings.NewReplacer("{H}", f.home, "{P}", f.project).Replace(template)
}

// credentialFileHookCall is one pre-call hook event of a connector's tool.
type credentialFileHookCall struct {
	connector, tool string
	args            map[string]any
}

func (c credentialFileHookCall) String() string {
	return fmt.Sprintf("%s %s %v", c.connector, c.tool, c.args)
}

// credentialFileHook posts calls to the connectors' hooks in action mode on
// one profile pack, per-user or as a managed gateway that knows the caller.
type credentialFileHook struct {
	f       credentialFileFixture
	profile string
	managed bool
}

func newCredentialFileHook(t *testing.T, f credentialFileFixture, profile string, managed bool) credentialFileHook {
	t.Helper()
	for _, connector := range []string{"claudecode", "codex", "copilot", "opencode"} {
		installToolCallCorpusProfileConnector(t, connector, profile)
	}
	return credentialFileHook{f, profile, managed}
}

// post returns the decision (block, alert or allow) and the response.
func (h credentialFileHook) post(t *testing.T, call credentialFileHookCall) (string, string) {
	t.Helper()
	body := nativeWriteCall{connector: call.connector, tool: call.tool,
		args: func(string) map[string]any { return call.args }}.body(t, h.f.project, call.String())
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = call.connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), h.profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+call.connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	event := "PreToolUse"
	switch call.connector {
	case "copilot":
		event = "preToolUse"
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(call.connector, "", event, []byte(body)))
	if h.managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: h.f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
	out := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %.400s", call, recorder.Code, out)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("%s: verdict %q: %v", call, out, err)
	}
	action, _ := resp["action"].(string)
	return action, out
}

// credentialFileWriteCalls is every way an agent changes the file at
// relative under the home: each connector's file tools in their reviewed
// argument schema (Claude Code Write, Edit and MultiEdit, OpenCode write,
// edit and patch, Codex and Copilot apply_patch, Copilot edit and create),
// and Claude Code and Codex Bash redirects, tee, cp and mv onto it, mv away,
// rm, sed -i and truncate, with absolute, ~, $HOME and ${HOME} spellings.
func credentialFileWriteCalls(f credentialFileFixture, relative string) []credentialFileHookCall {
	absolute := filepath.Join(f.home, relative)
	var calls []credentialFileHookCall
	for _, call := range nativeWriteCalls() {
		calls = append(calls, credentialFileHookCall{call.connector, call.tool, call.args(absolute)})
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, command := range []string{
			"printf 'x\\n' > " + absolute,
			"printf 'x\\n' >> ~/" + relative,
			`printf 'x\n' | tee "$HOME/` + relative + `"`,
			`printf 'x\n' | tee -a "${HOME}/` + relative + `"`,
			"cp notes.txt ~/" + relative,
			"mv notes.txt $HOME/" + relative,
			"mv ~/" + relative + " moved.txt",
			"rm " + absolute,
			"sed -i s/a/b/ ~/" + relative,
			"truncate -s 0 " + absolute,
		} {
			calls = append(calls, credentialFileHookCall{connector, "Bash", map[string]any{"command": command}})
		}
	}
	return calls
}

func credentialFileTopology(managed bool) string {
	if managed {
		return "managed"
	}
	return "per-user"
}

// TestCredentialFileWritesAlertInBalancedAndBlockInStrict: every write,
// append, truncation or delete of a credential file of the active home,
// through any connector's file tool or the shell, and whatever the spelling,
// is a HIGH finding of its write leg. The balanced default alerts and
// allows, so aws configure and kubectl config keep working; strict blocks,
// per-user and managed (gas-ux-r1:GAP-0052).
func TestCredentialFileWritesAlertInBalancedAndBlockInStrict(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		want := map[string]string{"default": "alert", "strict": "block"}[profile]
		for _, managed := range []bool{false, true} {
			for _, target := range credentialFileTargets {
				t.Run(profile+"/"+credentialFileTopology(managed)+"/"+target.relative, func(t *testing.T) {
					f := newCredentialFileFixture(t)
					hook := newCredentialFileHook(t, f, profile, managed)
					for _, call := range credentialFileWriteCalls(f, target.relative) {
						got, out := hook.post(t, call)
						if got != want || !strings.Contains(out, target.rule) {
							t.Errorf("%s: decision %s, want %s by %s: %.500s", call, got, want, target.rule, out)
						}
					}
				})
			}
		}
	}
}

// TestCredentialFileWriteThroughALink: a write to a project link that
// points at a credential file (the AWS credentials, an SSH private key) is
// judged as a write of that file, per-user and managed.
func TestCredentialFileWriteThroughALink(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		want := map[string]string{"default": "alert", "strict": "block"}[profile]
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+credentialFileTopology(managed), func(t *testing.T) {
				f := newCredentialFileFixture(t)
				hook := newCredentialFileHook(t, f, profile, managed)
				for name, rule := range map[string]string{"creds-link": credentialFileWriteRule, "key-link": "PATH-SSH-DIR"} {
					link := filepath.Join(f.project, name)
					for _, call := range []credentialFileHookCall{
						{"claudecode", "Write", map[string]any{"file_path": link, "content": "x\n"}},
						{"opencode", "write", map[string]any{"path": link, "content": "x\n"}},
						{"claudecode", "Bash", map[string]any{"command": "printf 'x\\n' > " + name}},
						{"codex", "Bash", map[string]any{"command": "printf 'x\\n' | tee " + link}},
					} {
						got, out := hook.post(t, call)
						if got != want || !strings.Contains(out, rule) {
							t.Errorf("%s: decision %s, want %s by %s: %.500s", call, got, want, rule, out)
						}
					}
				}
			})
		}
	}
}

// TestCredentialFileReadsAndOrdinaryWritesAreUnchanged: the write legs
// change neither a read of the same files (the read rules keep their MEDIUM
// alert) nor any write of another file, a project look-alike or a CLI cache
// next to the credential file, nor the aws, kubectl, docker and gh commands
// that manage these files, in either pack, per-user or managed.
func TestCredentialFileReadsAndOrdinaryWritesAreUnchanged(t *testing.T) {
	reads := map[string]string{
		"{H}/.aws/credentials":      "PATH-AWS-CREDS",
		"{H}/.kube/config":          "PATH-KUBE",
		"{H}/.docker/config.json":   "PATH-DOCKER",
		"~/.aws/credentials":        "PATH-AWS-CREDS",
		"$HOME/.docker/config.json": "PATH-DOCKER",
	}
	ordinary := []string{"{P}/notes.txt", "{P}/.aws/credentials", "{P}/fixtures/.kube/config", "{P}/docker/config.json",
		"{P}/.npmrc", "{H}/.aws/cli/cache/token.json", "{H}/.kube/cache/discovery.json",
		"{H}/.config/gcloud/configurations/config_default"}
	commands := []string{"aws configure set region us-east-1", "kubectl config use-context dev",
		"docker login -u a --password-stdin", "gh auth status", "cp ~/.aws/credentials backup.txt",
		"grep -c profile ~/.aws/config", "cat ~/.npmrc ~/.netrc"}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+credentialFileTopology(managed), func(t *testing.T) {
				f := newCredentialFileFixture(t)
				hook := newCredentialFileHook(t, f, profile, managed)
				for target, rule := range reads {
					absolute := strings.NewReplacer("~", f.home, "$HOME", f.home).Replace(f.path(target))
					for _, call := range []credentialFileHookCall{
						{"claudecode", "Read", map[string]any{"file_path": absolute}},
						{"opencode", "read", map[string]any{"path": absolute}},
						{"claudecode", "Bash", map[string]any{"command": "cat " + f.path(target)}},
						{"codex", "Bash", map[string]any{"command": "cat " + f.path(target)}},
					} {
						got, out := hook.post(t, call)
						if got != "alert" || !strings.Contains(out, rule) || strings.Contains(out, credentialFileWriteRule) {
							t.Errorf("read %s: decision %s, want the %s alert and no write finding: %.500s", call, got, rule, out)
						}
					}
				}
				for _, target := range ordinary {
					relative, _ := filepath.Rel(f.home, f.path(target))
					for _, call := range credentialFileWriteCalls(f, relative) {
						got, out := hook.post(t, call)
						if got == "block" || strings.Contains(out, credentialFileWriteRule) {
							t.Errorf("ordinary %s: decision %s, want no block and no %s: %.500s", call, got, credentialFileWriteRule, out)
						}
					}
				}
				for _, command := range commands {
					for _, connector := range []string{"claudecode", "codex"} {
						call := credentialFileHookCall{connector, "Bash", map[string]any{"command": command}}
						got, out := hook.post(t, call)
						if strings.Contains(out, credentialFileWriteRule) || profile == "default" && got == "block" {
							t.Errorf("command %s: decision %s with the write rule or a balanced block: %.500s", call, got, out)
						}
					}
				}
			})
		}
	}
}

// TestEveryCredentialReadRuleHasAWriteLeg keeps the class closed: every
// credential-tagged rule of the shipped sensitive-path packs has a write leg
// in credentialFileWriteLegs or a reason in
// credentialReadRulesWithoutFileWriteLeg, and every leg names shipped rules.
func TestEveryCredentialReadRuleHasAWriteLeg(t *testing.T) {
	legs := map[string]bool{}
	for _, leg := range credentialFileWriteLegs {
		for _, id := range leg.readRules {
			legs[id] = true
		}
	}
	shipped := map[string]bool{}
	check := func(where, id string) {
		_, excluded := credentialReadRulesWithoutFileWriteLeg[id]
		if legs[id] == excluded {
			t.Errorf("%s %s: in a write leg %t, excluded %t; want exactly one", where, id, legs[id], excluded)
		}
	}
	// The compiled-in Windows path rules are all credential or history rules.
	for _, rule := range windowsSensitivePathRules {
		shipped[rule.id] = true
		check("windows", rule.id)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
		for _, file := range pack.RuleFiles {
			if file.Category != "sensitive-path" {
				continue
			}
			for _, rule := range file.Rules {
				shipped[rule.ID] = true
				if !slices.Contains(rule.Tags, "credential") {
					continue
				}
				check(profile, rule.ID)
			}
		}
	}
	for id := range legs {
		if !shipped[id] {
			t.Errorf("write leg names %s, which no shipped pack has", id)
		}
	}
}

// TestCredentialReadRulesLeaveWritesToTheirLeg: a read rule of a file that
// has a write leg never takes a write of that file as its own mutation
// proof, so a fallback match of a CRITICAL read rule on a write (a call with
// a run-time redirect target) cannot block in balanced; the HIGH write leg
// judges it, as it judges the same write with a static target.
func TestCredentialReadRulesLeaveWritesToTheirLeg(t *testing.T) {
	files := map[string]string{
		"PATH-AWS-CREDS": ".aws/credentials", "PATH-AWS-CONFIG": ".aws/config", "PATH-KUBE": ".kube/config",
		"PATH-DOCKER": ".docker/config.json", "PATH-NPMRC": ".npmrc", "PATH-PYPIRC": ".pypirc",
		"PATH-GIT-CREDS": ".git-credentials", "PATH-NETRC": ".netrc",
		"secrets.cloud_credential_read": ".config/gh/hosts.yml", "PATH-GNUPG": ".gnupg/gpg.conf",
	}
	for _, leg := range credentialFileWriteLegs {
		for _, rule := range leg.readRules {
			if !credentialFileWriteLegOwnsReadRule(rule) {
				t.Errorf("%s: not owned by its write leg", rule)
			}
			relative, ok := files[rule]
			if !ok {
				continue
			}
			for _, command := range []string{"printf x > /home/alice/" + relative, "rm /home/alice/" + relative} {
				facts := actionfacts.Analyze(sensitivePathShellInput(command))
				if !credentialFileWritePrerequisite(facts) {
					t.Errorf("%s %q: the write leg does not prove it", rule, command)
				}
				if trustedActionClassifySensitivePathRisk(facts, rule) == trustedActionSensitivePathMutation {
					t.Errorf("%s %q: the read rule took the write as its mutation", rule, command)
				}
			}
		}
	}
	// A read rule without a write leg keeps its mutation proof.
	facts := actionfacts.Analyze(sensitivePathShellInput("rm /home/alice/.ssh/id_ed25519"))
	if trustedActionClassifySensitivePathRisk(facts, "PATH-SSH-KEY") != trustedActionSensitivePathMutation {
		t.Error("PATH-SSH-KEY lost its delete mutation proof")
	}
}

// credentialFileVerdict is the decision a finding of severity gives in a
// profile pack: CRITICAL blocks in every pack, HIGH alerts in balanced and
// permissive and blocks in strict.
func credentialFileVerdict(profile, severity string) string {
	if severity == "CRITICAL" || profile == "strict" {
		return "block"
	}
	return "alert"
}

// TestCredentialFileWritesOutsideTheActiveHomeKeepTheirVerdict: the write
// leg covers the active home only, so a write, copy, dd, tee, rm or move of a
// credential file in another account's home or in /root keeps the read
// rule's own verdict, as before the leg existed: CRITICAL files block in
// every profile, the kubeconfig alerts in balanced and permissive and blocks
// in strict (gx052 review M1).
func TestCredentialFileWritesOutsideTheActiveHomeKeepTheirVerdict(t *testing.T) {
	targets := []struct{ path, rule, severity string }{
		{"/home/bob/.aws/credentials", "PATH-AWS-CREDS", "CRITICAL"},
		{"/root/.aws/credentials", "PATH-AWS-CREDS", "CRITICAL"},
		{"/home/bob/.git-credentials", "PATH-GIT-CREDS", "CRITICAL"},
		{"/home/bob/.netrc", "PATH-NETRC", "CRITICAL"},
		{"/root/.git-credentials", "PATH-GIT-CREDS", "CRITICAL"},
		{"/home/bob/.kube/config", "PATH-KUBE", "HIGH"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+credentialFileTopology(managed), func(t *testing.T) {
				f := newCredentialFileFixture(t)
				hook := newCredentialFileHook(t, f, profile, managed)
				for _, target := range targets {
					want := credentialFileVerdict(profile, target.severity)
					for _, command := range []string{
						"printf x > " + target.path, "printf x >> " + target.path, "printf x | tee " + target.path,
						"cp notes.txt " + target.path, "dd if=notes.txt of=" + target.path, "rm " + target.path,
						"mv " + target.path + " moved.txt",
					} {
						for _, connector := range []string{"claudecode", "codex"} {
							call := credentialFileHookCall{connector, "Bash", map[string]any{"command": command}}
							got, out := hook.post(t, call)
							if got != want || !strings.Contains(out, target.rule) {
								t.Errorf("%s: decision %s, want %s by %s: %.400s", call, got, want, target.rule, out)
							}
						}
					}
				}
			})
		}
	}
}

// credentialCopyForm is one way an action reads credential file from and
// writes credential file to, in one command or across commands of the same
// action (a pipe, &&, ;, ||, a subshell, a command substitution), with what
// base 38197e3501..77e412ee74 did with it (gx052 review M2, N1):
//   - readRuleBlocks: when one read rule owns both files, its CRITICAL
//     mutation proof blocks in every profile;
//   - legSees: the write is a typed write the leg proves.
type credentialCopyForm struct {
	command        func(from, to string) string
	readRuleBlocks bool
	legSees        bool
}

var credentialCopyForms = []credentialCopyForm{
	{func(a, b string) string { return "cat " + a + " | tee " + b }, true, true},
	{func(a, b string) string { return "cat " + a + " | tee -a " + b }, true, true},
	{func(a, b string) string { return "base64 " + a + " | tee " + b }, true, true},
	{func(a, b string) string { return "cat " + a + " | base64 | base64 -d | tee " + b }, true, true},
	{func(a, b string) string { return "cat " + a + " > /tmp/s && cp /tmp/s " + b }, true, true},
	{func(a, b string) string { return "cat " + a + " > /tmp/s || cp /tmp/s " + b }, true, true},
	// Base reads these statement by statement, so its read rule never
	// sees the write: they alert on base, as on head; the leg adds strict.
	{func(a, b string) string { return "cat " + a + " > /tmp/s; cp /tmp/s " + b }, false, true},
	{func(a, b string) string { return "(cat " + a + ") | tee " + b }, false, true},
	// A redirect whose words hold a command substitution is not a typed
	// write: no write rule sees it, on base or head (detection, #1189).
	{func(a, b string) string { return "printf '%s' \"$(cat " + a + ")\" > " + b }, false, false},
}

// TestCredentialFileCopiedIntoAnotherKeepsTheReadVerdict: an action that
// reads one credential file and writes another keeps the read rule's
// mutation proof, so the write leg never narrows what the read rule judged
// before it existed (gx052 review M2, N1). Each row states the floor it may
// not fall below, base 38197e3501..77e412ee74 or better: a read rule that
// blocked on base blocks in every profile; elsewhere the leg alerts in
// balanced and permissive and blocks in strict (base: alert, allow, alert);
// dd if=A of=B keeps the read finding of A. A read that blocks by itself
// (an active SSH private key) may block any row.
func TestCredentialFileCopiedIntoAnotherKeepsTheReadVerdict(t *testing.T) {
	pairs := []struct {
		from, to, rule string
		sameRule       bool // one read rule owns both files
	}{
		{"{H}/.aws/credentials", "{H}/.git-credentials", "PATH-AWS-CREDS", false},
		{"{H}/.aws/credentials", "{H}/.netrc", "PATH-AWS-CREDS", false},
		{"{H}/.config/gh/hosts.yml", "{H}/.aws/credentials", "secrets.cloud_credential_read", false},
		{"{H}/.git-credentials", "{H}/.aws/credentials", "PATH-GIT-CREDS", false},
		{"{H}/.netrc", "{H}/.aws/credentials", "PATH-GIT-CREDS", false}, // PATH-NETRC reports as its alias
		{"{H}/.ssh/id_ed25519", "{H}/.aws/credentials", "PATH-SSH-KEY", false},
		{"~/.git-credentials", "~/.netrc", "PATH-GIT-CREDS", true},
		{"{H}/.git-credentials", "{H}/.netrc", "PATH-GIT-CREDS", true},
		{"/home/bob/.aws/credentials", "~/.aws/credentials", "PATH-AWS-CREDS", true},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+credentialFileTopology(managed), func(t *testing.T) {
				f := newCredentialFileFixture(t)
				hook := newCredentialFileHook(t, f, profile, managed)
				for _, pair := range pairs {
					from, to := f.path(pair.from), f.path(pair.to)
					type row struct{ command, want string }
					var rows []row
					for _, form := range credentialCopyForms {
						want := map[string]string{"default": "alert", "permissive": "allow", "strict": "alert"}[profile]
						switch {
						case pair.sameRule && form.readRuleBlocks:
							want = "block"
						case form.legSees:
							want = credentialFileVerdict(profile, "HIGH")
						}
						rows = append(rows, row{form.command(from, to), want})
					}
					if strings.HasPrefix(from, f.home) && strings.HasPrefix(to, f.home) {
						rows = append(rows, row{"dd if=" + from + " of=" + to, credentialFileVerdict(profile, "HIGH")})
					}
					for _, r := range rows {
						for _, connector := range []string{"claudecode", "codex"} {
							call := credentialFileHookCall{connector, "Bash", map[string]any{"command": r.command}}
							got, out := hook.post(t, call)
							rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
							if rank[got] < rank[r.want] || r.want != "allow" && profile != "permissive" && !strings.Contains(out, pair.rule) {
								t.Errorf("%s: decision %s, want at least %s with the %s read finding: %.400s", call, got, r.want, pair.rule, out)
							}
						}
					}
				}
			})
		}
	}
}

// credentialReadRulesWithoutFileWriteLeg names the credential-tagged
// sensitive-path rules that need no leg in credentialFileWriteLegs, and why.
var credentialReadRulesWithoutFileWriteLeg = map[string]string{
	"PATH-SSH-DIR":                           "is the write leg of SSH keys (sshDirectoryPrerequisite)",
	"PATH-SSH-KEY":                           "its write leg is PATH-SSH-DIR (GAP-1666)",
	"PATH-HISTORY":                           "owns history mutations itself",
	"PATH-ETC-SHADOW":                        "owns shadow mutations itself (shadowContentAccessPrerequisite)",
	"PATH-ENV-FILE":                          "creating or editing a project .env file is ordinary work",
	"PATH-PROC-ENVIRON":                      "a process environment is not a writable file",
	"PATH-PASSWORD-CRACKER-POTFILE":          "a recovered-password store no tool trusts for identity",
	"secrets.cloud_metadata_credential_read": "a metadata endpoint, not a file",
	"secrets.structured_credential_extract":  "an extraction tool, not a file",
	"secrets.workload_identity_token_read":   "a read-only projected service-account mount",
	"secrets.browser_session_store_read":     "browser stores: write detection is 1.0.10 (#1189)",
	"secrets.credential_file_write":          "is the write leg",
	"PATH-WIN-SSH-KEY":                       "its write leg is PATH-SSH-DIR (GAP-1666)",
	"PATH-WIN-PS-HISTORY":                    "PATH-HISTORY owns history mutations",
	"PATH-WIN-CREDENTIAL-MANAGER":            "an OS store written through its API: 1.0.10 (#1189)",
	"PATH-WIN-DPAPI":                         "an OS store written through its API: 1.0.10 (#1189)",
	"PATH-WIN-SAM":                           "a registry hive the OS holds open",
	"PATH-WIN-SECURITY-HIVE":                 "a registry hive the OS holds open",
	"PATH-WIN-SYSTEM-HIVE":                   "a registry hive the OS holds open",
}
