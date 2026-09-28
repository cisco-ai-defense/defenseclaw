// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Per-run managed harness configuration (connector.SandboxRunConfig): the
// manager renders it for every sandbox of a harness that reads it and
// bind-mounts each file read-only, in mount and copy mode alike, so the
// harness reads it with managed precedence and the workload cannot change
// it. The files live under <data_dir>/sandboxes/<name>/run-config until the
// sandbox is deleted. Every start renders them again from the re-resolved
// policy (refreshRunConfig) and rewrites them in place before the sandbox
// runs, so an administrator's change (allow_yolo, a required pack's MCP
// posture) reaches a stopped sandbox's next session; one the mounts cannot
// carry refuses the start.

// runConfigDirName is the per-sandbox directory of run files.
const runConfigDirName = "run-config"

// maxProjectMCPBytes bounds a repository MCP config the manager reads.
const maxProjectMCPBytes = 1 << 20

// MCPInventory is where a run's MCP servers come from: the user's own MCP
// servers for a harness (user scope, never a project's) that DefenseClaw
// inventoried and whose MCP policy does not block them, plus the ones it
// left behind with the reason. nil Options.MCP brings no server along.
type MCPInventory interface {
	SandboxMCPServers(ctx context.Context, harness string) ([]config.MCPServerEntry, []MCPSkip, error)
}

// MCPSkip is an MCP server a run leaves behind.
type MCPSkip struct {
	Name   string
	Reason string
}

// runConfig is a sandbox's rendered per-run configuration.
type runConfig struct {
	files   []connector.SandboxFile
	mcp     *sandboxapi.MCPSummary
	notices []string
}

// runConfigInput is what the per-run configuration depends on.
type runConfigInput struct {
	spec   *harness.Spec
	target connector.SandboxRenderTarget
	eff    *packs.Effective
	// yolo lets the harness skip its permission prompts (not safe mode).
	yolo        bool
	env         map[string]string
	credentials []string
	provider    *connector.SandboxModelProvider
	workdir     string
	project     string
}

// runConfigRecord is what a start needs to render a sandbox's run files
// again (refreshRunConfig) beyond its record and its OpenShell spec: none
// of it is secret.
type runConfigRecord struct {
	// Files are the in-sandbox paths of the files the sandbox mounts; its
	// mounts are fixed at create, so a render needing another set cannot
	// take effect.
	Files []string `json:"files"`
	// Credentials name the provider placeholder variables the run gets.
	Credentials []string `json:"credentials,omitempty"`
	// ModelProvider is the model provider the run pins.
	ModelProvider *connector.SandboxModelProvider `json:"model_provider,omitempty"`
	// Safe reports the files keep the harness's permission prompts.
	Safe bool `json:"safe"`
}

// planRunConfig renders the per-run files, or returns nil for a harness
// without per-run managed configuration.
func (m *Manager) planRunConfig(ctx context.Context, in runConfigInput) (*runConfig, error) {
	provider, ok := in.spec.Provider.(connector.SandboxRunConfigProvider)
	if !ok {
		return nil, nil
	}
	allowProject := in.eff.MCP.ProjectServers == packs.MCPProjectServersAllow
	summary := &sandboxapi.MCPSummary{ProjectServers: packs.MCPProjectServersBlock, Imported: []string{}}
	if allowProject {
		summary.ProjectServers = packs.MCPProjectServersAllow
	}
	project, projectOther := projectMCPServers(in.spec.Name, in.project)
	summary.Project = project

	var servers []connector.SandboxMCPServer
	var notices []string
	if !in.eff.MCP.Import {
		// --no-mcp, or a pack or setting that leaves MCP servers behind.
	} else if m.opts.MCP != nil {
		entries, skipped, err := m.opts.MCP.SandboxMCPServers(ctx, in.spec.Name)
		if err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "list the %s MCP servers to bring along: %v", in.spec.DisplayName, err)
		}
		for _, s := range skipped {
			summary.LeftBehind = append(summary.LeftBehind, sandboxapi.MCPLeftBehind{Name: displayMCPName(s.Name), Reason: s.Reason})
		}
		var dropped []string
		servers, summary.LeftBehind, dropped = importMCPServers(in.spec.Name, entries, summary.LeftBehind)
		if !allowProject && in.spec.Name == "codex" {
			servers, summary.LeftBehind = dropShadowedMCPServers(servers, project, summary.LeftBehind)
		}
		if len(dropped) > 0 {
			notices = append(notices, "MCP: "+strings.Join(dropped, "; ")+
				" (not passed into the sandbox; give a server a secret with --credential NAME=host)")
		}
	}
	for _, s := range servers {
		summary.Imported = append(summary.Imported, s.Name)
	}
	run := connector.SandboxRunConfig{
		Env: in.env, Credentials: in.credentials, ModelProvider: in.provider, Workdir: in.workdir,
		Safe: !in.yolo, MCPServers: servers, AllowProjectMCPServers: allowProject,
	}
	files, err := provider.SandboxRunFiles(in.target, run)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "render the %s run configuration: %v", in.spec.DisplayName, err)
	}
	if len(summary.LeftBehind) > 0 {
		parts := make([]string, 0, len(summary.LeftBehind))
		for _, s := range summary.LeftBehind {
			parts = append(parts, s.Name+" ("+s.Reason+")")
		}
		notices = append(notices, "MCP: not brought along: "+strings.Join(parts, ", "))
	}
	if names := projectMCPList(project, projectOther); names != "" {
		if allowProject {
			notices = append(notices, "MCP: the repository's servers "+names+
				" start without a DefenseClaw check (mcp.project_servers: allow)")
		} else {
			notices = append(notices, "MCP: blocked the repository's servers "+names+
				" (mcp.project_servers: block; a sandbox pack with mcp.project_servers: allow runs them)")
		}
	}
	return &runConfig{files: files, mcp: summary, notices: notices}, nil
}

// importMCPServers turns inventory entries into sandbox servers. Values
// that may be secrets never enter the sandbox: environment values and HTTP
// headers are dropped (their names are returned for the notice), and
// servers only this machine can reach, or that the harness cannot run,
// stay behind.
func importMCPServers(harnessName string, entries []config.MCPServerEntry, skipped []sandboxapi.MCPLeftBehind) ([]connector.SandboxMCPServer, []sandboxapi.MCPLeftBehind, []string) {
	var servers []connector.SandboxMCPServer
	var dropped []string
	seen := map[string]bool{}
	skip := func(name, reason string) {
		skipped = append(skipped, sandboxapi.MCPLeftBehind{Name: displayMCPName(name), Reason: reason})
	}
	for _, e := range entries {
		name := strings.TrimSpace(e.Name)
		switch {
		case e.Bundled:
			// The harness ships these itself.
			continue
		case seen[name]:
			continue
		case e.Disabled:
			skip(name, "disabled")
			continue
		}
		seen[name] = true
		s := connector.SandboxMCPServer{Name: name}
		transport := strings.ToLower(strings.TrimSpace(e.Transport))
		switch {
		case strings.TrimSpace(e.Command) != "":
			s.Command, s.Args = strings.TrimSpace(e.Command), append([]string(nil), e.Args...)
			if transport != "" && transport != "stdio" {
				skip(name, "unsupported transport "+transport)
				continue
			}
		case strings.TrimSpace(e.URL) != "":
			s.URL = strings.TrimSpace(e.URL)
			switch transport {
			case "", "http", "streamable-http", "streamable_http", "streamablehttp":
				s.Transport = "http"
			case "sse":
				if harnessName == "codex" {
					skip(name, "Codex does not support SSE servers")
					continue
				}
				s.Transport = "sse"
			default:
				skip(name, "unsupported transport "+transport)
				continue
			}
			if localMCPURL(s.URL) {
				skip(name, "runs on this machine, which the sandbox cannot reach")
				continue
			}
		default:
			skip(name, "no command or URL")
			continue
		}
		if err := connector.ValidateSandboxMCPServer(s); err != nil {
			skip(name, "not usable in a sandbox")
			continue
		}
		var names []string
		for key := range e.Env {
			names = append(names, key)
		}
		for key := range e.Headers {
			names = append(names, "header "+key)
		}
		if len(names) > 0 {
			sort.Strings(names)
			dropped = append(dropped, displayMCPName(name)+": "+strings.Join(sanitizeNames(names), ", "))
		}
		servers = append(servers, s)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	return servers, skipped, dropped
}

// dropShadowedMCPServers leaves behind an imported Codex server whose name a
// repository's .codex/config.toml also uses. Codex merges a trusted
// project's server table into the managed one key by key, and the managed
// table cannot remove the environment variables a project adds, so such a
// server would start with the repository's environment.
func dropShadowedMCPServers(servers []connector.SandboxMCPServer, project []string, skipped []sandboxapi.MCPLeftBehind) ([]connector.SandboxMCPServer, []sandboxapi.MCPLeftBehind) {
	shadowed := map[string]bool{}
	for _, name := range project {
		shadowed[name] = true
	}
	kept := servers[:0:0]
	for _, s := range servers {
		if shadowed[s.Name] {
			skipped = append(skipped, sandboxapi.MCPLeftBehind{Name: s.Name, Reason: "the repository defines a server of the same name"})
			continue
		}
		kept = append(kept, s)
	}
	return kept, skipped
}

// localMCPURL reports a remote server URL only the host can reach: a
// loopback, private or link-local address, or localhost.
func localMCPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}

// projectMCPServers lists the MCP servers a repository defines for the
// harness: .mcp.json for Claude Code, .codex/config.toml for Codex. Names a
// terminal cannot show safely are only counted (other).
func projectMCPServers(harnessName, project string) (names []string, other int) {
	if project == "" {
		return nil, 0
	}
	var entries []string
	switch harnessName {
	case "claudecode":
		data, err := safefile.ReadRegularFileBounded(filepath.Join(project, ".mcp.json"), maxProjectMCPBytes)
		if err != nil {
			return nil, 0
		}
		var doc struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return nil, 0
		}
		for name := range doc.MCPServers {
			entries = append(entries, name)
		}
	case "codex":
		dir := filepath.Join(project, ".codex")
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			return nil, 0
		}
		list, err := config.ReadMCPFromCodexConfigTOML(filepath.Join(dir, "config.toml"))
		if err != nil {
			return nil, 0
		}
		for _, e := range list {
			entries = append(entries, e.Name)
		}
	}
	sort.Strings(entries)
	for _, name := range entries {
		if safeMCPName.MatchString(name) {
			names = append(names, name)
		} else {
			other++
		}
	}
	return names, other
}

// projectMCPList renders names for a one-line notice.
func projectMCPList(names []string, other int) string {
	list := strings.Join(names, ", ")
	if other > 0 {
		more := fmt.Sprintf("%d with an unprintable name", other)
		if list == "" {
			return more
		}
		return list + " and " + more
	}
	return list
}

// safeMCPName is a server or variable name a notice can show verbatim.
var safeMCPName = regexp.MustCompile(`^[A-Za-z0-9 _.:@/-]{1,64}$`)

func displayMCPName(name string) string {
	if safeMCPName.MatchString(name) {
		return name
	}
	return "(unprintable name)"
}

func sanitizeNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, displayMCPName(n))
	}
	return out
}

// runConfigDir is where a sandbox's run files live on the host.
func (m *Manager) runConfigDir(name string) string {
	return filepath.Join(m.opts.DataDir, "sandboxes", name, runConfigDirName)
}

// paths lists the in-sandbox paths of the run files, sorted.
func (rc *runConfig) paths() []string {
	if rc == nil {
		return nil
	}
	out := make([]string, 0, len(rc.files))
	for _, f := range rc.files {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

// refreshRunConfig renders a stopped sandbox's run files again from its
// re-resolved policy eff before it starts, and rewrites them in place (the
// bind mounts bind their host paths, which the container resolves when it
// starts): safe mode follows the policy (launchYolo), and so do the MCP
// servers the run brings along and whether the project's own may start.
// env is the sandbox's creation environment (its OpenShell spec). A render
// that needs files the sandbox does not mount cannot take effect: when it
// is stricter than what the sandbox has, the start is refused (delete the
// sandbox and run it again); a looser one keeps the stricter files. It
// returns the MCP summary the files now carry.
func (m *Manager) refreshRunConfig(ctx context.Context, rec record, eff *packs.Effective, env map[string]string) (*sandboxapi.MCPSummary, *runConfigRecord, error) {
	spec, ok := harness.Get(rec.Harness)
	if !ok {
		return rec.MCP, rec.RunConfig, nil
	}
	if _, ok := spec.Provider.(connector.SandboxRunConfigProvider); !ok {
		return rec.MCP, rec.RunConfig, nil
	}
	yolo := rec.Yolo && eff.Yolo
	rr := rec.RunConfig
	if rr == nil {
		// A record from before run files were rendered again: they cannot
		// be rebuilt, so only a policy that wants them stricter matters.
		want := &sandboxapi.MCPSummary{ProjectServers: eff.MCP.ProjectServers}
		if rec.MCP != nil && eff.MCP.Import {
			want.Imported = rec.MCP.Imported
		}
		if runConfigTightened(!rec.Yolo, rec.MCP, !yolo, want) {
			return nil, nil, errRunConfigStricter(rec.Name)
		}
		return rec.MCP, rr, nil
	}
	target := connector.SandboxRenderTarget{
		IngressPort: m.opts.IngressPort, AgentVersion: rec.HarnessVersion, HookContractID: rec.HookContract,
	}
	rc, err := m.planRunConfig(ctx, runConfigInput{
		spec: spec, target: target, eff: eff, yolo: yolo, env: env, credentials: rr.Credentials,
		provider: rr.ModelProvider, workdir: rec.Workdir, project: rec.Project,
	})
	if err != nil || rc == nil {
		return rec.MCP, rr, err
	}
	if !slices.Equal(rc.paths(), sortedCopy(rr.Files)) {
		if runConfigTightened(rr.Safe, rec.MCP, !yolo, rc.mcp) {
			return nil, nil, errRunConfigStricter(rec.Name)
		}
		m.logf("sandbox %s: keeps its harness run configuration, which is stricter than its policy now asks", rec.Name)
		return rec.MCP, rr, nil
	}
	if _, err := m.writeRunConfig(rec.Name, rc); err != nil {
		return nil, nil, err
	}
	next := *rr
	next.Safe = !yolo
	return rc.mcp, &next, nil
}

// runConfigTightened reports a run posture (safe mode, MCP summary) that is
// stricter than the one the sandbox's files carry in some respect: safe
// mode now, the project's servers blocked now, or an imported server left
// behind now.
func runConfigTightened(haveSafe bool, have *sandboxapi.MCPSummary, wantSafe bool, want *sandboxapi.MCPSummary) bool {
	if wantSafe && !haveSafe {
		return true
	}
	if have == nil || want == nil {
		return false
	}
	if have.ProjectServers == packs.MCPProjectServersAllow && want.ProjectServers != packs.MCPProjectServersAllow {
		return true
	}
	for _, name := range have.Imported {
		if !slices.Contains(want.Imported, name) {
			return true
		}
	}
	return false
}

// errRunConfigStricter refuses a start whose policy wants harness settings
// the sandbox's mounted run files cannot take.
func errRunConfigStricter(name string) error {
	return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation,
		Message: "the sandbox policy now runs the harness under stricter settings (safe mode or MCP servers) than sandbox " + name +
			" was created with, and its configuration cannot change after create; delete it and run it again",
		Detail: "`defenseclaw sandbox delete " + name + "`, then `defenseclaw sandbox run` with the same project"}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// writeRunConfig writes the run files and returns their read-only bind
// mounts in docker driver form.
func (m *Manager) writeRunConfig(name string, rc *runConfig) ([]any, error) {
	if rc == nil || len(rc.files) == 0 {
		return nil, nil
	}
	dir := m.runConfigDir(name)
	if err := safefile.ProtectDirectory(dir); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "prepare the sandbox run configuration: %v", err)
	}
	mounts := make([]any, 0, len(rc.files))
	for _, f := range rc.files {
		host := filepath.Join(dir, runFileName(f.Path))
		if err := safefile.Write(host, f.Data); err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "write the sandbox run configuration: %v", err)
		}
		// The directory stays owner-only; the file itself must be readable
		// by the sandbox run-as user through the bind mount.
		if err := os.Chmod(host, 0o644); err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "write the sandbox run configuration: %v", err)
		}
		mounts = append(mounts, map[string]any{"type": "bind", "source": host, "target": f.Path, "read_only": true})
	}
	return mounts, nil
}

// removeRunConfig deletes a sandbox's run files.
func (m *Manager) removeRunConfig(name string) error {
	if err := os.RemoveAll(m.runConfigDir(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the run configuration of %s: %w", name, err)
	}
	return nil
}

// runFileName maps an in-sandbox path to a flat host file name.
func runFileName(sandboxPath string) string {
	return strings.ReplaceAll(strings.TrimPrefix(filepath.ToSlash(sandboxPath), "/"), "/", "__")
}

// withRunConfigMounts adds the run mounts to a template driver config.
func withRunConfigMounts(driver map[string]any, mounts []any) map[string]any {
	if len(mounts) == 0 {
		return driver
	}
	if driver == nil {
		driver = map[string]any{}
	}
	docker, _ := driver["docker"].(map[string]any)
	if docker == nil {
		docker = map[string]any{}
		driver["docker"] = docker
	}
	existing, _ := docker["mounts"].([]any)
	docker["mounts"] = append(append([]any{}, existing...), mounts...)
	return driver
}
