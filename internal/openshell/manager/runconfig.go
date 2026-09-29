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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
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
//
// A driver that mounts no host folders (OpenShell's MicroVM driver) gets
// the files baked into a run image instead (deliverRunConfig,
// image.Builder.RunImage), root-owned and read-only like the mounts, and
// nothing is written on the host. They cannot change after create: a start
// whose policy wants them stricter is refused, and a looser one keeps them.

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
	// baked says the files go into a run image (the driver's
	// RunFilesInImage), which outlives the sandbox: an imported MCP server
	// whose arguments or URL look like they carry a credential stays
	// behind.
	baked bool
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
	// Delivery is how the sandbox got the files: runDeliveryMount, or
	// runDeliveryImage. Empty in records from before it was kept, which
	// all mount them.
	Delivery string `json:"delivery,omitempty"`
	// Digest is the files' image.RunConfigDigest.
	Digest string `json:"digest,omitempty"`
}

// Run file deliveries (runConfigRecord.Delivery).
const (
	// runDeliveryMount bind-mounts the files read-only from the host, on a
	// driver with host mounts (docker).
	runDeliveryMount = "mount"
	// runDeliveryImage bakes them into the sandbox's run image, on a driver
	// that bakes them (openshell.Driver.RunFilesInImage).
	runDeliveryImage = "image"
)

// runDelivery is how a sandbox receives its run files, and the image its
// template names.
type runDelivery struct {
	// image is the template's image: the overlay image's tag, or on a
	// driver with its own image repository the run image or the alias.
	image string
	// runImage is that run image or alias.
	runImage *image.RunImage
	// mounts are the files' read-only bind mounts (runDeliveryMount).
	mounts []any
	// how is the delivery, and digest the files' image.RunConfigDigest.
	how, digest string
}

// deliverRunConfig delivers a sandbox's run files (rc; nil for a harness
// without them) as the gateway's compute driver d can take them. With host
// mounts (docker) it writes them under the sandbox's run-config directory
// and returns their read-only bind mounts, and the template names the
// overlay image img. On a driver that bakes them into an image it writes
// nothing on the host: the template names the run image of img with the
// files, or img's alias for a harness without run files, under the driver's
// image repository, which no registry serves. extraEnv is the request's
// --env, whose credentials are never baked into an image.
func (m *Manager) deliverRunConfig(ctx context.Context, d openshell.Driver, name string, img image.Record, rc *runConfig,
	extraEnv map[string]string) (runDelivery, error) {
	out := runDelivery{image: img.Tag}
	switch {
	case rc != nil && d.RunFilesInImage:
		out.how, out.digest = runDeliveryImage, image.RunConfigDigest(rc.files)
		if k := bakedSecret(rc.files, extraEnv); k != "" {
			return runDelivery{}, &sandboxapi.Error{Code: sandboxapi.CodeInvalid,
				Message: "the value of " + k + " from --env would be baked into the image of sandbox " + name,
				Detail: "on a MicroVM gateway a sandbox's harness settings are part of its image, which outlives the sandbox; " +
					"pass it with `--credential " + k + "=<host>` instead, which OpenShell resolves only at egress"}
		}
		ri, err := m.opts.Images.RunImage(ctx, img, rc.files, d.ImageRepository)
		if err != nil {
			return runDelivery{}, m.runImageError(img, err)
		}
		out.image, out.runImage = ri.Tag, &ri
	case rc != nil && d.HostMounts:
		out.how, out.digest = runDeliveryMount, image.RunConfigDigest(rc.files)
		mounts, err := m.writeRunConfig(name, rc)
		if err != nil {
			return runDelivery{}, err
		}
		out.mounts = mounts
	case rc != nil:
		// driverRefusal refuses such a create before anything is made.
		return runDelivery{}, sandboxapi.Errorf(sandboxapi.CodeInternal,
			"sandbox %s: the gateway's compute driver takes the harness run configuration neither as mounts nor in an image", name)
	case d.ImageRepository != "":
		ri, err := m.opts.Images.AliasImage(ctx, img, d.ImageRepository)
		if err != nil {
			return runDelivery{}, m.runImageError(img, err)
		}
		out.image, out.runImage = ri.Tag, &ri
	}
	return out, nil
}

// runImageError reports a run image or alias that could not be made.
func (m *Manager) runImageError(img image.Record, err error) error {
	m.logf("%s: %s: run image: %v", gatewaylog.ErrCodeOpenShellImageBuildFailed, img.Connector, err)
	return &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable, Message: "the sandbox image with this run's harness settings could not be made from " + img.Tag,
		Detail: err.Error()}
}

// runFileSecretEnv are the variables a harness's run files pin whose value
// is a credential: Claude Code's drop-in pins the bearer token and the
// extra headers of every model request to the run's values
// (connector.ClaudeCodeSandboxProviderEnv).
var runFileSecretEnv = []string{"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS"}

// bakedSecret names the --env variable (extra), if any, whose value the run
// files carry and which is a credential: one of runFileSecretEnv, or a URL
// with a user name or password in it, or with a query or fragment value,
// where gateways take keys and tokens (a base URL such as
// https://gw.example/?key=...). Baked into a run image the value
// would outlive the sandbox, in a Docker layer anyone who reaches the Docker
// socket can read and in the disk the MicroVM driver prepares from the
// image and never removes. Credential placeholders are never in the files.
func bakedSecret(files []connector.SandboxFile, extra map[string]string) string {
	names := make([]string, 0, len(extra))
	for k := range extra {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := extra[k]
		if v == "" {
			continue
		}
		secret := slices.Contains(runFileSecretEnv, k)
		if u, err := url.Parse(v); err == nil && (u.User != nil || u.Host != "" && (u.Fragment != "" || queryValue(u))) {
			secret = true
		}
		if secret && filesCarry(files, v) {
			return k
		}
	}
	return ""
}

// filesCarry reports whether a file holds v, as is or JSON-escaped.
func filesCarry(files []connector.SandboxFile, v string) bool {
	quoted, _ := json.Marshal(v)
	escaped := quoted[1 : len(quoted)-1]
	for _, f := range files {
		if bytes.Contains(f.Data, []byte(v)) || bytes.Contains(f.Data, escaped) {
			return true
		}
	}
	return false
}

// runFileChecks are what the workload check after ready expects of the run
// files delivered how: baked into an image, owned by root with mode 0644;
// bind-mounted, mode 0644 on a read-only mount, owned by the host user who
// wrote them, which is the workload's uid:gid.
func runFileChecks(files []connector.SandboxFile, how string, uid, gid int) []verifyFile {
	out := make([]verifyFile, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		v := verifyFile{Path: f.Path, SHA256: hex.EncodeToString(sum[:]), Mode: 0o644}
		if how != runDeliveryImage {
			v.UID, v.GID, v.ReadOnlyMount = uid, gid, true
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// withRunFileChecks is v with checks in place of what it held for the same
// paths; a nil v starts one for the workload identity uid:gid. v itself is
// never changed (verifyRecord is replaced, not changed in place).
func withRunFileChecks(v *verifyRecord, uid, gid int, checks []verifyFile) *verifyRecord {
	next := &verifyRecord{UID: uid, GID: gid}
	if v != nil {
		next.UID, next.GID, next.Files = v.UID, v.GID, slices.Clone(v.Files)
	}
	replaced := map[string]bool{}
	for _, c := range checks {
		replaced[c.Path] = true
	}
	next.Files = slices.DeleteFunc(next.Files, func(f verifyFile) bool { return replaced[f.Path] })
	next.Files = append(next.Files, checks...)
	sort.Slice(next.Files, func(i, j int) bool { return next.Files[i].Path < next.Files[j].Path })
	return next
}

// runWorkdir is the workdir a sandbox's run files are rendered with: its
// own, but none on a driver that bakes them into an image. The workdir
// names the repository (/sandbox/work/<repo>), and in the files (Codex
// starts imported stdio MCP servers there) it would make each repository
// a posture of its own, with its own run image and so its own first boot
// and MicroVM disk. Without it the servers start where the harness does,
// which is the workdir.
func runWorkdir(d openshell.Driver, workdir string) string {
	if d.RunFilesInImage {
		return ""
	}
	return workdir
}

// vmFirstBoot reports whether a new sandbox that flags and eff describe
// would boot an image the gateway's compute driver d has not prepared yet
// (sandboxapi.Explain.VMFirstBoot): its run image, or its overlay image's
// alias, is not made yet, or the driver's image cache (under the home of
// the daemon, which runs as the gateway's user) holds no disk prepared
// from its image ID for the workload identity. A run image also depends
// on what only the create request carries, the model provider's settings,
// --env and --credential; the render takes them from the newest sandbox of
// the harness and image, whose runs usually share them, and assumes none
// without one. Always false on a driver that prepares nothing.
func (m *Manager) vmFirstBoot(ctx context.Context, cfg *config.Config, d openshell.Driver, flags packs.Flags, eff *packs.Effective) bool {
	spec, ok := harness.Get(flags.Harness)
	if d.ImageCache == "" || m.opts.Images == nil || !ok {
		return false
	}
	cache := m.vmImageCache(d)
	if cache == "" {
		return false
	}
	img, err := m.image(ctx, cfg, spec, d, false)
	if err != nil {
		// The image is built first, and then prepared.
		return true
	}
	id := img.ImageID
	if _, runFiles := spec.Provider.(connector.SandboxRunConfigProvider); runFiles {
		env, creds, provider := m.newestRunInputs(spec.Name, img.ImageID)
		target := connector.SandboxRenderTarget{IngressPort: m.opts.IngressPort, AgentVersion: img.HarnessVersion, HookContractID: img.HookContract}
		rc, err := m.planRunConfig(ctx, runConfigInput{
			spec: spec, target: target, eff: eff, yolo: eff.Yolo, env: env, credentials: creds,
			provider: provider, workdir: runWorkdir(d, ""), project: flags.Project, baked: d.RunFilesInImage,
		})
		if err != nil || rc == nil {
			return true
		}
		ri, ok, err := m.opts.Images.RecordedRunImage(ctx, img, rc.files, d.ImageRepository)
		if err != nil || !ok {
			return true
		}
		id = ri.ImageID
	}
	for _, disk := range image.VMDisks(cache, id) {
		if disk.UID == img.UID && disk.GID == img.GID {
			return false
		}
	}
	return true
}

// vmImageCache is where the gateway's compute driver d keeps what it
// prepares from each image: the directory Options.VMDiskFree reports (the
// gateway's state_dir, when its configuration sets one), else d.ImageCache
// under the home of the daemon's user, who runs the gateway. "" when
// neither is known.
func (m *Manager) vmImageCache(d openshell.Driver) string {
	if m.opts.VMDiskFree != nil {
		if dir, _, err := m.opts.VMDiskFree(); err == nil && dir != "" {
			return dir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || d.ImageCache == "" {
		return ""
	}
	return filepath.Join(home, d.ImageCache)
}

// newestRunInputs are the creation environment, credential names and model
// provider of the newest sandbox of harness on the overlay image imageID
// that has run files, or none.
func (m *Manager) newestRunInputs(harnessName, imageID string) (map[string]string, []string, *connector.SandboxModelProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var newest *box
	for _, b := range m.boxes {
		r := b.rec
		if r.Harness != harnessName || r.ImageID != imageID || r.RunConfig == nil || b.sb == nil {
			continue
		}
		if newest == nil || r.CreatedAt.After(newest.rec.CreatedAt) {
			newest = b
		}
	}
	if newest == nil {
		return nil, nil, nil
	}
	return maps.Clone(newest.sb.Spec.Environment), slices.Clone(newest.rec.RunConfig.Credentials), newest.rec.RunConfig.ModelProvider
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
		servers, summary.LeftBehind, dropped = importMCPServers(in.spec.Name, entries, summary.LeftBehind, in.eff.MCP.HostPorts)
		if in.baked {
			servers, summary.LeftBehind = dropCredentialMCPServers(servers, summary.LeftBehind)
		}
		for _, s := range servers {
			if port, ok := hostPortOfMCP(s.URL); ok {
				notices = append(notices, fmt.Sprintf("MCP: %s reaches port %d on this machine as %s:%d; it connects once you approve the sandbox's ask for the port",
					displayMCPName(s.Name), port, openshellHostAlias, port))
			}
		}
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
// stay behind. A server on this machine's loopback whose port is one of
// the run's accepted host ports (hostPorts) comes along, pointed at
// host.openshell.internal; for another port, the reason names the
// --host-port that would bring it.
func importMCPServers(harnessName string, entries []config.MCPServerEntry, skipped []sandboxapi.MCPLeftBehind,
	hostPorts []int) ([]connector.SandboxMCPServer, []sandboxapi.MCPLeftBehind, []string) {
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
				rewritten, why := hostPortMCPURL(s.URL, hostPorts)
				if rewritten == "" {
					skip(name, why)
					continue
				}
				s.URL = rewritten
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

// bakedMCPCredential is why an imported server whose command line or URL
// looks like it carries a credential stays behind on a driver that bakes
// the run files into an image.
const bakedMCPCredential = "its arguments or URL look like they carry a credential, which a MicroVM sandbox's image would keep " +
	"after the sandbox is gone; give it the secret with --credential NAME=host"

// dropCredentialMCPServers leaves behind the imported servers whose
// arguments or URL look like they carry a credential (mcpCredential). On a
// driver that bakes the run files into a run image their command lines and
// URLs would sit in a Docker layer and in the disk the MicroVM driver
// prepares from it, which outlive the sandbox; on docker they stay in the
// sandbox's owner-only run-config directory and go with it.
func dropCredentialMCPServers(servers []connector.SandboxMCPServer, skipped []sandboxapi.MCPLeftBehind) ([]connector.SandboxMCPServer, []sandboxapi.MCPLeftBehind) {
	kept := servers[:0:0]
	for _, s := range servers {
		if mcpCredential(s) {
			skipped = append(skipped, sandboxapi.MCPLeftBehind{Name: displayMCPName(s.Name), Reason: bakedMCPCredential})
			continue
		}
		kept = append(kept, s)
	}
	return kept, skipped
}

// credentialWords are the words of a flag, variable or header name that
// says its value is a credential (--api-key, --auth-token, GITHUB_TOKEN,
// X-API-Key).
var credentialWords = []string{"token", "secret", "password", "passwd", "apikey", "key", "auth", "authorization",
	"credential", "credentials", "bearer", "cookie"}

// credentialPrefixes start well-known credential formats (GitHub, OpenAI
// and Anthropic, Slack, AWS access keys, Stripe), of at least
// credentialMinLen characters.
var credentialPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "github_pat_", "sk-", "xoxb-", "xoxp-", "xoxa-", "AKIA", "sk_live_", "rk_live_"}

const credentialMinLen = 20

// mcpCredential reports an MCP server whose command line or URL looks like
// it carries a credential: a URL with a query or fragment value (where
// tokens and keys are passed), an argument that follows or holds the value
// of a credential flag (--api-key VALUE, --token=VALUE), a NAME=VALUE
// argument or a "Name: value" header with a credential name, a Bearer
// value, or a value in a well-known credential format. It errs on the side
// of leaving a server behind.
func mcpCredential(s connector.SandboxMCPServer) bool {
	if s.URL != "" {
		if u, err := url.Parse(s.URL); err != nil || u.User != nil || u.Fragment != "" || queryValue(u) {
			return true
		}
	}
	for i, arg := range s.Args {
		name, value, hasValue := strings.Cut(arg, "=")
		header, headerValue, isHeader := strings.Cut(arg, ":")
		switch {
		case strings.Contains(strings.ToLower(arg), "bearer "):
			return true
		case hasValue && value != "" && credentialName(name):
			// --token=VALUE, or NAME=VALUE for env(1) and the like.
			return true
		case isHeader && strings.TrimSpace(headerValue) != "" && credentialName(header):
			// --header "X-API-Key: VALUE" (mcp-remote and the like).
			return true
		case strings.HasPrefix(name, "-") && !hasValue && credentialName(name) && i+1 < len(s.Args) && !strings.HasPrefix(s.Args[i+1], "-"):
			// --api-key VALUE.
			return true
		}
		for _, v := range []string{arg, value, strings.TrimSpace(headerValue)} {
			for _, p := range credentialPrefixes {
				if len(v) >= credentialMinLen && strings.HasPrefix(v, p) {
					return true
				}
			}
		}
	}
	return false
}

// queryValue reports a URL whose query gives some parameter a value.
func queryValue(u *url.URL) bool {
	for _, values := range u.Query() {
		for _, v := range values {
			if v != "" {
				return true
			}
		}
	}
	return false
}

// credentialName reports a flag or variable name one of whose words is a
// credentialWords entry (--api-key, --github-token, CLIENT_SECRET).
func credentialName(name string) bool {
	words := strings.FieldsFunc(strings.ToLower(strings.TrimLeft(name, "-")), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for _, w := range words {
		if slices.Contains(credentialWords, w) {
			return true
		}
	}
	return false
}

// localMCPUnreachable is why a server only this machine reaches stays
// behind.
const localMCPUnreachable = "runs on this machine, which the sandbox cannot reach"

// hostPortMCPURL points a server URL on this machine's loopback (a
// localMCPURL) at host.openshell.internal when its port is one of the
// run's accepted host ports, through which the sandbox reaches the host's
// loopback. Otherwise it returns "" and why the server stays behind: for a
// loopback HTTP server, the --host-port that would bring it along. HTTPS
// stays behind: the server's certificate names localhost, not the alias.
func hostPortMCPURL(raw string, hostPorts []int) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", localMCPUnreachable
	}
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || strings.HasSuffix(host, ".localhost")
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if !loopback {
		return "", localMCPUnreachable
	}
	port, err := strconv.Atoi(u.Port())
	if u.Port() == "" {
		port, err = map[string]int{"http": 80, "https": 443}[strings.ToLower(u.Scheme)], nil
	}
	if err != nil || port <= 0 || port > 65535 {
		return "", localMCPUnreachable
	}
	if strings.ToLower(u.Scheme) != "http" {
		return "", "runs on this machine over " + strings.ToUpper(u.Scheme) + ", whose certificate cannot name " + openshellHostAlias
	}
	if !slices.Contains(hostPorts, port) {
		return "", fmt.Sprintf("%s; run the sandbox with --host-port %d to bring it along", localMCPUnreachable, port)
	}
	u.Host = net.JoinHostPort(openshellHostAlias, strconv.Itoa(port))
	return u.String(), ""
}

// hostPortOfMCP reports the host port an imported server reaches through
// host.openshell.internal.
func hostPortOfMCP(raw string) (int, bool) {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || !strings.EqualFold(u.Hostname(), openshellHostAlias) {
		return 0, false
	}
	port, err := strconv.Atoi(u.Port())
	return port, err == nil && port > 0
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
// sandbox and run it again); a looser one keeps the stricter files. Files
// baked into the sandbox's run image never change: a render with other
// files is refused when stricter and kept from when looser. It returns the
// MCP summary the files now carry, and what the workload check expects of
// them now (a rewrite changes their digests).
func (m *Manager) refreshRunConfig(ctx context.Context, rec record, eff *packs.Effective, env map[string]string) (*sandboxapi.MCPSummary, *runConfigRecord, *verifyRecord, error) {
	spec, ok := harness.Get(rec.Harness)
	if !ok {
		return rec.MCP, rec.RunConfig, rec.Verify, nil
	}
	if _, ok := spec.Provider.(connector.SandboxRunConfigProvider); !ok {
		return rec.MCP, rec.RunConfig, rec.Verify, nil
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
			return nil, nil, nil, errRunConfigStricter(rec, runConfigFixed)
		}
		return rec.MCP, rr, rec.Verify, nil
	}
	d, _ := openshell.LookupDriver(rec.Driver)
	target := connector.SandboxRenderTarget{
		IngressPort: m.opts.IngressPort, AgentVersion: rec.HarnessVersion, HookContractID: rec.HookContract,
	}
	rc, err := m.planRunConfig(ctx, runConfigInput{
		spec: spec, target: target, eff: eff, yolo: yolo, env: env, credentials: rr.Credentials,
		provider: rr.ModelProvider, workdir: runWorkdir(d, rec.Workdir), project: rec.Project, baked: d.RunFilesInImage,
	})
	if err != nil || rc == nil {
		return rec.MCP, rr, rec.Verify, err
	}
	if rr.Delivery == runDeliveryImage {
		if image.RunConfigDigest(rc.files) == rr.Digest {
			return rec.MCP, rr, rec.Verify, nil
		}
		if runConfigTightened(rr.Safe, rec.MCP, !yolo, rc.mcp) {
			return nil, nil, nil, errRunConfigStricter(rec, runConfigBaked)
		}
		m.logf("sandbox %s: keeps the harness run configuration baked into its image, which is stricter than its policy now asks", rec.Name)
		return rec.MCP, rr, rec.Verify, nil
	}
	if !slices.Equal(rc.paths(), sortedCopy(rr.Files)) {
		if runConfigTightened(rr.Safe, rec.MCP, !yolo, rc.mcp) {
			return nil, nil, nil, errRunConfigStricter(rec, runConfigFixed)
		}
		m.logf("sandbox %s: keeps its harness run configuration, which is stricter than its policy now asks", rec.Name)
		return rec.MCP, rr, rec.Verify, nil
	}
	if _, err := m.writeRunConfig(rec.Name, rc); err != nil {
		return nil, nil, nil, err
	}
	next := *rr
	next.Safe = !yolo
	next.Digest = image.RunConfigDigest(rc.files)
	verify := rec.Verify
	if verify != nil {
		// What was just written is what this session's check must find.
		verify = withRunFileChecks(verify, verify.UID, verify.GID, runFileChecks(rc.files, runDeliveryMount, verify.UID, verify.GID))
	}
	return rc.mcp, &next, verify, nil
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

// Why a sandbox's harness settings cannot follow a stricter policy
// (errRunConfigStricter).
const (
	runConfigFixed = "its configuration cannot change after create"
	runConfigBaked = "a MicroVM sandbox's harness settings are baked into its image at create"
)

// errRunConfigStricter refuses a start of rec whose policy wants harness
// settings its run files cannot take, and says why. A copy's work stays
// in the sandbox, and only a start reaches it (pull starts a stopped
// sandbox): deleting it first would discard what was never pulled.
func errRunConfigStricter(rec record, why string) error {
	name := rec.Name
	e := &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation,
		Message: "the sandbox policy now runs the harness under stricter settings (safe mode or MCP servers) than sandbox " + name +
			" was created with, and " + why + "; delete it and run it again",
		Detail: "`defenseclaw sandbox delete " + name + "`, then `defenseclaw sandbox run` with the same project"}
	if rec.WorkdirMode == config.OpenShellWorkdirCopy {
		e.Message = "the sandbox policy now runs the harness under stricter settings (safe mode or MCP servers) than sandbox " + name +
			" was created with, and " + why + ", so it cannot start; its work stays in it, and deleting it discards what was never pulled"
		e.Detail = "to bring the work back first, start it under the settings it was made with (undo the change that made the policy stricter, " +
			"or ask your administrator), `defenseclaw sandbox pull " + name + "`, then `defenseclaw sandbox delete " + name +
			"` and `defenseclaw sandbox run` with the same project"
	}
	return e
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
