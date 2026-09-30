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

package sandboxcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// What `sandbox run` remembers of the sandbox it created, in the CLI's
// state (cliStateDir) next to the kept run log and the accepted undo point.
// The daemon keeps the sandbox's policy, mounts and credentials; the run's
// harness options and the names behind its banner are the CLI's. A later
// session (`connect`, or a shell wrapper's resume) passes the options
// again, the connect banner shows the run's Model and Secret lines, and the
// resume question does not call a flag the sandbox already has "ignored".
// Secret values are never kept, and --env values only as a digest.

// runLaunch is one sandbox's remembered run.
type runLaunch struct {
	// SandboxID ties the record to the sandbox: a later sandbox of the
	// same name does not inherit it.
	SandboxID string `json:"sandbox_id,omitempty"`
	// Args are the harness options passed after `--` (launchOptions: a
	// prompt is not replayed).
	Args []string `json:"args,omitempty"`
	// Credentials are the --credential NAME=host[:port] flags.
	Credentials []string `json:"credentials,omitempty"`
	GitHubWrite bool     `json:"github_write,omitempty"`
	// EnvNames are the --env names; EnvDigest tells two sets of --env
	// flags apart without keeping their values.
	EnvNames      []string `json:"env_names,omitempty"`
	EnvDigest     string   `json:"env_digest,omitempty"`
	LLM           string   `json:"llm,omitempty"`
	BedrockRegion string   `json:"bedrock_region,omitempty"`
	// ModelSource and ModelHosts are the banner's shared model credential
	// (the variable it came from and the hosts it works at); ModelNote the
	// banner's note for a run without one.
	ModelSource string   `json:"model_source,omitempty"`
	ModelHosts  []string `json:"model_hosts,omitempty"`
	ModelNote   string   `json:"model_note,omitempty"`
	Context     []string `json:"context,omitempty"`
	Unmask      []string `json:"unmask,omitempty"`
	HostPorts   []int    `json:"host_ports,omitempty"`
	NoMCP       bool     `json:"no_mcp,omitempty"`
	CPU         string   `json:"cpu,omitempty"`
	Memory      string   `json:"memory,omitempty"`
	NoSnapshot  bool     `json:"no_snapshot,omitempty"`
}

const runLaunchFile = "launch.json"

// newRunLaunch is what a run with o remembers of sandbox sb.
func newRunLaunch(sb *sandboxapi.Sandbox, spec *harness.Spec, o RunOptions, llm llmChoice) runLaunch {
	rec := runLaunch{
		SandboxID: sb.ID, Args: launchOptions(spec, o.Args), Credentials: o.Credentials, GitHubWrite: o.GitHubWrite,
		EnvNames: envNames(o.Env), EnvDigest: envDigest(o.Env), LLM: strings.ToLower(strings.TrimSpace(o.LLM)),
		BedrockRegion: o.BedrockRegion, Context: o.Context, Unmask: o.Unmask, HostPorts: o.HostPorts, NoMCP: o.NoMCP,
		CPU: strings.TrimSpace(o.CPU), Memory: strings.TrimSpace(o.Memory), NoSnapshot: o.NoSnapshot,
	}
	if llm.Credential != nil {
		rec.ModelSource, rec.ModelHosts = llm.Source, llm.Hosts
	} else {
		rec.ModelNote = llm.Note
	}
	return rec
}

// saveRunLaunch records the run that created sb (best effort: without it
// a later session shows less and asks again for the run's options).
func (a *App) saveRunLaunch(sb *sandboxapi.Sandbox, rec runLaunch) {
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := safefile.WritePrivate(filepath.Join(dir, runLaunchFile), data); err != nil {
		a.warn("could not remember the run's options for `" + CommandName + " connect " + sb.Name + "`: " + err.Error())
	}
}

// runLaunchOf returns what the run that created sb remembered, or nil.
func (a *App) runLaunchOf(sb *sandboxapi.Sandbox) *runLaunch {
	if sb == nil {
		return nil
	}
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return nil
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, runLaunchFile), 64<<10)
	if err != nil {
		return nil
	}
	var rec runLaunch
	if json.Unmarshal(data, &rec) != nil || rec.SandboxID != sb.ID {
		return nil
	}
	return &rec
}

// cleanCopyFile marks a copy-mode sandbox whose session ended with nothing
// to bring back: `delete` of it stopped need not warn about work it could
// not check.
const cleanCopyFile = "copy-clean.json"

type cleanCopyRecord struct {
	SandboxID string    `json:"sandbox_id,omitempty"`
	At        time.Time `json:"at"`
}

// markCleanCopy records that the session that ends now found sb's copy
// unchanged (best effort).
func (a *App) markCleanCopy(sb *sandboxapi.Sandbox) {
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return
	}
	if data, err := json.Marshal(cleanCopyRecord{SandboxID: sb.ID, At: a.Now().UTC()}); err == nil {
		_ = safefile.WritePrivate(filepath.Join(dir, cleanCopyFile), data)
	}
}

// cleanCopy reports whether sb's last session found its copy unchanged and
// it has not run since.
func (a *App) cleanCopy(sb *sandboxapi.Sandbox) bool {
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return false
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, cleanCopyFile), 4<<10)
	if err != nil {
		return false
	}
	var rec cleanCopyRecord
	if json.Unmarshal(data, &rec) != nil || rec.SandboxID != sb.ID {
		return false
	}
	return sb.StartedAt.IsZero() || !sb.StartedAt.After(rec.At)
}

// forgetCleanCopy drops the mark as the sandbox starts again.
func (a *App) forgetCleanCopy(name string) {
	if dir, err := a.cliStateDir(name); err == nil {
		_ = os.Remove(filepath.Join(dir, cleanCopyFile))
	}
}

// launchOptions are the harness options of args a later session passes
// again: every option with its value, up to the first word that is not
// one (a prompt, or a subcommand whose own options would not apply
// without it) and is not the harness's launch operand (launchOperand). A
// one-prompt run's arguments (the harness's print mode) are not kept at
// all. An option's value is the next word unless the option carries it
// (--model=x) or the word is another option or holds a space (a prompt
// after a switch). A harness whose command line holds no prompt word
// (keepsEveryArg) keeps every argument, in order.
func launchOptions(spec *harness.Spec, args []string) []string {
	if len(args) == 0 || printMode(spec, args) {
		return nil
	}
	if keepsEveryArg(spec) {
		return slices.Clone(args)
	}
	var out []string
	operand := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !operand && launchOperand(spec, arg) {
			out, operand = append(out, arg), true
			continue
		}
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			break
		}
		out = append(out, arg)
		if strings.Contains(arg, "=") || i+1 >= len(args) {
			continue
		}
		if next := args[i+1]; !strings.HasPrefix(next, "-") && !strings.ContainsAny(next, " \t\r\n") {
			out = append(out, next)
			i++
		}
	}
	return out
}

// keepsEveryArg reports whether every word of spec's interactive command
// line is a launch setting: `omnigent run [AGENT]` takes the agent (a YAML
// file or directory) as its one operand, with options before or after it,
// and a first message only through -p, a one-prompt run.
func keepsEveryArg(spec *harness.Spec) bool {
	return spec.Name == "omnigent"
}

// launchOperand reports whether word, a harness argument that is not an
// option, is launch configuration a later session needs again rather than
// a prompt or a one-off subcommand: OpenCode's project directory
// (`opencode [project]`) when it reads as a path, which none of OpenCode's
// subcommands does, and Hermes's chat, the interactive session a bare
// `hermes` starts.
func launchOperand(spec *harness.Spec, word string) bool {
	if strings.HasPrefix(word, "-") || strings.ContainsAny(word, " \t\r\n") {
		return false
	}
	switch spec.Name {
	case "opencode":
		return word == "." || word == ".." || strings.HasPrefix(word, "~") || strings.Contains(word, "/")
	case "hermes":
		return word == "chat"
	}
	return false
}

// sessionArgs are the harness arguments of a later session of a sandbox:
// the run's options, then the ones given now. Arguments that already start
// with the run's options (the run's command typed again) are taken as
// they are.
func sessionArgs(stored, given []string) []string {
	if len(stored) == 0 {
		return given
	}
	if len(given) >= len(stored) && slices.Equal(given[:len(stored)], stored) {
		return given
	}
	return append(append([]string(nil), stored...), given...)
}

func envNames(list []string) []string {
	var names []string
	for _, kv := range list {
		if k, _, ok := strings.Cut(kv, "="); ok && !slices.Contains(names, k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// envDigest identifies a set of --env flags: the last value of each name
// wins, as in ParseEnv.
func envDigest(list []string) string {
	if len(list) == 0 {
		return ""
	}
	env, err := ParseEnv(list)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "=" + env[k] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sameSet reports whether two flag lists hold the same values in any
// order.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func samePorts(a, b []int) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}
