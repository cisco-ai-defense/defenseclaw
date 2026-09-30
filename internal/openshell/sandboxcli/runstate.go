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
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// What `sandbox run` remembers of the sandbox it created, in the CLI's
// state (cliStateDir).
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
		EnvNames: envNames(o.Env), EnvDigest: envDigest(o.Env), LLM: firstNonEmpty(strings.ToLower(strings.TrimSpace(o.LLM)), llm.Configured),
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

// copyHandoverFile is what the CLI knows of a copy-mode sandbox's work
// between sessions, which stays in the sandbox until a pull brings it back:
// where it last went, and what the copy held when the sandbox last stopped.
// `delete` words its question from it, and a pull of the stopped sandbox
// takes the last pull again instead of starting the sandbox to read the
// same state.
const copyHandoverFile = "copy-handover.json"

type copyHandover struct {
	// SandboxID ties the record to the sandbox: a later sandbox of the same
	// name does not inherit it.
	SandboxID string `json:"sandbox_id,omitempty"`
	// Last is the last time the work was brought back; nil when it never
	// was.
	Last *handover `json:"last,omitempty"`
	// Stopped is what the copy held when a pull, a session's end or `sandbox
	// stop` looked at it and stopped the sandbox; nil once it starts again.
	Stopped *stoppedCopy `json:"stopped,omitempty"`
}

// handover is one bringing back of a sandbox's work.
type handover struct {
	Mode workspace.ApplyMode `json:"mode"`
	// Folder is where a 3-way apply put it; Branch and Patch are the branch
	// and patch file of --branch, --patch-out or an apply that could not
	// merge in place.
	Folder string    `json:"folder,omitempty"`
	Branch string    `json:"branch,omitempty"`
	Patch  string    `json:"patch,omitempty"`
	At     time.Time `json:"at"`
}

// stoppedCopy is what the copy held as the sandbox stopped.
type stoppedCopy struct {
	At time.Time `json:"at"`
	// Clean: nothing in it was left to bring back.
	Clean bool `json:"clean,omitempty"`
	// Pulled is the result of the last pull when the copy was in the state
	// that pull took; the next pull is made from it (PullOptions.Reuse).
	Pulled string `json:"pulled,omitempty"`
}

func (a *App) readCopyHandover(name string) (copyHandover, string) {
	dir, err := a.cliStateDir(name)
	if err != nil {
		return copyHandover{}, ""
	}
	path := filepath.Join(dir, copyHandoverFile)
	var rec copyHandover
	if data, err := safefile.ReadRegularFileBounded(path, 16<<10); err == nil && json.Unmarshal(data, &rec) != nil {
		rec = copyHandover{}
	}
	return rec, path
}

// updateCopyHandover changes sb's record (best effort: without it `delete`
// warns about work it cannot check, and a pull starts the sandbox).
func (a *App) updateCopyHandover(sb *sandboxapi.Sandbox, change func(*copyHandover)) {
	rec, path := a.readCopyHandover(sb.Name)
	if path == "" {
		return
	}
	if rec.SandboxID != sb.ID {
		rec = copyHandover{SandboxID: sb.ID}
	}
	change(&rec)
	if data, err := json.Marshal(rec); err == nil {
		_ = safefile.WritePrivate(path, data)
	}
}

// copyHandoverOf is sb's record, or nil.
func (a *App) copyHandoverOf(sb *sandboxapi.Sandbox) *copyHandover {
	if sb == nil {
		return nil
	}
	rec, _ := a.readCopyHandover(sb.Name)
	if rec.SandboxID == "" || rec.SandboxID != sb.ID {
		return nil
	}
	return &rec
}

// recordHandover records where an apply put sb's work.
func (a *App) recordHandover(sb *sandboxapi.Sandbox, r *workspace.ApplyResult) {
	if r == nil {
		return
	}
	h := &handover{Mode: r.Mode, Branch: r.Branch, Patch: r.PatchPath, At: a.Now().UTC()}
	switch {
	case r.Mode == workspace.ApplyMerge && (r.Applied || r.UpToDate):
		h.Folder, h.Branch, h.Patch = sb.Project, "", ""
	case r.Branch != "":
		h.Mode = workspace.ApplyBranch
	case r.PatchPath != "":
		h.Mode = workspace.ApplyPatch
	default:
		return
	}
	a.updateCopyHandover(sb, func(rec *copyHandover) {
		if old := rec.Last; r.UpToDate && old != nil && old.Mode == h.Mode && old.Folder == h.Folder && old.Branch == h.Branch {
			// It is where it went the last time, since then.
			return
		}
		rec.Last = h
	})
}

// markStoppedCopy records what sb's copy held as it stopped: nothing left
// to bring back (clean), and the last pull when the copy was in its state.
func (a *App) markStoppedCopy(sb *sandboxapi.Sandbox, clean bool, pulled string) {
	a.updateCopyHandover(sb, func(rec *copyHandover) {
		rec.Stopped = nil
		if clean || pulled != "" {
			rec.Stopped = &stoppedCopy{At: a.Now().UTC(), Clean: clean, Pulled: pulled}
		}
	})
}

// stoppedCopyOf is what sb's copy held as it last stopped, when sb has not
// run since: it is not running, and nothing dropped the mark (every start
// goes through this CLI, which drops it, and so do a session and a `sandbox
// exec` in the running sandbox: forgetStoppedCopy).
func (a *App) stoppedCopyOf(sb *sandboxapi.Sandbox) *stoppedCopy {
	rec := a.copyHandoverOf(sb)
	if rec == nil || rec.Stopped == nil || sb.Phase == "ready" || sb.StartedAt.After(rec.Stopped.At) {
		return nil
	}
	return rec.Stopped
}

// cleanCopy reports whether nothing was left in sb's copy to bring back
// when it last stopped, and it has not run since.
func (a *App) cleanCopy(sb *sandboxapi.Sandbox) bool {
	st := a.stoppedCopyOf(sb)
	return st != nil && st.Clean
}

// forgetStoppedCopy drops what was known of the copy of sandbox name as it
// stopped, as it starts again; where its work last went stays.
func (a *App) forgetStoppedCopy(name string) {
	rec, path := a.readCopyHandover(name)
	if path == "" || rec.Stopped == nil {
		return
	}
	rec.Stopped = nil
	if data, err := json.Marshal(rec); err == nil {
		_ = safefile.WritePrivate(path, data)
	}
}

// forgetApply is an undone apply of sb's work: that work is in the sandbox
// alone again, and the apply is no longer where it went.
func (a *App) forgetApply(sb *sandboxapi.Sandbox) {
	a.updateCopyHandover(sb, func(rec *copyHandover) {
		if rec.Stopped != nil {
			rec.Stopped.Clean = false
		}
		if rec.Last != nil && rec.Last.Mode == workspace.ApplyMerge {
			rec.Last = nil
		}
	})
}

// handoverText is where a hand-over put the work: "applied to ~/code/app
// at 14:03".
func (a *App) handoverText(h *handover) string {
	var where string
	switch {
	case h.Mode == workspace.ApplyMerge:
		where = "applied to " + a.tildePath(h.Folder)
	case h.Branch != "" && h.Patch != "":
		where = "put on branch " + h.Branch + " and in " + a.tildePath(h.Patch)
	case h.Branch != "":
		where = "put on branch " + h.Branch
	default:
		where = "written to " + a.tildePath(h.Patch)
	}
	return where + " at " + a.clock(h.At)
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
