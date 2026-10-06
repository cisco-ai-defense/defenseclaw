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

// Package configwrite is the single writer for config.yaml. Go and Python
// (cli/defenseclaw/config_writer.py) follow the same protocol on the same
// lock, so they interoperate:
//
//  1. Lock config.yaml.lock (O_RDWR|O_CREAT|O_NOFOLLOW, 0600): flock(LOCK_EX)
//     on POSIX, LockFileEx on byte 0 length 1 on Windows. Default timeout
//     DefaultLockTimeout; on timeout the error is ErrLockBusy.
//  2. Read the current bytes and their sha256; when Options.ExpectSHA256 is
//     set and differs, fail with ErrConflict (compare-and-swap).
//  3. Apply the changes as a node-level YAML patch that keeps comments and
//     order.
//  4. Validate the candidate bytes with the canonical validator (schema,
//     runtime semantics, guardrail profiles) before writing.
//  5. Write a temp file in the same directory, fsync, rename over the
//     config (MoveFileExW on Windows), fsync the directory. A failed
//     directory fsync is an error.
//  6. Write config.generation.json (GenerationState) the same way, with the
//     generation incremented.
//  7. Release the lock. Callers that own an audit logger record
//     config.change.applied from the Result.
//
// Both writers refuse when the host is StandaloneEnterprise() and the actor
// is not ActorLifecycle or ActorMigration. Under SecureClientIntegration()
// nothing changes.
package configwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

const (
	// LockSuffix is appended to the config path for the writer lock; it is
	// the same file Python's locked_config_yaml uses.
	LockSuffix = cfgtxn.LockSuffix
	// GenerationFileName is the writer's state file, next to config.yaml.
	GenerationFileName = cfgtxn.GenerationFileName
	// DefaultLockTimeout bounds the wait for another writer.
	DefaultLockTimeout = cfgtxn.DefaultLockTimeout
)

// Actors that may write on a managed (StandaloneEnterprise) host.
const (
	ActorMigration = "migration"
	ActorLifecycle = "lifecycle"
)

// Actor prefixes; the suffix is the OS user, token principal or decision ID.
const (
	ActorPrefixCLI      = "cli:"
	ActorPrefixTUI      = "tui:"
	ActorPrefixAPI      = "api:"
	ActorPrefixSandbox  = "sandbox:"
	ActorPrefixHandEdit = "hand-edit:"
)

var (
	// ErrConflict means config.yaml changed after the caller read it.
	ErrConflict = errors.New("configwrite: config.yaml changed since it was read")
	// ErrLockBusy means another writer held the lock past the timeout.
	ErrLockBusy = cfgtxn.ErrLockBusy
	// ErrManaged means the host is managed and the actor may not write.
	ErrManaged = errors.New("configwrite: this device is managed; policy changes are made in the management plane")
	// ErrNotImplemented was returned by the frozen stubs. Nothing returns it
	// now; it stays for callers that compiled against the stub contract.
	ErrNotImplemented = errors.New("configwrite: not implemented yet")
)

// Change is one edit. Path is dotted, with [i] for list items, for example
// asset_policy.skill.denied[0].name. A key that contains a dot is written
// ["a.b"]. Unset removes the key; Value is then ignored. An index equal to
// the list length appends.
type Change struct {
	Path  string
	Value any
	Unset bool
}

// Options describe who writes and why.
type Options struct {
	// Actor is ActorMigration, ActorLifecycle or a prefixed actor such as
	// "cli:alice".
	Actor string
	// Reason is a short human sentence recorded in the generation file.
	Reason string
	// ExpectSHA256 is the hex sha256 of the bytes the caller read; empty
	// skips the compare-and-swap check.
	ExpectSHA256 string
	// Timeout bounds the lock wait; zero means DefaultLockTimeout.
	Timeout time.Duration
}

// Result describes a committed write.
type Result struct {
	// Generation is the new config_generation.
	Generation uint64
	// SHA256 is the hex sha256 of the written bytes.
	SHA256 string
	// Changed lists the dotted paths whose value changed.
	Changed []string
	// RestartRequired lists the changed paths that need a gateway restart.
	RestartRequired []string
}

// GenerationState is config.generation.json.
type GenerationState = cfgtxn.GenerationState

// Apply edits config.yaml at path under the writer lock and returns the new
// generation. When no change alters a value nothing is written and the
// result carries the current generation.
func Apply(ctx context.Context, path string, changes []Change, opt Options) (Result, error) {
	return transact(ctx, path, opt, func(current []byte) ([]byte, []string, error) {
		return patchDocument(current, changes)
	})
}

// ReplaceDocument writes raw as the whole config.yaml at path under the
// writer lock, after the same validation. Migrations and restores use it.
func ReplaceDocument(ctx context.Context, path string, raw []byte, opt Options) (Result, error) {
	candidate := append([]byte(nil), raw...)
	return transact(ctx, path, opt, func(current []byte) ([]byte, []string, error) {
		changed, err := diffDocuments(current, candidate)
		if err != nil {
			return nil, nil, err
		}
		return candidate, changed, nil
	})
}

// Locked runs install with config.yaml.lock held and then records the
// bytes now at path in config.generation.json. It is for writers that
// install the file themselves under their own transaction, such as the
// enterprise lifecycle (actor ActorLifecycle). install returns whether it
// changed the file; an unchanged file keeps the generation.
func Locked(ctx context.Context, path string, opt Options, install func() (bool, error)) (Result, error) {
	if err := checkActor(opt.Actor); err != nil {
		return Result{}, err
	}
	txn, err := cfgtxn.Begin(ctx, path, opt.Timeout)
	if err != nil {
		return Result{}, err
	}
	defer txn.Close()
	changed, err := install()
	if err != nil {
		return Result{}, err
	}
	raw, _, _, err := txn.Read()
	if err != nil {
		return Result{}, err
	}
	sum := cfgtxn.SHA256Hex(raw)
	if !changed {
		state, _ := cfgtxn.ReadGenerationState(txn.Path())
		return Result{Generation: state.Generation, SHA256: sum}, nil
	}
	state, err := txn.RecordGeneration(sum, opt.Actor, opt.Reason)
	if err != nil {
		return Result{}, err
	}
	return Result{Generation: state.Generation, SHA256: sum}, nil
}

// LockPath returns the writer lock path for a config path.
func LockPath(configPath string) string { return cfgtxn.LockPath(configPath) }

// GenerationPath returns the config.generation.json path for a config path.
func GenerationPath(configPath string) string { return cfgtxn.GenerationPath(configPath) }

// ReadGenerationState reads config.generation.json next to configPath. A
// missing file returns os.ErrNotExist (wrapped).
func ReadGenerationState(configPath string) (GenerationState, error) {
	return cfgtxn.ReadGenerationState(configPath)
}

// SHA256Hex is the hex sha256 the writer records and compares
// (Options.ExpectSHA256, Result.SHA256).
func SHA256Hex(raw []byte) string { return cfgtxn.SHA256Hex(raw) }

// CurrentActor returns prefix + the OS user name ("cli:alice").
func CurrentActor(prefix string) string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	if name == "" {
		name = "unknown"
	}
	return prefix + name
}

func checkActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("configwrite: an actor is required")
	}
	return nil
}

// managedRefuses reports whether the managed gate refuses actor for the
// current bytes: a standalone managed document (or environment) and an
// actor other than the lifecycle or a migration.
func managedRefuses(current []byte, actor string) bool {
	if actor == ActorLifecycle || actor == ActorMigration {
		return false
	}
	return config.StandaloneManagedSource(current)
}

type mutateFunc func(current []byte) (candidate []byte, changed []string, err error)

func transact(ctx context.Context, path string, opt Options, mutate mutateFunc) (Result, error) {
	if err := checkActor(opt.Actor); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(path) == "" {
		path = config.ConfigPath()
	}
	// Refuse a managed host before the lock opens: taking it creates the
	// lock file and, on a read-only or admin-owned directory, would fail
	// with a permission error that hides the managed refusal. The check is
	// repeated under the lock below.
	if unlocked, readErr := os.ReadFile(path); readErr == nil || os.IsNotExist(readErr) {
		if managedRefuses(unlocked, opt.Actor) {
			return Result{}, ErrManaged
		}
	}
	txn, err := cfgtxn.Begin(ctx, path, opt.Timeout)
	if err != nil {
		return Result{}, err
	}
	defer txn.Close()

	current, mode, exists, err := txn.Read()
	if err != nil {
		return Result{}, err
	}
	sum := cfgtxn.SHA256Hex(current)
	if opt.ExpectSHA256 != "" && !strings.EqualFold(opt.ExpectSHA256, sum) {
		return Result{}, ErrConflict
	}
	if managedRefuses(current, opt.Actor) {
		return Result{}, ErrManaged
	}
	candidate, changed, err := mutate(current)
	if err != nil {
		return Result{}, err
	}
	if exists && bytes.Equal(candidate, current) {
		state, _ := cfgtxn.ReadGenerationState(txn.Path())
		return Result{Generation: state.Generation, SHA256: sum}, nil
	}
	if err := config.ValidateCandidate(txn.Path(), candidate); err != nil {
		return Result{}, fmt.Errorf("configwrite: the change does not validate: %w", err)
	}
	// An editing writer also proves the rule packs and rule IDs load, so a
	// bad reference is refused here instead of failing every later reload.
	// Migrations and the lifecycle install what they were given.
	if opt.Actor != ActorMigration && opt.Actor != ActorLifecycle {
		if err := config.ValidateCandidateAssets(txn.Path(), candidate); err != nil {
			return Result{}, fmt.Errorf("configwrite: the change does not validate: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	state, err := txn.Commit(candidate, mode, opt.Actor, opt.Reason)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Generation:      state.Generation,
		SHA256:          state.ConfigSHA256,
		Changed:         changed,
		RestartRequired: RestartRequired(changed),
	}, nil
}

// restartKeys are the keys a running gateway applies only after a restart:
// the process-level keys of spec section 4, plus what its reload still
// treats as restart-required (internal/gateway diffConfigs and
// guardrailNeedsRestart): claw, agent and routing (paths, identity and the
// model router process captured at start), the guardrail listener and
// enablement, and the hook settings setup bakes into the installed hooks.
// "*" matches one segment. Everything else is hot; a
// running gateway keeps a restart-required value at its running value and
// applies the rest of the change.
var restartKeys = []string{
	"data_dir",
	"observability.local.path",
	"observability.local.judge_bodies_path",
	"gateway",
	"guardrail.host", "guardrail.port", "guardrail.enabled", "guardrail.connector",
	"guardrail.scanner_mode", "guardrail.retain_judge_bodies",
	"guardrail.hook_fail_mode", "guardrail.hook_self_heal", "guardrail.hook_self_heal_debounce_ms",
	"guardrail.connectors.*.enabled", "guardrail.connectors.*.hook_fail_mode",
	"claw", "agent", "routing",
	"deployment_mode", "enterprise.profile", "enterprise.network",
	"environment", "tenant_id", "workspace_id", "discovery_source",
}

// RestartRequired returns the paths in changed that need a gateway restart.
func RestartRequired(changed []string) []string {
	var out []string
	for _, path := range changed {
		segs := restartSegments(path)
		if hotGatewayPath(segs) {
			continue
		}
		for _, key := range restartKeys {
			if restartKeyMatches(segs, strings.Split(key, ".")) {
				out = append(out, path)
				break
			}
		}
	}
	return out
}

// hotGatewayPath reports the gateway keys a reload applies in place: the
// install watcher settings and every config_reload key but its mode.
func hotGatewayPath(segs []string) bool {
	if len(segs) >= 3 && segs[0] == "gateway" && segs[1] == "config_reload" {
		return segs[2] != "mode"
	}
	return len(segs) >= 2 && segs[0] == "gateway" && segs[1] == "watcher"
}

// restartKeyMatches reports whether a change at path touches key: path is
// key, under it, or an ancestor of it.
func restartKeyMatches(path, key []string) bool {
	n := len(path)
	if len(key) < n {
		n = len(key)
	}
	for i := 0; i < n; i++ {
		if key[i] != "*" && key[i] != path[i] {
			return false
		}
	}
	return true
}

// restartSegments splits a change path into its key segments, dropping list
// indexes and quoting (a.b[0]["c.d"] is a, b, c.d).
func restartSegments(path string) []string {
	parts, err := parsePath(path)
	if err != nil {
		return strings.Split(path, ".")
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if !part.isIdx {
			out = append(out, part.key)
		}
	}
	return out
}

// pathPart is one segment of a change path: a mapping key or a list index.
type pathPart struct {
	key   string
	index int
	isIdx bool
}

// parsePath splits a change path (a.b[0]["c.d"]) into its segments.
func parsePath(path string) ([]pathPart, error) {
	var parts []pathPart
	i := 0
	expectKey := true
	for i < len(path) {
		switch c := path[i]; {
		case c == '.':
			if expectKey {
				return nil, fmt.Errorf("configwrite: empty segment in path %q", path)
			}
			expectKey = true
			i++
		case c == '[':
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("configwrite: unclosed [ in path %q", path)
			}
			inner := path[i+1 : i+end]
			if strings.HasPrefix(inner, `"`) && strings.HasSuffix(inner, `"`) && len(inner) >= 2 {
				// A quoted key may itself contain ']'; find the closing quote.
				close := strings.Index(path[i+2:], `"]`)
				if close < 0 {
					return nil, fmt.Errorf("configwrite: unclosed quoted key in path %q", path)
				}
				parts = append(parts, pathPart{key: path[i+2 : i+2+close]})
				i = i + 2 + close + 2
			} else {
				var n int
				if _, err := fmt.Sscanf(inner, "%d", &n); err != nil || n < 0 || fmt.Sprint(n) != inner {
					return nil, fmt.Errorf("configwrite: bad list index [%s] in path %q", inner, path)
				}
				parts = append(parts, pathPart{index: n, isIdx: true})
				i += end + 1
			}
			expectKey = false
		default:
			if !expectKey {
				return nil, fmt.Errorf("configwrite: missing . before %q in path %q", path[i:], path)
			}
			end := strings.IndexAny(path[i:], ".[")
			if end < 0 {
				end = len(path) - i
			}
			parts = append(parts, pathPart{key: path[i : i+end]})
			i += end
			expectKey = false
		}
	}
	if len(parts) == 0 || expectKey {
		return nil, fmt.Errorf("configwrite: empty path %q", path)
	}
	if parts[0].isIdx {
		return nil, fmt.Errorf("configwrite: path %q must start with a key", path)
	}
	return parts, nil
}

func parseDocument(current []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(current)) > 0 {
		if err := yaml.Unmarshal(current, &doc); err != nil {
			return nil, fmt.Errorf("configwrite: parse config.yaml: %w", err)
		}
	}
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configwrite: config.yaml root must be a mapping")
	}
	return &doc, nil
}

func encodeDocument(doc *yaml.Node) ([]byte, error) {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, fmt.Errorf("configwrite: encode config.yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("configwrite: encode config.yaml: %w", err)
	}
	return out.Bytes(), nil
}

func patchDocument(current []byte, changes []Change) ([]byte, []string, error) {
	doc, err := parseDocument(current)
	if err != nil {
		return nil, nil, err
	}
	var changed []string
	for _, change := range changes {
		parts, err := parsePath(change.Path)
		if err != nil {
			return nil, nil, err
		}
		before := lookup(doc.Content[0], parts)
		if change.Unset {
			if before == nil {
				continue
			}
			if err := unsetPath(doc.Content[0], parts); err != nil {
				return nil, nil, fmt.Errorf("configwrite: unset %s: %w", change.Path, err)
			}
			changed = append(changed, change.Path)
			continue
		}
		value, err := valueNode(change.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("configwrite: value for %s: %w", change.Path, err)
		}
		if before != nil && sameValue(before, value) {
			continue
		}
		if err := setPath(doc.Content[0], parts, value); err != nil {
			return nil, nil, fmt.Errorf("configwrite: set %s: %w", change.Path, err)
		}
		changed = append(changed, change.Path)
	}
	if len(changed) == 0 {
		return current, nil, nil
	}
	out, err := encodeDocument(doc)
	if err != nil {
		return nil, nil, err
	}
	return out, changed, nil
}

func valueNode(value any) (*yaml.Node, error) {
	if node, ok := value.(*yaml.Node); ok {
		return node, nil
	}
	var node yaml.Node
	if err := node.Encode(value); err != nil {
		return nil, err
	}
	return &node, nil
}

func sameValue(a, b *yaml.Node) bool {
	var left, right any
	if a.Decode(&left) != nil || b.Decode(&right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func mapLookup(m *yaml.Node, key string) (int, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i, m.Content[i+1]
		}
	}
	return -1, nil
}

func lookup(root *yaml.Node, parts []pathPart) *yaml.Node {
	cur := root
	for _, part := range parts {
		if cur == nil {
			return nil
		}
		if part.isIdx {
			if cur.Kind != yaml.SequenceNode || part.index >= len(cur.Content) {
				return nil
			}
			cur = cur.Content[part.index]
			continue
		}
		_, cur = mapLookup(cur, part.key)
	}
	return cur
}

func setPath(root *yaml.Node, parts []pathPart, value *yaml.Node) error {
	cur := root
	for i, part := range parts {
		last := i == len(parts)-1
		var next *yaml.Node
		if part.isIdx {
			if cur.Kind != yaml.SequenceNode {
				return fmt.Errorf("segment %d is not a list", i)
			}
			switch {
			case part.index < len(cur.Content):
				next = cur.Content[part.index]
				if last {
					keepComments(value, next)
					cur.Content[part.index] = value
					return nil
				}
			case part.index == len(cur.Content):
				next = newContainer(parts, i+1, value, last)
				cur.Content = append(cur.Content, next)
				if last {
					return nil
				}
			default:
				return fmt.Errorf("list index %d is past the end (%d items)", part.index, len(cur.Content))
			}
		} else {
			if cur.Kind != yaml.MappingNode {
				return fmt.Errorf("segment %q is not a mapping", part.key)
			}
			idx, existing := mapLookup(cur, part.key)
			if existing != nil {
				if last {
					keepComments(value, existing)
					cur.Content[idx+1] = value
					return nil
				}
				if existing.Kind == yaml.ScalarNode && existing.Tag == "!!null" {
					*existing = *newContainer(parts, i+1, value, false)
				}
				next = existing
			} else {
				next = newContainer(parts, i+1, value, last)
				cur.Content = append(cur.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part.key}, next)
				if last {
					return nil
				}
			}
		}
		cur = next
	}
	return nil
}

// newContainer returns value for the last segment, else an empty mapping or
// list matching the next segment.
func newContainer(parts []pathPart, nextIndex int, value *yaml.Node, last bool) *yaml.Node {
	if last {
		return value
	}
	if parts[nextIndex].isIdx {
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func keepComments(dst, src *yaml.Node) {
	if dst.HeadComment == "" {
		dst.HeadComment = src.HeadComment
	}
	if dst.LineComment == "" {
		dst.LineComment = src.LineComment
	}
	if dst.FootComment == "" {
		dst.FootComment = src.FootComment
	}
}

func unsetPath(root *yaml.Node, parts []pathPart) error {
	parent := lookup(root, parts[:len(parts)-1])
	if len(parts) == 1 {
		parent = root
	}
	if parent == nil {
		return nil
	}
	last := parts[len(parts)-1]
	if last.isIdx {
		if parent.Kind != yaml.SequenceNode || last.index >= len(parent.Content) {
			return nil
		}
		parent.Content = append(parent.Content[:last.index], parent.Content[last.index+1:]...)
		return nil
	}
	idx, _ := mapLookup(parent, last.key)
	if idx < 0 {
		return nil
	}
	parent.Content = append(parent.Content[:idx], parent.Content[idx+2:]...)
	return nil
}

// ChangedPaths lists the leaf paths whose values differ between two config
// documents (what Result.Changed carries), for a caller that installs the
// document itself and still needs to know what it changed.
func ChangedPaths(before, after []byte) ([]string, error) { return diffDocuments(before, after) }

// diffDocuments lists the leaf paths whose values differ between two
// documents. Lists compare as a whole.
func diffDocuments(before, after []byte) ([]string, error) {
	var left, right any
	if len(bytes.TrimSpace(before)) > 0 {
		if err := yaml.Unmarshal(before, &left); err != nil {
			// An unparseable current file is replaced wholesale.
			left = nil
		}
	}
	if err := yaml.Unmarshal(after, &right); err != nil {
		return nil, fmt.Errorf("configwrite: parse the new document: %w", err)
	}
	var out []string
	diffValues("", left, right, &out)
	sort.Strings(out)
	return out, nil
}

func diffValues(prefix string, left, right any, out *[]string) {
	lm, lok := left.(map[string]any)
	rm, rok := right.(map[string]any)
	if lok && rok {
		keys := map[string]struct{}{}
		for k := range lm {
			keys[k] = struct{}{}
		}
		for k := range rm {
			keys[k] = struct{}{}
		}
		for k := range keys {
			child := k
			if prefix != "" {
				child = prefix + "." + k
			}
			diffValues(child, lm[k], rm[k], out)
		}
		return
	}
	if !reflect.DeepEqual(left, right) {
		if prefix == "" {
			prefix = "$"
		}
		*out = append(*out, prefix)
	}
}
