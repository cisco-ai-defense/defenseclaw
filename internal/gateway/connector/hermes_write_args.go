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

package connector

import (
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hermespatch"
)

// HermesUnverifiedPatchArgs is the projection of a Hermes patch call whose
// write targets cannot be read: an apply_patch call with no envelope and no
// path, which the trusted-action parser treats as a patch whose targets are
// unknown (the protected files may be among them).
var HermesUnverifiedPatchArgs = json.RawMessage(`{}`)

// HermesMaxPatchTargets bounds the distinct targets of one V4A patch that are
// judged one by one. A patch that names more is judged as unverified.
const HermesMaxPatchTargets = 256

// HermesWriteView is one write target of a Hermes native file-write call, in
// the reviewed single-target tool shape the trusted-action parser judges:
// write_file {path, content}, edit {file_path, old_string, new_string,
// replace_all} or delete_file {path}. The unverified view is apply_patch
// with HermesUnverifiedPatchArgs and no Path.
type HermesWriteView struct {
	Tool string
	Args json.RawMessage
	// Path is the target as the call names it ("" for the unverified view).
	Path string

	fields  map[string]any
	pathKey string
}

// Retarget is the view's arguments with target in place of Path. ok is
// false for the unverified view.
func (v HermesWriteView) Retarget(target string) (json.RawMessage, bool) {
	if v.pathKey == "" {
		return nil, false
	}
	fields := make(map[string]any, len(v.fields))
	for key, value := range v.fields {
		fields[key] = value
	}
	fields[v.pathKey] = target
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	return out, true
}

func hermesView(tool, pathKey, path string, fields map[string]any) (HermesWriteView, bool) {
	view := HermesWriteView{Tool: tool, Path: path, fields: fields, pathKey: pathKey}
	args, ok := view.Retarget(path)
	if !ok {
		return HermesWriteView{}, false
	}
	view.Args = args
	return view, true
}

func hermesUnverifiedView() HermesWriteView {
	return HermesWriteView{Tool: "apply_patch", Args: HermesUnverifiedPatchArgs}
}

// HermesTrustedWriteViews projects a Hermes native file-write call onto the
// reviewed single-target write contracts the trusted-action parser judges,
// one view per file the call changes, so each target reaches the same
// file-write rules as a write_file call naming it (GAP-0667). The caller
// judges every view and keeps the strongest verdict.
//
// The contract is Hermes' own (tools/file_tools.py in hermes-agent: the
// published PATCH_SCHEMA and WRITE_FILE_SCHEMA and the _handle_patch and
// _handle_write_file handlers, which read only the keys below and ignore
// any other):
//
//   - write_file {path, content, cross_profile} writes content to path; it
//     is one write_file {path, content} view.
//   - patch {mode, path, old_string, new_string, replace_all, patch,
//     cross_profile}: mode defaults to "replace", which edits path and is
//     one Claude Code edit {file_path, old_string, new_string, replace_all}
//     view; mode "patch" applies a V4A patch whose Update, Add, Delete and
//     Move File headers name the files: each written file (Update, Add, a
//     Move destination) is a write_file view and each removed file (Delete,
//     a Move source) a delete_file view. An Add view carries the text
//     _apply_add writes; the others a stand-in text. In that mode path is
//     only checked and locked, never written, so it is not a target.
//
// A patch call that does not fit that contract (another mode, a key of the
// wrong type, a V4A patch Hermes cannot parse or that names no file, a path
// or target with a control character, more than HermesMaxPatchTargets
// targets) is the one unverified view. A write_file call that does not fit
// is left alone (ok false): Hermes refuses it before it writes.
func HermesTrustedWriteViews(toolName string, args json.RawMessage) (views []HermesWriteView, ok bool) {
	switch strings.TrimSpace(toolName) {
	case "write_file":
		view, ok := hermesWriteFileView(args)
		if !ok {
			return nil, false
		}
		return []HermesWriteView{view}, true
	case "patch":
		if views, ok := hermesPatchViews(args); ok {
			return views, true
		}
		return []HermesWriteView{hermesUnverifiedView()}, true
	default:
		return nil, false
	}
}

func hermesWriteFileView(args json.RawMessage) (HermesWriteView, bool) {
	fields, ok := hermesWriteFields(args)
	if !ok {
		return HermesWriteView{}, false
	}
	path, pathOK := hermesString(fields, "path")
	content, contentOK := hermesString(fields, "content")
	if !pathOK || path == "" || !contentOK {
		return HermesWriteView{}, false
	}
	return hermesView("write_file", "path", path, map[string]any{"content": content})
}

func hermesPatchViews(args json.RawMessage) ([]HermesWriteView, bool) {
	fields, ok := hermesWriteFields(args)
	if !ok {
		return nil, false
	}
	mode := "replace"
	if _, present := fields["mode"]; present {
		if mode, ok = hermesString(fields, "mode"); !ok {
			return nil, false
		}
	}
	path := ""
	if raw, present := fields["path"]; present && !hermesJSONNull(raw) {
		if json.Unmarshal(raw, &path) != nil || !hermespatch.PlainPath(path) {
			return nil, false
		}
	}
	switch mode {
	case "replace":
		oldText, oldOK := hermesString(fields, "old_string")
		newText, newOK := hermesString(fields, "new_string")
		if path == "" || !oldOK || !newOK {
			return nil, false
		}
		edit := map[string]any{"old_string": oldText, "new_string": newText}
		if raw, present := fields["replace_all"]; present && !hermesJSONNull(raw) {
			var all bool
			if json.Unmarshal(raw, &all) != nil {
				return nil, false
			}
			edit["replace_all"] = all
		}
		view, ok := hermesView("edit", "file_path", path, edit)
		if !ok {
			return nil, false
		}
		return []HermesWriteView{view}, true
	case "patch":
		body, bodyOK := hermesString(fields, "patch")
		if !bodyOK || body == "" {
			return nil, false
		}
		targets, parsed := hermespatch.Parse(body)
		if !parsed {
			return nil, false
		}
		return hermesTargetViews(targets)
	default:
		return nil, false
	}
}

// hermesWriteStandIn is the content of a write_file view whose written text
// is not known from the call alone (an Update or a Move destination, whose
// result depends on the file), or is over hermesMaxAddContentBytes. It is
// not empty, as the text it stands for is not.
const hermesWriteStandIn = "x"

// hermesMaxAddContentBytes bounds the decoded text an Add view carries: the
// trusted-action parser's bound on one written text (64 KiB). Over it, or
// when the view's encoded arguments are over hermesMaxViewArgsBytes, the Add
// view carries hermesWriteStandIn, as a write_file call over those bounds is
// judged on its target with a stand-in text.
const hermesMaxAddContentBytes = 64 << 10

// hermesMaxViewArgsBytes is the trusted-action parser's bound on a whole
// argument object (256 KiB).
const hermesMaxViewArgsBytes = 256 << 10

// hermesTargetViews is one view per distinct target, kind of change and
// written text. An Add view carries the text Hermes writes, so the content
// rules judge it as they judge a write_file call of that text.
func hermesTargetViews(targets []hermespatch.DetailedTarget) ([]HermesWriteView, bool) {
	type viewKey struct {
		target  HermesPatchTarget
		content string
	}
	seen := make(map[viewKey]bool, len(targets))
	views := make([]HermesWriteView, 0, len(targets))
	for _, target := range targets {
		if !hermespatch.PlainPath(target.Path) {
			return nil, false
		}
		content := hermesWriteStandIn
		if target.Add {
			content = hermesAddContent(target.Lines)
		}
		key := viewKey{target: target.Target, content: content}
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(seen) > HermesMaxPatchTargets {
			return nil, false
		}
		var (
			view HermesWriteView
			ok   bool
		)
		if target.Write {
			view, ok = hermesView("write_file", "path", target.Path, map[string]any{"content": content})
			if ok && content != hermesWriteStandIn && len(view.Args) > hermesMaxViewArgsBytes {
				view, ok = hermesView("write_file", "path", target.Path, map[string]any{"content": hermesWriteStandIn})
			}
		} else {
			view, ok = hermesView("delete_file", "path", target.Path, map[string]any{})
		}
		if !ok {
			return nil, false
		}
		views = append(views, view)
	}
	return views, len(views) > 0
}

// hermesAddContent is the text Hermes' _apply_add writes for an Add: the
// contents of its "+" lines joined with "\n", or hermesWriteStandIn when that
// text is over hermesMaxAddContentBytes.
func hermesAddContent(lines []string) string {
	content := strings.Join(lines, "\n")
	if len(content) > hermesMaxAddContentBytes {
		return hermesWriteStandIn
	}
	return content
}

// hermesWriteFields decodes a tool argument object whose keys do not repeat
// (Hermes reads a repeated key's last value; the parser must not guess).
func hermesWriteFields(args json.RawMessage) (map[string]json.RawMessage, bool) {
	if antigravityValidateUniqueJSON(args) != nil {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// hermesString reads a string argument; a missing key or JSON null (Python's
// None, which the handlers refuse) is not one.
func hermesString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, present := fields[key]
	if !present || hermesJSONNull(raw) {
		return "", false
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}

func hermesJSONNull(raw json.RawMessage) bool { return strings.TrimSpace(string(raw)) == "null" }

// HermesPatchTarget is one file a Hermes V4A patch changes.
type HermesPatchTarget = hermespatch.Target

// HermesV4ATargets exposes the shared target reading to gateway callers.
func HermesV4ATargets(body string) ([]HermesPatchTarget, bool) {
	return hermespatch.Targets(body)
}
