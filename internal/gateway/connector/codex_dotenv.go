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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Codex's native OTLP exporter (reqwest) sends the [otel] exports to the
// loopback gateway through HTTP(S)_PROXY, with the connector-scoped
// Authorization bearer, whenever NO_PROXY does not list the loopback
// (GAP-1550). Codex has no exporter-level proxy option, but at startup, before
// any thread starts, it loads CODEX_HOME/.env (dotenvy: later lines win,
// ${VAR} expands from the process environment, CODEX_* keys are ignored).
// Setup therefore appends one marked block there that adds the loopback to
// whatever NO_PROXY/no_proxy the shell or the user's own .env lines already
// set, and Teardown removes exactly that block. Nothing in the user's own
// lines is rewritten, and the merge happens at Codex start, so a later change
// to the shell's NO_PROXY is still honored.
//
// Windows keeps the documented workaround (GAP-1464): the per-user .env there
// would need the private-file ACL handling of config.toml, which this block
// does not take on.
const (
	codexDotEnvBeginPrefix = "# >>> DefenseClaw (managed; removed on uninstall): keep Codex telemetry to the local gateway off HTTP(S)_PROXY"
	codexDotEnvEnd         = "# <<< DefenseClaw <<<"
	// codexDotEnvCreatedFlag marks a .env file that Setup created, so
	// Teardown deletes it again instead of leaving an empty file behind.
	codexDotEnvCreatedFlag = "[created-file]"
	// codexDotEnvJoinedFlag marks a newline Setup added because the user's
	// last line had none; Teardown removes it again.
	codexDotEnvJoinedFlag = "[added-newline]"
)

// codexDotEnvLoopbackHosts are the gateway's loopback spellings. Codex dials
// the endpoint written into [otel] (127.0.0.1); localhost and ::1 cover a
// hand-edited endpoint.
var codexDotEnvLoopbackHosts = []string{"127.0.0.1", "localhost", "::1"}

// codexDotEnvBodyLines are the managed assignments. NO_PROXY is what reqwest
// reads first, so it carries the union of both spellings plus the loopback;
// no_proxy then mirrors it for the tools Codex runs (curl reads no_proxy).
// Empty expansions leave empty list entries, which proxy matchers skip.
func codexDotEnvBodyLines() []string {
	loopback := strings.Join(codexDotEnvLoopbackHosts, ",")
	return []string{
		`NO_PROXY="${NO_PROXY},${no_proxy},` + loopback + `"`,
		`no_proxy="${NO_PROXY}"`,
	}
}

func codexDotEnvPath() string {
	return filepath.Join(filepath.Dir(codexConfigPath()), ".env")
}

// codexDotEnvSupported reports whether Setup manages the .env block on this
// platform.
func codexDotEnvSupported() bool {
	return runtime.GOOS != "windows"
}

type codexDotEnvState struct {
	// pristine is the file content without the managed block.
	pristine []byte
	// existed reports whether the file existed before DefenseClaw added the
	// block (false when the block carries the created-file flag).
	existed bool
	// hasBlock reports whether a managed block was found.
	hasBlock bool
}

// splitCodexDotEnv separates the managed block from the user's content.
func splitCodexDotEnv(raw []byte, exists bool) (codexDotEnvState, error) {
	state := codexDotEnvState{pristine: raw, existed: exists}
	if !exists {
		return state, nil
	}
	lines := strings.SplitAfter(string(raw), "\n")
	begin, end := -1, -1
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r\n")
		if begin < 0 && strings.HasPrefix(trimmed, codexDotEnvBeginPrefix) {
			begin = i
			continue
		}
		if begin >= 0 && trimmed == codexDotEnvEnd {
			end = i
			break
		}
	}
	if begin < 0 {
		return state, nil
	}
	if end < 0 {
		return state, fmt.Errorf("%s has a DefenseClaw block without its end line %q; remove the block by hand and rerun", codexDotEnvPath(), codexDotEnvEnd)
	}
	header := lines[begin]
	before := strings.Join(lines[:begin], "")
	after := strings.Join(lines[end+1:], "")
	if strings.Contains(header, codexDotEnvJoinedFlag) && after == "" {
		before = strings.TrimSuffix(before, "\n")
	}
	state.pristine = []byte(before + after)
	state.hasBlock = true
	state.existed = !(strings.Contains(header, codexDotEnvCreatedFlag) && len(state.pristine) == 0)
	return state, nil
}

// renderCodexDotEnv appends the managed block to the user's content.
func renderCodexDotEnv(pristine []byte, existed bool) []byte {
	var out bytes.Buffer
	out.Write(pristine)
	header := codexDotEnvBeginPrefix
	if !existed {
		header += " " + codexDotEnvCreatedFlag
	}
	if len(pristine) > 0 && !bytes.HasSuffix(pristine, []byte("\n")) {
		out.WriteString("\n")
		header += " " + codexDotEnvJoinedFlag
	}
	out.WriteString(header + " >>>\n")
	for _, line := range codexDotEnvBodyLines() {
		out.WriteString(line + "\n")
	}
	out.WriteString(codexDotEnvEnd + "\n")
	return out.Bytes()
}

func codexDotEnvPerm(path string) os.FileMode {
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		return info.Mode().Perm()
	}
	return 0o600
}

// ensureCodexDotEnvProxyBypass writes (or refreshes) the managed block.
func ensureCodexDotEnvProxyBypass(opts SetupOpts) error {
	if !codexDotEnvSupported() {
		return nil
	}
	path := codexDotEnvPath()
	if err := ensureCodexConfigDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("create Codex config directory: %w", err)
	}
	return atomicTransformFileWithStateDir(path, opts.DataDir, codexDotEnvPerm(path), func(raw []byte, exists bool) (atomicTransformResult, error) {
		state, err := splitCodexDotEnv(raw, exists)
		if err != nil {
			return atomicTransformResult{}, err
		}
		rendered := renderCodexDotEnv(state.pristine, state.existed)
		if exists && bytes.Equal(rendered, raw) {
			return atomicTransformResult{Data: raw}, nil
		}
		return atomicTransformResult{Data: rendered}, nil
	})
}

// removeCodexDotEnvProxyBypass removes exactly the managed block, and the
// file when Setup created it. Runs on every platform so a block is never
// stranded; a file without the block is not touched.
func removeCodexDotEnvProxyBypass(opts SetupOpts) error {
	path := codexDotEnvPath()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if !bytes.Contains(raw, []byte(codexDotEnvBeginPrefix)) {
		return nil
	}
	return atomicTransformFileWithStateDir(path, opts.DataDir, codexDotEnvPerm(path), func(raw []byte, exists bool) (atomicTransformResult, error) {
		state, err := splitCodexDotEnv(raw, exists)
		if err != nil {
			return atomicTransformResult{}, err
		}
		if !state.hasBlock {
			return atomicTransformResult{Data: raw}, nil
		}
		if !state.existed {
			return atomicTransformResult{Remove: true}, nil
		}
		return atomicTransformResult{Data: state.pristine}, nil
	})
}

// codexDotEnvResidue reports a managed block left in CODEX_HOME/.env.
func codexDotEnvResidue() []string {
	raw, err := os.ReadFile(codexDotEnvPath())
	if err != nil || !bytes.Contains(raw, []byte(codexDotEnvBeginPrefix)) {
		return nil
	}
	return []string{".env still contains the DefenseClaw NO_PROXY block"}
}
