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

// until 1.1: DefenseClaw 1.0.4 removed the OpenHands and OmniGent connectors
// (#1182). A host an older release set up still runs their hook script or
// imports their policy module. The teardown of these teardown-only
// connectors replaces an owned OpenHands hook with a static deny stub and
// removes an owned OmniGent policy module. Edited bytes are saved first under
// connector_backups/<connector>; the compare-and-swap publication can recover
// an interruption. A hard-linked, foreign or unsafe file is left intact for
// manual repair, with its tokens kept so the old hook reaches the retired
// gateway route, which denies every call. OmniGent's tokens are revoked only
// after its policy file is gone. The OpenHands hook token remains: a copy of
// its old script can allow calls before contacting the gateway if the token
// is missing. Nothing in 1.0.4 accepts that token.
//
// Teardown touches nothing else: agent config files (hooks.json, config.yaml),
// import paths (.pth), runtime records (.hookcfg), backups, the hook contract
// lock and every other connector's files stay as they are. The lifecycle
// caller removes only the retired lock entry after VerifyClean succeeds.
// RemovedConnectorLeftovers lists what is left, with the steps to remove it
// by hand; status, doctor and every uninstall form show that list. The
// gateway keeps the old hook routes, which block every call
// (gateway/retired_connector_hook.go). Delete this file in 1.1.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	removedOpenHandsID         = "openhands"
	removedOpenHandsHookScript = "openhands-hook.sh"
	removedOmnigentID          = "omnigent"
	removedOmnigentModuleName  = "defenseclaw_omnigent_policy"
	removedOmnigentPolicyKey   = "defenseclaw_guardrail"
	// removedScriptReadLimit bounds the read of a hook script: anything
	// larger is not one DefenseClaw wrote.
	removedScriptReadLimit = 1 << 20
	// removedMarkerLines is how many leading lines may hold the marker.
	removedMarkerLines = 3
	// removedConfigReadLimit bounds the read of an agent config; a larger
	// one cannot be checked and is listed for a check by hand.
	removedConfigReadLimit = 16 << 20
)

// RemovedConnectorForHookPath returns the removed connector whose gateway
// hook route path is: the route every 0.8.10 to 1.0.3 OpenHands hook and
// OmniGent policy module posts to. until 1.1.
func RemovedConnectorForHookPath(path string) (string, bool) {
	switch path {
	case "/api/v1/" + removedOpenHandsID + "/hook":
		return removedOpenHandsID, true
	case "/api/v1/" + removedOmnigentID + "/hook":
		return removedOmnigentID, true
	}
	return "", false
}

// RemovedConnectorDenyReason is the reason DefenseClaw gives when it blocks
// a call of a removed connector: the stub's, and the retired gateway
// route's. until 1.1.
func RemovedConnectorDenyReason(name string) (string, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return "", false
	}
	if c.name == removedOmnigentID {
		return removedOmnigentDenyReason, true
	}
	return removedOpenHandsDenyReason, true
}

// removedOpenHandsDenyReason is the reason the OpenHands stub gives with every
// block. It holds no $, !, backslash or single quote, so every shell prints it
// as it is.
const removedOpenHandsDenyReason = "DefenseClaw blocked this call: OpenHands support was removed in DefenseClaw 1.0.4. " +
	"To use OpenHands without DefenseClaw, remove every hook that runs " + removedOpenHandsHookScript +
	" from your OpenHands hooks.json (~/.openhands/hooks.json, or .openhands/hooks.json in a workspace), then restart OpenHands."

// removedOpenHandsTombstone is the hook script an OpenHands teardown leaves.
// OpenHands blocks a call on exit status 2 and shows the deny reason.
// A direct run uses sh -p, which ignores startup files and imported functions.
// An older hooks.json may instead run `bash script`, which ignores the shebang
// and imports functions before reading this file. In that case a Bash keyword
// starts a privileged Bash by absolute path. The parent script ends with the
// child's status; no imported exit, echo or command function can change it.
const removedOpenHandsTombstone = "#!/bin/sh -p\n" +
	"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
	"# OpenHands support was removed in DefenseClaw 1.0.4. This hook blocks every\n" +
	"# call. Remove the hooks that run it from your OpenHands hooks.json.\n" +
	"removed_deny() {\n" +
	"    echo '{\"decision\":\"deny\",\"reason\":\"" + removedOpenHandsDenyReason + "\"}'\n" +
	"    exit 2\n" +
	"}\n" +
	"case ${BASH_VERSION-} in\n" +
	"    ?*) case $- in\n" +
	"            *p*) removed_deny ;;\n" +
	"            *) /bin/bash -p \"$0\" \"$@\" ;;\n" +
	"        esac ;;\n" +
	"    *) removed_deny ;;\n" +
	"esac\n"

// removedOmnigentDenyReason is the reason the retired gateway route gives.
const removedOmnigentDenyReason = "DefenseClaw blocked this action: OmniGent support was removed in DefenseClaw 1.0.4. " +
	"To use OmniGent without DefenseClaw, remove " + removedOmnigentModuleName + " from policy_modules and the " +
	removedOmnigentPolicyKey + " policy from your OmniGent config.yaml, then restart OmniGent."

// removedOnlyConnector is the teardown-only connector of a removed connector.
type removedOnlyConnector struct {
	name, label string
	// script is the hook script or policy module an older setup wrote under
	// <data>/hooks; marker starts one of its first lines.
	script, marker string
	tombstone      string
	// inPlaceTail ends the stub written into a longer old script, after
	// blanks out to its old end (inPlaceStub); "" writes the stub alone.
	inPlaceTail string
	mode        os.FileMode
	configStep  string
	// keepHookToken keeps the hook API token at teardown: an old hook of the
	// connector that finds no token lets the call run (fail mode open), and
	// copies of its script read the same token (see the file comment).
	keepHookToken bool
	// editLogical names the backup record of the script whose post-setup
	// hash proves the script unedited (keepEdited); "" when there is none.
	editLogical string
}

// removedOpenHandsLauncherFlag is how a Windows hooks.json command names the
// OpenHands connector of the native launcher (defenseclaw-hook --connector
// openhands).
var removedOpenHandsLauncherFlag = regexp.MustCompile(`(?i)--connector(?:\s*=\s*|\s+)["']?open[-_]?hands\b`)

var (
	removedOpenHands = removedOnlyConnector{
		name: removedOpenHandsID, label: "OpenHands",
		script: removedOpenHandsHookScript, marker: "# defenseclaw-managed-hook v",
		// A process already reading a longer old script can
		// reach only the tail. `command` bypasses an exit function; a final
		// syntax error still exits nonzero if command was overridden too.
		tombstone: removedOpenHandsTombstone, inPlaceTail: "command exit 2\n)\n", mode: 0o700,
		keepHookToken: true,
		configStep:    "remove every hook whose command runs " + removedOpenHandsHookScript + " (or defenseclaw-hook --connector openhands) from this file, then restart OpenHands",
	}
	removedOmnigent = removedOnlyConnector{
		name: removedOmnigentID, label: "OmniGent",
		script: removedOmnigentModuleName + ".py", marker: "# defenseclaw-managed-policy v",
		mode: 0o600, editLogical: "module",
		configStep: "remove " + removedOmnigentModuleName + " from policy_modules and the " + removedOmnigentPolicyKey +
			" policy (handler " + removedOmnigentModuleName + ".defenseclaw_policy) from this file, then restart OmniGent",
	}
)

// removedConnector returns the teardown-only connector for a removed
// connector ID, or false.
func removedConnector(name string) (Connector, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c, true
}

func removedConnectorFor(name string) (removedOnlyConnector, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case removedOpenHandsID, "open-hands", "open_hands":
		return removedOpenHands, true
	case removedOmnigentID:
		return removedOmnigent, true
	}
	return removedOnlyConnector{}, false
}

// IsRemovedConnector reports whether name is a connector 1.0.4 removed
// (OpenHands, OmniGent). until 1.1.
func IsRemovedConnector(name string) bool {
	_, ok := removedConnectorFor(name)
	return ok
}

func (c removedOnlyConnector) Name() string { return c.name }

func (c removedOnlyConnector) Description() string {
	return c.label + " connector was removed in DefenseClaw 1.0.4; teardown only"
}

func (c removedOnlyConnector) ToolInspectionMode() ToolInspectionMode { return ToolModePreExecution }

func (c removedOnlyConnector) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }

func (c removedOnlyConnector) Setup(context.Context, SetupOpts) error {
	return fmt.Errorf("connector %q was removed in DefenseClaw 1.0.4; choose a supported connector", c.name)
}

func (c removedOnlyConnector) Authenticate(*http.Request) bool { return false }

func (c removedOnlyConnector) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return nil, fmt.Errorf("connector %q was removed", c.name)
}

func (c removedOnlyConnector) SetCredentials(string, string) {}

func (c removedOnlyConnector) scriptPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", c.script)
}

// removedScriptState is what is at a removed connector's script path.
type removedScriptState int

const (
	removedScriptAbsent removedScriptState = iota
	// removedScriptStub is the deny stub this release writes.
	removedScriptStub
	// removedScriptOwned is a script an older release wrote (its marker is
	// there): the working hook or an older stub. Teardown replaces it.
	removedScriptOwned
	// removedScriptForeign is anything else: no marker, a link, a folder,
	// another kind of file. Teardown never changes it.
	removedScriptForeign
)

// scriptStateAndLinks is what is at path and, for a regular file, how many
// names (hard links) it has and its bytes.
func (c removedOnlyConnector) scriptStateAndLinks(path string) (removedScriptState, uint32, []byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return removedScriptAbsent, 0, nil, nil, nil
	}
	if err != nil {
		return 0, 0, nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return removedScriptForeign, 0, nil, nil, nil
	}
	file, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("stat opened %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return 0, 0, nil, nil, fmt.Errorf("%s changed while it was opened: %w", path, errAtomicTransformConflict)
	}
	links, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return 0, 0, nil, nil, err
	}
	return c.classifyScript(data), links, data, opened, nil
}

func (c removedOnlyConnector) classifyScript(data []byte) removedScriptState {
	switch {
	case c.isStub(data):
		return removedScriptStub
	case len(data) <= removedScriptReadLimit && removedHasMarker(data, c.marker):
		return removedScriptOwned
	}
	return removedScriptForeign
}

// isStub reports whether data is the stub, or the stub as writeStubInPlace
// leaves it in a file that held a longer script (inPlaceStub).
func (c removedOnlyConnector) isStub(data []byte) bool {
	if c.tombstone == "" {
		return false
	}
	rest, ok := bytes.CutPrefix(data, []byte(c.tombstone))
	switch {
	case !ok:
		return false
	case len(rest) == 0:
		return true
	case c.inPlaceTail == "":
		return false
	}
	pad, ok := bytes.CutSuffix(rest, []byte(c.inPlaceTail))
	return ok && len(bytes.Trim(pad, " ")) == 0
}

// inPlaceStub is what writeStubInPlace writes into a file that held old
// bytes of oldLen. A shell that is already running the old OpenHands script
// reads on from where it was, so the file must not end where the old one
// went on: after the stub come blanks out to the old end, then exit 2. A
// run that reads on from anywhere past the stub reaches that exit 2. It
// stays within removedScriptReadLimit.
func (c removedOnlyConnector) inPlaceStub(oldLen int) []byte {
	stub := []byte(c.tombstone)
	if oldLen <= len(stub) {
		return stub
	}
	pad := min(oldLen-len(stub), removedScriptReadLimit-len(stub)-len(c.inPlaceTail))
	return append(append(stub, bytes.Repeat([]byte(" "), pad)...), c.inPlaceTail...)
}

// removedHasMarker reports whether one of the first lines of data starts with
// marker.
func removedHasMarker(data []byte, marker string) bool {
	lines := bytes.SplitN(data, []byte("\n"), removedMarkerLines+1)
	if len(lines) > removedMarkerLines {
		lines = lines[:removedMarkerLines]
	}
	for _, line := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte(marker)) {
			return true
		}
	}
	return false
}

// Teardown cleans the retired hook or policy file and revokes the tokens; see
// the file comment.
func (c removedOnlyConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("%s teardown: empty data directory", c.name)
	}
	// Validate every later token removal before changing the script. An
	// invalid path (including a directory or link at a legacy .tmp name)
	// leaves the prior installation intact for a retry after manual repair.
	if err := c.preflightTokens(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; nothing was changed", c.name, err)
	}
	// File cleanup is the commit point: once it is in place, a later
	// token I/O failure must roll forward on retry. Restoring an old hook
	// after some tokens were revoked could let it fail open. Backup receipts
	// stay intact, and neither the vendor config nor import path is changed.
	if err := c.replaceScript(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept, the retired gateway route blocks every call, and the next start tries again", c.name, err)
	}
	if err := c.hookLeft(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept, and the retired gateway route blocks every call", c.name, err)
	}
	if err := c.revokeTokens(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; the hook or policy cleanup and backup receipts were kept, and the next start retries token revocation", c.name, err)
	}
	return nil
}

func (c removedOnlyConnector) preflightTokens(dataDir string) error {
	if !c.keepHookToken {
		path := c.hookTokenPath(dataDir)
		if path == "" {
			return fmt.Errorf("resolve the %s hook token path", c.name)
		}
		for _, candidate := range []string{path, path + ".tmp"} {
			if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return fmt.Errorf("inspect hook token %s: %w", candidate, err)
			}
			if err := validateHookAPITokenLocation(dataDir, candidate); err != nil {
				return fmt.Errorf("hook token %s is not safe to revoke: %w", candidate, err)
			}
			if err := checkOwnedOTLPPathTokenFile(candidate); err != nil {
				return fmt.Errorf("hook token %s is not safe to revoke: %w", candidate, err)
			}
		}
	}
	for _, path := range []string{c.otlpTokenPath(dataDir), c.otlpTokenPath(dataDir) + ".tmp"} {
		if err := checkOwnedOTLPPathTokenFile(path); err != nil {
			return fmt.Errorf("OTLP token %s is not safe to revoke: %w", path, err)
		}
	}
	return nil
}

// replaceScript publishes an OpenHands deny stub or removes an owned OmniGent
// policy file. A refusal keeps the tokens for a later retry or manual cleanup.
func (c removedOnlyConnector) replaceScript(dataDir string) error {
	path := c.scriptPath(dataDir)
	// The CAS may have detached the verified file before a process stopped.
	// Its old bytes are protected by the recovery intent. Reconcile it before
	// deciding that there is no file left or revoking any tokens.
	receipt, stateDir, err := c.pendingStubPublication(dataDir)
	if err != nil {
		return fmt.Errorf("inspect interrupted %s for %s: %w", c.cleanupOperation(), path, err)
	}
	if receipt != "" {
		if err := recoverAtomicTransformWithStateDir(path, stateDir); err != nil {
			return fmt.Errorf("recover interrupted %s for %s: %w", c.cleanupOperation(), path, err)
		}
	}
	state, links, data, original, err := c.scriptStateAndLinks(path)
	if err != nil {
		return fmt.Errorf("read %s: %w; nothing was changed", path, err)
	}
	// Every write below first saves the bytes it replaces when they may be
	// the user's edit; a save that fails leaves the script as it is.
	keep := func(old []byte, live os.FileInfo) error { return c.keepEdited(dataDir, path, live, old) }
	if c.name == removedOmnigentID {
		if state != removedScriptOwned {
			return nil
		}
		if err := keep(data, original); err != nil {
			return fmt.Errorf("%w; nothing was changed", err)
		}
		if links > 1 {
			return fmt.Errorf("%s has %d names (hard links); refusing to remove the policy file. To finish: %s", path, links, c.hardLinkStep(path))
		}
		return removedStubTransform(path, filepath.Join(dataDir, "connector_backups", c.name), c.mode,
			func(current []byte, exists bool) (atomicTransformResult, error) {
				if !exists {
					return atomicTransformResult{}, errAtomicTransformConflict
				}
				state, count, observed, opened, err := c.scriptStateAndLinks(path)
				if err != nil || opened == nil || !os.SameFile(opened, original) || count != 1 || !bytes.Equal(observed, current) {
					return atomicTransformResult{}, fmt.Errorf("%s changed before policy removal: %w", path, errAtomicTransformConflict)
				}
				if state != removedScriptOwned {
					return atomicTransformResult{}, fmt.Errorf("%s became foreign before policy removal", path)
				}
				if err := keep(current, opened); err != nil {
					return atomicTransformResult{}, err
				}
				return atomicTransformResult{Remove: true}, nil
			})
	}
	if state != removedScriptOwned {
		return nil
	}
	if err := keep(data, nil); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	// No snapshot can protect an edit made through another name after the
	// snapshot and before the in-place OpenHands write. A single-name hook
	// still needs that write to block a shell already reading its old bytes.
	if links > 1 {
		return fmt.Errorf("%s is the script an older DefenseClaw wrote and has %d names (hard links); refusing to replace it. To finish: %s",
			path, links, c.hardLinkStep(path))
	}
	written, inPlace := c.writeStubInPlace(path, original, keep)
	if inPlace != nil {
		// A failed in-place write can coincide with a new file at the path.
		// Only the old, still-owned file may be published over.
		var state removedScriptState
		var data []byte
		var links uint32
		state, links, data, written, err = c.scriptStateAndLinks(path)
		if err != nil {
			return fmt.Errorf("read %s again: %w (writing the stub into it: %v)", path, err, inPlace)
		}
		if state == removedScriptAbsent || state == removedScriptForeign {
			return fmt.Errorf("%s became absent or foreign after the in-place write failed; refusing to replace it (writing the stub into it: %v)", path, inPlace)
		}
		if !os.SameFile(original, written) {
			return fmt.Errorf("%s changed identity after the in-place write failed; refusing to replace it (writing the stub into the prior file: %v)", path, inPlace)
		}
		if links > 1 {
			return fmt.Errorf("%s is the hook script an older DefenseClaw wrote and has %d names (hard links), and the stub could not be written into it: %w. To finish: %s",
				path, links, inPlace, c.hardLinkStep(path))
		}
		if state == removedScriptStub {
			return nil
		}
		if err := keep(data, written); err != nil {
			return fmt.Errorf("%w (writing the stub into it: %v)", err, inPlace)
		}
	}
	if err := c.publishVerifiedStub(dataDir, path, written, inPlace == nil, keep); err != nil {
		if inPlace == nil {
			return fmt.Errorf("the stub was written into the previously verified file, but %s could not be safely replaced: %w", path, err)
		}
		return fmt.Errorf("replace %s with the stub that blocks every call: %w (writing it into the file: %v)", path, err, inPlace)
	}
	return nil
}

// pendingStubPublication reads the CAS recovery namespace used for the old
// stub publication and the policy removal. It creates nothing on a read.
func (c removedOnlyConnector) pendingStubPublication(dataDir string) (string, string, error) {
	path := c.scriptPath(dataDir)
	stateDir := removedStubRecoveryDir(path, filepath.Join(dataDir, "connector_backups", c.name))
	info, err := os.Lstat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return "", stateDir, nil
	}
	if err != nil {
		return "", stateDir, err
	}
	if !info.IsDir() {
		return "", stateDir, fmt.Errorf("recovery directory %s is not a directory", stateDir)
	}
	loaded, err := loadAtomicTransformIntentWithStates(path, stateDir)
	if err != nil {
		return "", stateDir, err
	}
	if loaded.exists {
		return loaded.path, stateDir, nil
	}
	return "", stateDir, nil
}

func (c removedOnlyConnector) cleanupOperation() string {
	if c.name == removedOmnigentID {
		return "policy removal"
	}
	return "stub publication"
}

// publishVerifiedStub binds the final publication to the file verified by
// the in-place write or the second read. The compare-and-swap engine retains
// a raced replacement for recovery instead of renaming over it. Force gives
// the path a separate stub file after a successful in-place write.
func (c removedOnlyConnector) publishVerifiedStub(
	dataDir, path string, verified os.FileInfo, writtenInPlace bool,
	keep func([]byte, os.FileInfo) error,
) error {
	// keepEdited has already made this folder private when it needed a saved
	// copy; an unedited OmniGent module has its setup receipt here instead.
	// The CAS recovery intent lives in this same folder.
	stateDir := filepath.Join(dataDir, "connector_backups", c.name)
	return removedStubTransform(path, stateDir, c.mode, func(current []byte, exists bool) (atomicTransformResult, error) {
		if !exists {
			return atomicTransformResult{}, fmt.Errorf("%s became absent before stub publication", path)
		}
		named, err := os.Lstat(path)
		if err != nil {
			return atomicTransformResult{}, fmt.Errorf("inspect %s before stub publication: %w", path, err)
		}
		if !named.Mode().IsRegular() || !os.SameFile(named, verified) {
			return atomicTransformResult{}, fmt.Errorf("%s changed identity before stub publication: %w", path, errAtomicTransformConflict)
		}
		state := c.classifyScript(current)
		if writtenInPlace {
			if state != removedScriptStub {
				return atomicTransformResult{}, fmt.Errorf("%s changed after the in-place stub write", path)
			}
		} else if state == removedScriptOwned {
			if err := keep(current, named); err != nil {
				return atomicTransformResult{}, err
			}
		} else if state != removedScriptStub {
			return atomicTransformResult{}, fmt.Errorf("%s became foreign before stub publication", path)
		}
		return atomicTransformResult{Data: []byte(c.tombstone), Perm: c.mode, Force: true}, nil
	})
}

// removedEditedInfix names the saved copy of a marked script:
// connector_backups/<connector>/<script>.edited-<first 16 hex digits of its
// SHA-256>, with -2, -3, ... on a collision. The name does not end in .py or
// .sh, so nothing imports or runs it by its name.
const removedEditedInfix = ".edited-"

// removedKeepEditedWrite publishes a new saved copy without replacing an
// existing file; tests replace it to fail.
var removedKeepEditedWrite = atomicCreateFileNoFollow

// keepEdited saves the exact bytes of the script at path before the teardown
// replaces them, when they may be the user's edit: the connector records the
// hash of what its setup wrote (editLogical), and data is not that. A record
// for another file, or none, proves nothing, so data is saved then too. The
// copy is written to a temporary file, synced, published without replacement
// (the folder synced) and read back; an error means it is not saved, and the
// caller must not replace the script. The same bytes are saved once. OpenHands
// has no post-setup hash, so every marked hook is saved before a write.
//
// live is the file data was read from (nil: the file at path now). A copy
// counts as saved only when it is a file of its own (removedSavedCopy): a
// name of the live file (a hard link), a link to it, or a file that another
// name or other accounts can change is no copy, since the stub written into
// the live file, or a later change, would reach it too. Such a name is left
// in place and a new numbered copy is made instead; a link or folder at the
// hash-derived name stops the save for manual recovery.
func (c removedOnlyConnector) keepEdited(dataDir, path string, live os.FileInfo, data []byte) error {
	if c.editLogical != "" {
		record, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, c.name, c.editLogical))
		if err == nil && record.Connector == c.name && record.LogicalName == c.editLogical &&
			sameManagedTargetPath(record.Path, path) && record.PostSHA256 == sha256Hex(data) {
			return nil
		}
	}
	if live == nil {
		var err error
		if live, err = os.Lstat(path); err != nil {
			return fmt.Errorf("save the edited %s before replacing it: %w", path, err)
		}
	}
	base := c.editedCopyPath(dataDir, data)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(base)); err != nil {
		return fmt.Errorf("save the edited %s before replacing it: %w", path, err)
	}
	for i := 0; i < 1000; i++ {
		saved := base
		if i > 0 {
			saved = fmt.Sprintf("%s-%d", base, i+1)
		}
		if removedSavedCopy(saved, live, data) == nil {
			return nil
		}
		info, err := os.Lstat(saved)
		switch {
		case err == nil && !info.Mode().IsRegular():
			return fmt.Errorf("save the edited %s: %s is not a regular file; move it out of the way, then run %s",
				path, saved, c.teardownCommand())
		case err == nil:
			// It may contain an operator's later edit. Never replace it.
			continue
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("inspect saved copy %s before replacing %s: %w", saved, path, err)
		}
		if err := removedKeepEditedWrite(saved, data, 0o600); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("save the edited %s to %s before replacing it: %w; move %s out of the way, then run %s",
				path, saved, err, saved, c.teardownCommand())
		}
		if err := removedSavedCopy(saved, live, data); err != nil {
			return fmt.Errorf("save the edited %s: %s is not a copy of its own that reads back as it: %w", path, saved, err)
		}
		return nil
	}
	return fmt.Errorf("save the edited %s: all saved-copy names beginning %s are occupied; move one out of the way, then run %s",
		path, base, c.teardownCommand())
}

// removedSavedCopy returns nil when saved is a copy of data of its own: a
// regular file (never a link) with one name, not the live file, that only
// its owner can read and change (removedSavedCopyPrivate), holding exactly
// data. It reads through one handle and checks that handle is the file
// named saved.
func removedSavedCopy(saved string, live os.FileInfo, data []byte) error {
	named, err := os.Lstat(saved)
	if err != nil {
		return err
	}
	if !named.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", saved)
	}
	file, err := os.OpenFile(saved, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(named, opened) {
		return fmt.Errorf("%s changed while it was read", saved)
	}
	if live != nil && os.SameFile(opened, live) {
		return fmt.Errorf("%s is another name (a hard link) of the module itself", saved)
	}
	links, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return err
	}
	if links != 1 {
		return fmt.Errorf("%s has %d names (hard links)", saved, links)
	}
	if err := removedSavedCopyPrivate(file, opened); err != nil {
		return fmt.Errorf("%s: %w", saved, err)
	}
	got, err := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("%s does not hold the same bytes", saved)
	}
	return nil
}

func (c removedOnlyConnector) editedCopyPath(dataDir string, data []byte) string {
	return filepath.Join(dataDir, "connector_backups", c.name, c.script+removedEditedInfix+sha256Hex(data)[:16])
}

// editedCopies lists the saved copies of a marked script (keepEdited).
func (c removedOnlyConnector) editedCopies(dataDir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dataDir, "connector_backups", c.name, c.script+removedEditedInfix+"*"))
	return matches
}

// removedInPlaceWriteAt and removedInPlaceTruncate are the writes of
// writeStubInPlace; tests replace them to fail part way.
var (
	removedInPlaceWriteAt  = func(file *os.File, data []byte, offset int64) (int, error) { return file.WriteAt(data, offset) }
	removedInPlaceTruncate = func(file *os.File, size int64) error { return file.Truncate(size) }
)

// writeStubInPlace writes the OpenHands stub into the verified file at path
// only while it has one name. It checks the file again through the
// handle it writes:
// one that is no longer an older release's script, or that another account
// than the hooks folder's owner owns (removedInPlaceRefusal), is not
// written. The stub itself (well under one page) goes in first; if that
// write fails part way, the old bytes are put back, so no name is ever left
// with part of the stub before the old script. Once the whole stub is in,
// every name runs it to its exit 2 whatever follows, and the rest (the tail
// of inPlaceStub, the cut, the mode) only finishes the file, which is synced
// and read back. keep saves the old bytes it read through the handle, with
// the handle's file (keepEdited), before anything is written. A file that
// gained another hard-link name while the copy was saved is refused.
func (c removedOnlyConnector) writeStubInPlace(path string, verified os.FileInfo, keep func([]byte, os.FileInfo) error) (os.FileInfo, error) {
	if c.name != removedOpenHandsID {
		return nil, fmt.Errorf("%s does not use an in-place deny stub", c.label)
	}
	file, err := os.OpenFile(path, os.O_RDWR|otlpOpenNoFollow(), 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit || !os.SameFile(info, verified) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	folder, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := removedInPlaceRefusal(info, folder); err != nil {
		return nil, err
	}
	old, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return nil, err
	}
	if c.classifyScript(old) != removedScriptOwned {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	if err := keep(old, info); err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(named, info) {
		return nil, fmt.Errorf("%s changed identity before the in-place stub write: %w", path, errAtomicTransformConflict)
	}
	links, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return nil, fmt.Errorf("count names of %s before the in-place stub write: %w", path, err)
	}
	if links > 1 {
		return nil, fmt.Errorf("%s gained %d names (hard links) before the in-place stub write: %s", path, links, c.hardLinkStep(path))
	}
	stub := c.inPlaceStub(len(old))
	head := len(c.tombstone)
	if n, err := removedInPlaceWriteAt(file, stub[:head], 0); err != nil {
		return nil, removedPutBack(file, old, n, err)
	}
	if _, err := removedInPlaceWriteAt(file, stub[head:], int64(head)); err != nil {
		return nil, fmt.Errorf("the file begins with the whole stub, which blocks every call, but the rest could not be written: %w", err)
	}
	if err := removedInPlaceTruncate(file, int64(len(stub))); err != nil {
		return nil, fmt.Errorf("the file begins with the whole stub, which blocks every call, but its old tail could not be cut: %w", err)
	}
	if err := file.Chmod(c.mode); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	got := make([]byte, len(stub)+1)
	n, err := file.ReadAt(got, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if !bytes.Equal(got[:n], stub) {
		return nil, fmt.Errorf("%s does not read back as the stub", path)
	}
	return info, nil
}

// removedPutBack puts back the old bytes a failed write of the stub's first
// n bytes changed.
func removedPutBack(file *os.File, old []byte, n int, cause error) error {
	if n <= 0 {
		return fmt.Errorf("%w; nothing was changed", cause)
	}
	_, err := removedInPlaceWriteAt(file, old[:min(n, len(old))], 0)
	if err == nil && n > len(old) {
		err = removedInPlaceTruncate(file, int64(len(old)))
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		return fmt.Errorf("%w, and the %d bytes it wrote could not be put back (%v), so the file may hold part of the stub", cause, n, err)
	}
	return fmt.Errorf("%w; the %d bytes it wrote were put back", cause, n)
}

// hookLeft reports an incomplete retired file cleanup and the manual step.
// While it fails, the tokens stay and VerifyClean fails.
func (c removedOnlyConnector) hookLeft(dataDir string) error {
	path := c.scriptPath(dataDir)
	if receipt, _, err := c.pendingStubPublication(dataDir); err != nil {
		return fmt.Errorf("inspect interrupted %s for %s: %w", c.cleanupOperation(), path, err)
	} else if receipt != "" {
		return fmt.Errorf("interrupted %s for %s is still pending; run %s before removing saved copies or tokens", c.cleanupOperation(), path, c.teardownCommand())
	}
	state, links, _, _, err := c.scriptStateAndLinks(path)
	fileKind := "hook script"
	if c.name == removedOmnigentID {
		fileKind = "policy module"
	}
	switch {
	case err != nil:
		return fmt.Errorf("read %s: %w", path, err)
	case state == removedScriptAbsent || state == removedScriptStub:
		return nil
	case state == removedScriptOwned && links > 1:
		return fmt.Errorf("%s is the %s an older DefenseClaw wrote and has %d names (hard links); cleanup is incomplete. To finish: %s",
			path, fileKind, links, c.hardLinkStep(path))
	case state == removedScriptOwned:
		return fmt.Errorf("%s is still the %s an older DefenseClaw wrote", path, fileKind)
	}
	return fmt.Errorf("%s was not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first %d lines, or not a regular file), and it may still be used. To finish: %s",
		path, removedMarkerLines, c.foreignStep())
}

// hardLinkStep is the manual step for a script with more than one name.
func (c removedOnlyConnector) hardLinkStep(path string) string {
	list := "find / -xdev -samefile " + path + " lists them"
	if runtime.GOOS == "windows" {
		list = "fsutil hardlink list " + path + " lists them"
	}
	result := "writes the stub and revokes the tokens"
	if c.name == removedOmnigentID {
		result = "removes the retired policy file and revokes the tokens"
	}
	return "copy back what you need from connector_backups before deleting any linked name there; " +
		"delete every other name of this file (" + list + "), then run " + c.teardownCommand() +
		", which " + result
}

// foreignStep is the manual step for a script path DefenseClaw cannot prove
// it wrote.
func (c removedOnlyConnector) foreignStep() string {
	return "if it is not yours, delete it; if it is, move it out of DefenseClaw's hooks folder; then run " +
		c.teardownCommand() + ", which revokes the tokens"
}

func (c removedOnlyConnector) teardownCommand() string {
	return "defenseclaw-gateway connector teardown --connector " + c.name
}

func (c removedOnlyConnector) otlpTokenPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", otlpPathTokenFileName(OTLPPathTokenScope(c.name)))
}

// revokeTokens removes the connector's hook API and OTLP tokens, except a
// hook token it keeps (keepHookToken). Nothing in 1.0.4 accepts them.
func (c removedOnlyConnector) revokeTokens(dataDir string) error {
	var errs []error
	if !c.keepHookToken && c.hookTokenPresent(dataDir) {
		if err := RemoveHookAPIToken(dataDir, c.name); err != nil {
			errs = append(errs, fmt.Errorf("%s teardown: revoke the hook token: %w", c.name, err))
		}
	}
	token := c.otlpTokenPath(dataDir)
	for _, path := range []string{token, token + ".tmp"} {
		if err := removeOwnedOTLPPathTokenFile(path); err != nil {
			errs = append(errs, fmt.Errorf("%s teardown: revoke %s: %w", c.name, path, err))
		}
	}
	return errors.Join(errs...)
}

// hookTokenPresent reports whether the hook token or its temporary file may
// be there (true when the path cannot be built or read).
func (c removedOnlyConnector) hookTokenPresent(dataDir string) bool {
	path, err := HookAPITokenFilePath(dataDir, c.name)
	if err != nil {
		return true
	}
	for _, candidate := range []string{path, path + ".tmp"} {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

// tokenPaths are the tokens teardown revokes.
func (c removedOnlyConnector) tokenPaths(dataDir string) []string {
	var paths []string
	if path := c.hookTokenPath(dataDir); path != "" && !c.keepHookToken {
		paths = append(paths, path)
	}
	return append(paths, c.otlpTokenPath(dataDir))
}

// keptTokenPath is the hook token teardown keeps (keepHookToken), or "".
func (c removedOnlyConnector) keptTokenPath(dataDir string) string {
	if !c.keepHookToken {
		return ""
	}
	return c.hookTokenPath(dataDir)
}

func (c removedOnlyConnector) hookTokenPath(dataDir string) string {
	path, err := HookAPITokenFilePath(dataDir, c.name)
	if err != nil {
		return ""
	}
	return path
}

// keptTokenWhat and keptTokenStep describe the hook token teardown keeps.
func (c removedOnlyConnector) keptTokenWhat() string {
	return "the " + c.label + " hook token, which DefenseClaw keeps: an old " + c.label + " hook (" + c.script +
		" or a copy of it in this folder) that finds no token lets every call run in fail mode open; with it, the hook reaches the gateway, which blocks every call. Nothing in DefenseClaw 1.0.4 accepts it"
}

func (c removedOnlyConnector) keptTokenStep() string {
	return "delete it only once no " + c.label + " hooks.json, in your home or in any workspace, runs " + c.script +
		" or a copy of it, and " + c.label + " was restarted"
}

// VerifyClean fails while an old hook may still run at the script path
// (hookLeft) or a token is still there: what Teardown changes. What it
// leaves is listed by RemovedConnectorLeftovers, not reported here.
func (c removedOnlyConnector) VerifyClean(opts SetupOpts) error {
	if err := c.hookLeft(opts.DataDir); err != nil {
		return fmt.Errorf("%s cleanup incomplete: %w", c.name, err)
	}
	for _, token := range c.tokenPaths(opts.DataDir) {
		if _, err := os.Lstat(token); err == nil {
			return fmt.Errorf("%s cleanup incomplete: token %s is still there", c.name, token)
		}
	}
	return nil
}

// RemovedLeftover is one thing a removed connector's teardown leaves for the
// user: what it is and how to remove it by hand.
type RemovedLeftover struct {
	Path string `json:"path"`
	What string `json:"what"`
	Step string `json:"step"`
}

// RemovedConnectorLeftovers lists what is left of a removed connector on this
// host, with the manual steps; false when name is not a removed connector.
// It only reads.
func RemovedConnectorLeftovers(name string, opts SetupOpts) ([]RemovedLeftover, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c.leftovers(opts), true
}

func (c removedOnlyConnector) leftovers(opts SetupOpts) []RemovedLeftover {
	var out []RemovedLeftover
	add := func(path, what, step string) {
		out = append(out, RemovedLeftover{Path: path, What: what, Step: step})
	}
	for _, path := range c.configPaths(opts) {
		data, err := readRemovedConfig(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			add(path, fmt.Sprintf("could not be read (%v)", err), "check it by hand: "+c.configStep)
			continue
		}
		names, checkErr := c.configNames(data)
		switch {
		case names:
			add(path, c.configWhat(), c.configStep)
		case checkErr != nil:
			add(path, fmt.Sprintf("could not be checked (%v), so it may still name DefenseClaw's hook", checkErr), "check it by hand: "+c.configStep)
		}
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return out
	}
	if c.name == removedOmnigentID {
		if pth := managedFileBackupTargetPath(opts.DataDir, c.name, "pth", ""); pth != "" {
			if item, ok := removedPthLeftover(pth, filepath.Join(opts.DataDir, "hooks")); ok {
				out = append(out, item)
			}
		}
	}
	script := c.scriptPath(opts.DataDir)
	publicationReceipt, publicationStateDir, publicationErr := c.pendingStubPublication(opts.DataDir)
	if publicationErr != nil {
		add(publicationStateDir, fmt.Sprintf("could not inspect interrupted %s (%v)", c.cleanupOperation(), publicationErr),
			"rerun "+c.teardownCommand()+"; do not delete saved copies or tokens until recovery succeeds")
	} else if publicationReceipt != "" {
		add(publicationReceipt, "interrupted "+c.cleanupOperation()+"; cleanup is incomplete",
			"rerun "+c.teardownCommand()+" before deleting saved copies or tokens; keep this receipt if recovery fails")
	}
	state, links, _, _, err := c.scriptStateAndLinks(script)
	tokenStep := c.teardownCommand()
	fileKind := "hook script"
	if c.name == removedOmnigentID {
		fileKind = "policy module"
	}
	switch {
	case err != nil:
		add(script, fmt.Sprintf("could not be read (%v)", err), "delete it once nothing above runs it")
	case state == removedScriptStub:
		add(script, "the stub that blocks every "+c.label+" call", "delete it once nothing above runs it")
	case state == removedScriptOwned && links > 1:
		add(script, fmt.Sprintf("still the %s an older DefenseClaw wrote, with %d names (hard links); teardown leaves it and its tokens, so every name still reaches the gateway, which blocks every call", fileKind, links),
			c.hardLinkStep(script))
		tokenStep = "follow the step for " + script + " first"
	case state == removedScriptOwned:
		add(script, "still the "+fileKind+" an older DefenseClaw wrote", c.teardownCommand())
	case state == removedScriptForeign:
		add(script, "not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first lines, or not a regular file); teardown keeps its tokens, so a retired file here still reaches the gateway, which blocks every call",
			c.foreignStep())
		tokenStep = "follow the step for " + script + " first"
	}
	if c.name == removedOpenHandsID {
		record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
		if _, err := os.Lstat(record); err == nil {
			add(record, "the runtime settings of the removed hook; DefenseClaw no longer reads it", "delete it")
		}
	}
	backups := filepath.Join(opts.DataDir, "connector_backups", c.name)
	if _, err := os.Lstat(backups); err == nil {
		step := "copy back what you need, then delete this folder"
		if publicationReceipt != "" || publicationErr != nil {
			step = "do not delete this folder until " + c.teardownCommand() + " has recovered the interrupted publication"
		}
		add(backups, "the copies of your files DefenseClaw saved before its setup changed them (pristine_bytes, base64)",
			step)
	}
	for _, saved := range c.editedCopies(opts.DataDir) {
		what := "your edited " + c.script
		if c.name == removedOpenHandsID {
			what = "the prior " + c.script + " (including any edits)"
			what += ", as it was when the teardown replaced it with the stub that blocks every call"
		} else {
			what += ", as it was before the teardown removed the policy file"
		}
		add(saved, what,
			"copy back what you need (not into DefenseClaw's hooks folder), then delete it")
	}
	if kept := c.keptTokenPath(opts.DataDir); kept != "" {
		if _, err := os.Lstat(kept); err == nil {
			add(kept, c.keptTokenWhat(), c.keptTokenStep())
		}
	}
	for _, token := range c.tokenPaths(opts.DataDir) {
		if _, err := os.Lstat(token); err == nil {
			add(token, "a DefenseClaw token for the removed connector", tokenStep)
		}
	}
	return out
}

func (c removedOnlyConnector) configWhat() string {
	if c.name == removedOmnigentID {
		return "OmniGent config still names DefenseClaw's retired policy module"
	}
	return "OpenHands still runs DefenseClaw's hook from here; it blocks every call"
}

// configNames reports whether an agent config still runs or imports the
// script. It checks the bytes and the decoded values (JSON for hooks.json,
// YAML for config.yaml), so a name written with escapes is found too. The
// error says why a file that does not name it could not be checked: too
// large, or not JSON or YAML.
func (c removedOnlyConnector) configNames(data []byte) (bool, error) {
	if c.textNames(string(data)) {
		return true, nil
	}
	if len(data) > removedConfigReadLimit {
		return false, fmt.Errorf("it is larger than %d MiB", removedConfigReadLimit>>20)
	}
	body := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(body)) == 0 {
		return false, nil
	}
	var doc any
	if c.name == removedOpenHandsID {
		if err := json.Unmarshal(body, &doc); err != nil {
			return false, fmt.Errorf("it is not JSON: %w", err)
		}
	} else if err := yaml.Unmarshal(body, &doc); err != nil {
		return false, fmt.Errorf("it is not YAML: %w", err)
	}
	return removedValueNames(doc, c.textNames), nil
}

// textNames reports whether one config text (a command, a module name)
// names the script: OpenHands' hook script or the native launcher's
// OpenHands connector, OmniGent's policy module.
func (c removedOnlyConnector) textNames(text string) bool {
	lower := strings.ToLower(text)
	if c.name == removedOmnigentID {
		return strings.Contains(lower, removedOmnigentModuleName)
	}
	return strings.Contains(lower, removedOpenHandsHookScript) || removedOpenHandsLauncherFlag.MatchString(text)
}

// removedValueNames reports whether a string or key anywhere in a decoded
// JSON or YAML value names the script.
func removedValueNames(value any, names func(string) bool) bool {
	switch v := value.(type) {
	case string:
		return names(v)
	case []any:
		for _, item := range v {
			if removedValueNames(item, names) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			if names(key) || removedValueNames(item, names) {
				return true
			}
		}
	case map[any]any:
		for key, item := range v {
			if names(fmt.Sprint(key)) || removedValueNames(item, names) {
				return true
			}
		}
	}
	return false
}

// removedPthLeftover lists OmniGent's import-path file when it still holds
// DefenseClaw's line (the hook folder), with a step that takes out only that
// line when the file holds other import paths too.
func removedPthLeftover(pth, hooks string) (RemovedLeftover, bool) {
	data, err := readRemovedConfig(pth)
	if errors.Is(err, os.ErrNotExist) {
		return RemovedLeftover{}, false
	}
	lineStep := "remove only the line " + hooks + " (DefenseClaw's hook folder) from this file, and keep every other line, once no OmniGent config.yaml names " + removedOmnigentModuleName
	if err != nil || len(data) > removedConfigReadLimit {
		if err == nil {
			err = fmt.Errorf("it is larger than %d MiB", removedConfigReadLimit>>20)
		}
		return RemovedLeftover{Path: pth, What: fmt.Sprintf("could not be read (%v)", err), Step: "check it by hand: " + lineStep}, true
	}
	own, other := false, false
	for _, line := range strings.Split(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case sameManagedTargetPath(line, hooks):
			own = true
		default:
			other = true
		}
	}
	switch {
	case !own:
		return RemovedLeftover{}, false
	case other:
		return RemovedLeftover{Path: pth, What: "adds DefenseClaw's hook folder to OmniGent's Python import path; it holds other import paths too", Step: lineStep}, true
	}
	return RemovedLeftover{Path: pth, What: "adds DefenseClaw's hook folder to OmniGent's Python import path; it holds nothing else",
		Step: "delete this file once no OmniGent config.yaml names " + removedOmnigentModuleName}, true
}

// configPaths are the agent config files an older setup may have changed:
// the one its backup record names, the ones the hook contract lock names,
// the explicit config home and the agent's default (both), and for OmniGent
// the files OMNIGENT_CONFIG and OMNIGENT_CONFIG_HOME select.
func (c removedOnlyConnector) configPaths(opts SetupOpts) []string {
	file, defaultDir := "hooks.json", ".openhands"
	if c.name == removedOmnigentID {
		file, defaultDir = "config.yaml", ".omnigent"
	}
	var paths []string
	if strings.TrimSpace(opts.DataDir) != "" {
		paths = append(paths, managedFileBackupTargetPath(opts.DataDir, c.name, "config", ""))
		if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
			for _, path := range entry.Locations.HookConfigPaths {
				if strings.EqualFold(filepath.Base(path), file) {
					paths = append(paths, removedAbsolute(path))
				}
			}
		}
	}
	// The agent may read its default config as well as the explicit one.
	if home := strings.TrimSpace(opts.ConfigHome); home != "" {
		paths = append(paths, filepath.Join(removedAbsolute(home), file))
	}
	paths = append(paths, homePath(defaultDir, file))
	if c.name == removedOmnigentID {
		paths = append(paths, removedAbsolute(os.Getenv("OMNIGENT_CONFIG")))
		if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" {
			paths = append(paths, filepath.Join(removedAbsolute(home), file))
		}
	}
	var unique []string
	for _, path := range uniqueNonEmptyStrings(paths) {
		seen := false
		for _, kept := range unique {
			if sameManagedTargetPath(kept, path) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, path)
		}
	}
	return unique
}

// removedAbsolute resolves ~ and a relative path the way an older setup
// read it ("" stays "").
func removedAbsolute(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return ""
	case value == "~":
		return homePath()
	case strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`):
		return filepath.Join(homePath(), value[2:])
	}
	if absolute, err := filepath.Abs(value); err == nil {
		return absolute
	}
	return filepath.Clean(value)
}

// readRemovedConfig reads an agent config through links, as the agent does,
// up to one byte past removedConfigReadLimit (more is a file too large to
// check).
func readRemovedConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(file, removedConfigReadLimit+1))
}

// FormatRemovedLeftovers renders leftovers as the lines status, uninstall and
// teardown print ("" for none).
func FormatRemovedLeftovers(name string, leftovers []RemovedLeftover) string {
	if len(leftovers) == 0 {
		return ""
	}
	label := name
	if c, ok := removedConnectorFor(name); ok {
		label = c.label
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:\n", label)
	for _, item := range leftovers {
		fmt.Fprintf(&b, "  - %s: %s. To remove: %s.\n", item.Path, item.What, item.Step)
	}
	return b.String()
}
