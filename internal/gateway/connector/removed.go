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
// connectors does exactly two things:
//
//  1. It replaces the hook script an older release wrote for the connector
//     (OpenHands' openhands-hook.sh, OmniGent's policy module), proven by its
//     DefenseClaw marker, with a static deny stub. A stub an older teardown
//     left that allowed every call is replaced the same way. The stub blocks
//     every call and says that support was removed in 1.0.4 and how to
//     remove the hook. The stub is written into the file itself first (the
//     same file, so every other name of it, a hard link, gets it too; the
//     whole stub, synced and read back), and then a copy is renamed over
//     the path in one atomic step (removedOnlyConnector.replaceScript).
//     An OmniGent module whose bytes are not the ones the older setup
//     recorded it wrote (its backup record's post-setup hash) was edited:
//     its exact bytes are saved first, synced and read back, under
//     connector_backups/omnigent/ (removedOnlyConnector.keepEdited), and the
//     stub replaces it only once they are; the older teardown kept such a
//     module. The OpenHands script never had that record, and the older
//     teardown wrote its stub over it whatever its bytes.
//     A script that is gone while an agent config still runs or imports it
//     (an old hook OpenHands would run, then let the call through on the
//     missing file's error) gets the stub too (restoreStubForRegistration).
//     A stub the agent cannot run or load, or that another account may
//     change (its mode drifted, or another account owns it), is put right
//     (repairStub).
//     The hook contract lock entry of the connector records the stub's
//     digest as its script's, or no digest when the script is gone
//     (sealStub), so the lock seals exactly what is at the path; a lock or
//     entry that is gone is written again for the stub, with every agent
//     config that runs it, and read back.
//  2. It revokes the DefenseClaw tokens issued for the connector, but only
//     once nothing but the stub is left at the script path. An old hook that
//     may still run (a hard-linked file the stub could not be written into;
//     a link, or a file DefenseClaw cannot prove it wrote) keeps its tokens:
//     without them the old hook allows every call in fail mode open, with
//     them it reaches the retired gateway route, which blocks every call
//     whatever the token. The teardown then fails with the step that
//     resolves it by hand (removedOnlyConnector.hookLeft), and the next
//     start tries again. The OpenHands hook token is never revoked
//     (removedOnlyConnector.keepHookToken): a 1.0.0 to 1.0.3 OpenHands hook
//     reads it from the folder the script is in and, when it finds none,
//     lets every call run in fail mode open before it contacts the gateway.
//     A copy of the script under another name in the hooks folder reads the
//     same token, and no check can prove that no hooks.json (in the home or
//     in any workspace) runs such a copy. Nothing in 1.0.4 accepts the token
//     (the gateway loads hook tokens only for the connectors it ships), and
//     the retired route blocks whatever the token, so keeping it only keeps
//     old hooks blocking. An OmniGent module that finds no token blocks, so
//     its token goes.
//
// Nothing else is touched: agent config files (hooks.json, config.yaml),
// import paths (.pth), runtime records (.hookcfg), backups, every other
// entry of the hook contract lock and every other connector's files stay as
// they are.
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

// removedOmnigentDenyReason is the reason the OmniGent stub gives.
const removedOmnigentDenyReason = "DefenseClaw blocked this action: OmniGent support was removed in DefenseClaw 1.0.4. " +
	"To use OmniGent without DefenseClaw, remove " + removedOmnigentModuleName + " from policy_modules and the " +
	removedOmnigentPolicyKey + " policy from your OmniGent config.yaml, then restart OmniGent."

// removedOmnigentTombstone is the policy module an OmniGent teardown leaves.
// OmniGent imports it in process, so it is Python with no import: it denies
// every request with the reason.
const removedOmnigentTombstone = "# defenseclaw-managed-policy v0 (disabled tombstone)\n" +
	"\"\"\"OmniGent support was removed in DefenseClaw 1.0.4.\n\n" +
	"This policy module denies every OmniGent request. Remove " + removedOmnigentModuleName + " from\n" +
	"policy_modules and the " + removedOmnigentPolicyKey + " policy from your OmniGent config.yaml,\n" +
	"then restart OmniGent.\n\"\"\"\n\n" +
	"_REASON = \"" + removedOmnigentDenyReason + "\"\n\n\n" +
	"def defenseclaw_policy(event):\n" +
	"    return {\"result\": \"DENY\", \"reason\": _REASON}\n\n\n" +
	"POLICY_REGISTRY = [\n" +
	"    {\n" +
	"        \"handler\": \"" + removedOmnigentModuleName + ".defenseclaw_policy\",\n" +
	"        \"kind\": \"callable\",\n" +
	"        \"name\": \"DefenseClaw Guardrail (removed)\",\n" +
	"        \"description\": \"Deny every request: DefenseClaw 1.0.4 removed OmniGent support.\",\n" +
	"    }\n" +
	"]\n"

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
		// A process already reading a longer, hard-linked old script can
		// reach only the tail. `command` bypasses an exit function; a final
		// syntax error still exits nonzero if command was overridden too.
		tombstone: removedOpenHandsTombstone, inPlaceTail: "command exit 2\n)\n", mode: 0o700,
		keepHookToken: true,
		configStep:    "remove every hook whose command runs " + removedOpenHandsHookScript + " (or defenseclaw-hook --connector openhands) from this file, then restart OpenHands",
	}
	removedOmnigent = removedOnlyConnector{
		name: removedOmnigentID, label: "OmniGent",
		script: removedOmnigentModuleName + ".py", marker: "# defenseclaw-managed-policy v",
		tombstone: removedOmnigentTombstone, mode: 0o600, editLogical: "module",
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
func (c removedOnlyConnector) scriptStateAndLinks(path string) (removedScriptState, uint32, []byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return removedScriptAbsent, 0, nil, nil
	}
	if err != nil {
		return 0, 0, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return removedScriptForeign, 0, nil, nil
	}
	file, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return 0, 0, nil, err
	}
	defer file.Close()
	links, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return 0, 0, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return 0, 0, nil, err
	}
	return c.classifyScript(data), links, data, nil
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
// stays within removedScriptReadLimit. OmniGent imports the whole module at
// once, so its stub is written alone.
func (c removedOnlyConnector) inPlaceStub(oldLen int) []byte {
	stub := []byte(c.tombstone)
	if c.inPlaceTail == "" || oldLen <= len(stub) {
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

// Teardown replaces the script with the deny stub and revokes the tokens; see
// the file comment.
func (c removedOnlyConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("%s teardown: empty data directory", c.name)
	}
	// Windows lock files stay after their lock: the idle one the seal of the
	// hook contract lock used goes when the teardown ends, so it changes
	// nothing else in the data directory.
	defer RemoveIdleFileLockSentinels()
	// Validate every later token removal before changing the script. An
	// invalid path (including a directory or link at a legacy .tmp name)
	// leaves the prior installation intact for a retry after manual repair.
	if err := c.preflightTokens(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; nothing was changed", c.name, err)
	}
	// The stub is the security commit point: once it is in place, a later
	// token I/O failure must roll forward on retry. Restoring an old hook
	// after some tokens were revoked could let it fail open. Backup receipts
	// stay intact, and neither the vendor config nor import path is changed.
	if err := c.replaceScript(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept (with them an old hook reaches the gateway, which blocks every call), and the next start tries again", c.name, err)
	}
	if err := c.restoreStubForRegistration(opts); err != nil {
		return fmt.Errorf("%s teardown: %w; the next start tries again", c.name, err)
	}
	if err := c.repairStub(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept, and the next start tries again", c.name, err)
	}
	if err := c.hookLeft(opts); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept, so the old hook still reaches the gateway, which blocks every call", c.name, err)
	}
	if err := c.sealStub(opts); err != nil {
		return fmt.Errorf("%s teardown: %w; the stub that blocks every call is in place, and the next start tries again", c.name, err)
	}
	if err := c.revokeTokens(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; the deny stub and backup receipts were kept, and the next start retries token revocation", c.name, err)
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

// replaceScript writes the deny stub over a script an older release wrote.
// It writes the stub into the file itself first, so every name of the file
// (a hard link) blocks, then renames a copy over the path, which replaces
// the file at the path itself, never a link's target. When the stub cannot
// be written into a file with more than one name, nothing is renamed: the
// rename would give only this name the stub, and a later run would then
// revoke the tokens of the old hook under its other names (hookLeft keeps
// them while the old file is still at the path).
func (c removedOnlyConnector) replaceScript(dataDir string) error {
	path := c.scriptPath(dataDir)
	state, links, data, err := c.scriptStateAndLinks(path)
	if err != nil {
		return fmt.Errorf("read %s: %w; nothing was changed", path, err)
	}
	if state != removedScriptOwned {
		return nil
	}
	// Every write below first saves the bytes it replaces when they may be
	// the user's edit; a save that fails leaves the script as it is.
	keep := func(old []byte, live os.FileInfo) error { return c.keepEdited(dataDir, path, live, old) }
	if err := keep(data, nil); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	inPlace := c.writeStubInPlace(path, keep)
	if inPlace != nil && links > 1 {
		// The save may have replaced one of the names (a hard link at the
		// saved copy's name, keepEdited), so they are counted again.
		if _, now, _, err := c.scriptStateAndLinks(path); err == nil && now <= 1 {
			links = now
		}
	}
	if inPlace != nil && links > 1 {
		return fmt.Errorf("%s is the hook script an older DefenseClaw wrote and has %d names (hard links), and the stub could not be written into it: %w. To finish: %s",
			path, links, inPlace, c.hardLinkStep(path))
	}
	if inPlace != nil {
		// The rename replaces what is there now, which may have changed
		// since the first read.
		if state, _, data, err := c.scriptStateAndLinks(path); err != nil {
			return fmt.Errorf("read %s again: %w (writing the stub into it: %v)", path, err, inPlace)
		} else if state == removedScriptOwned {
			if err := keep(data, nil); err != nil {
				return fmt.Errorf("%w (writing the stub into it: %v)", err, inPlace)
			}
		}
	}
	if err := atomicReplaceFileNoFollow(path, []byte(c.tombstone), c.mode); err != nil {
		if inPlace == nil {
			return fmt.Errorf("%s holds the stub that blocks every call, but its copy could not be renamed over it: %w", path, err)
		}
		return fmt.Errorf("replace %s with the stub that blocks every call: %w (writing it into the file: %v)", path, err, inPlace)
	}
	return nil
}

// removedEditedInfix names the saved copy of an edited script:
// connector_backups/<connector>/<script>.edited-<first 16 hex digits of its
// SHA-256>. The name does not end in .py or .sh, so nothing imports or runs
// it by its name.
const removedEditedInfix = ".edited-"

// removedKeepEditedWrite writes the saved copy; tests replace it to fail.
var removedKeepEditedWrite = atomicReplaceFileNoFollow

// keepEdited saves the exact bytes of the script at path before the teardown
// replaces them, when they may be the user's edit: the connector records the
// hash of what its setup wrote (editLogical), and data is not that. A record
// for another file, or none, proves nothing, so data is saved then too. The
// copy is written to a temporary file, synced, renamed into place (the
// folder synced) and read back; an error means it is not saved, and the
// caller must not replace the script. The same bytes are saved once.
//
// live is the file data was read from (nil: the file at path now). A copy
// counts as saved only when it is a file of its own (removedSavedCopy): a
// name of the live file (a hard link), a link to it, or a file that another
// name or other accounts can change is no copy, since the stub written into
// the live file, or a later change, would reach it too. Such a name is
// replaced with a copy of its own; a link or folder there is never written
// through, so the save fails.
func (c removedOnlyConnector) keepEdited(dataDir, path string, live os.FileInfo, data []byte) error {
	if c.editLogical == "" {
		return nil
	}
	record, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, c.name, c.editLogical))
	if err == nil && record.Connector == c.name && record.LogicalName == c.editLogical &&
		sameManagedTargetPath(record.Path, path) && record.PostSHA256 == sha256Hex(data) {
		return nil
	}
	if live == nil {
		if live, err = os.Lstat(path); err != nil {
			return fmt.Errorf("save the edited %s before replacing it: %w", path, err)
		}
	}
	saved := c.editedCopyPath(dataDir, data)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(saved)); err != nil {
		return fmt.Errorf("save the edited %s before replacing it: %w", path, err)
	}
	if removedSavedCopy(saved, live, data) == nil {
		return nil
	}
	if err := removedKeepEditedWrite(saved, data, 0o600); err != nil {
		return fmt.Errorf("save the edited %s to %s before replacing it: %w; move %s out of the way, then run %s",
			path, saved, err, saved, c.teardownCommand())
	}
	if err := removedSavedCopy(saved, live, data); err != nil {
		return fmt.Errorf("save the edited %s: %s is not a copy of its own that reads back as it: %w", path, saved, err)
	}
	return nil
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
	if err := removedSavedCopyPrivate(opened); err != nil {
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

// editedCopies lists the saved copies of an edited script (keepEdited).
func (c removedOnlyConnector) editedCopies(dataDir string) []string {
	if c.editLogical == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(dataDir, "connector_backups", c.name, c.script+removedEditedInfix+"*"))
	return matches
}

// removedInPlaceWriteAt and removedInPlaceTruncate are the writes of
// writeStubInPlace; tests replace them to fail part way.
var (
	removedInPlaceWriteAt  = func(file *os.File, data []byte, offset int64) (int, error) { return file.WriteAt(data, offset) }
	removedInPlaceTruncate = func(file *os.File, size int64) error { return file.Truncate(size) }
)

// writeStubInPlace writes the stub into the file at path, which every one of
// its names shares. The file is checked again through the handle it writes:
// one that is no longer an older release's script, or that another account
// than the hooks folder's owner owns (removedInPlaceRefusal), is not
// written. The stub itself (well under one page) goes in first; if that
// write fails part way, the old bytes are put back, so no name is ever left
// with part of the stub before the old script. Once the whole stub is in,
// every name runs it to its exit 2 whatever follows, and the rest (the tail
// of inPlaceStub, the cut, the mode) only finishes the file, which is synced
// and read back. keep saves the old bytes it read through the handle, with
// the handle's file (keepEdited), before anything is written.
func (c removedOnlyConnector) writeStubInPlace(path string, keep func([]byte, os.FileInfo) error) error {
	file, err := os.OpenFile(path, os.O_RDWR|otlpOpenNoFollow(), 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return fmt.Errorf("%s changed while it was read", path)
	}
	folder, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := removedInPlaceRefusal(info, folder); err != nil {
		return err
	}
	old, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return err
	}
	if c.classifyScript(old) != removedScriptOwned {
		return fmt.Errorf("%s changed while it was read", path)
	}
	if err := keep(old, info); err != nil {
		return err
	}
	stub := c.inPlaceStub(len(old))
	head := len(c.tombstone)
	if n, err := removedInPlaceWriteAt(file, stub[:head], 0); err != nil {
		return removedPutBack(file, old, n, err)
	}
	if _, err := removedInPlaceWriteAt(file, stub[head:], int64(head)); err != nil {
		return fmt.Errorf("the file begins with the whole stub, which blocks every call, but the rest could not be written: %w", err)
	}
	if err := removedInPlaceTruncate(file, int64(len(stub))); err != nil {
		return fmt.Errorf("the file begins with the whole stub, which blocks every call, but its old tail could not be cut: %w", err)
	}
	if err := file.Chmod(c.mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	got := make([]byte, len(stub)+1)
	n, err := file.ReadAt(got, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if !bytes.Equal(got[:n], stub) {
		return fmt.Errorf("%s does not read back as the stub", path)
	}
	return nil
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

// hookLeft returns why an old hook may still run at the script path, or why
// a registration of it may not block, with the step that resolves it by
// hand; nil when the path holds the stub (under every name), or nothing and
// no agent config runs or imports it. While it fails, the tokens stay and
// VerifyClean fails.
func (c removedOnlyConnector) hookLeft(opts SetupOpts) error {
	path := c.scriptPath(opts.DataDir)
	state, links, _, err := c.scriptStateAndLinks(path)
	switch {
	case err != nil:
		return fmt.Errorf("read %s: %w", path, err)
	case state == removedScriptStub:
		if why := c.stubUnusable(path); why != nil {
			return fmt.Errorf("%s holds the stub, but %v, so %s may not %s it and let its calls through. To finish: run %s, which puts it right",
				path, why, c.label, c.stubUse(), c.teardownCommand())
		}
		return nil
	case state == removedScriptAbsent:
		if removedDataDirGone(opts.DataDir) {
			// DefenseClaw is uninstalled from this data directory (a deferred
			// uninstall verify): nothing of it is left to block, and a config
			// that still names the script is a leftover the uninstall lists.
			return nil
		}
		if config, live := c.registrationRunsScript(opts); live {
			return fmt.Errorf("%s is gone, but %s still runs or imports it (or cannot be checked), so %s does not block its calls. To finish: run %s, which writes the stub that blocks every call, or %s",
				path, config, c.label, c.teardownCommand(), c.configStep)
		}
		return nil
	case state == removedScriptOwned && links > 1:
		return fmt.Errorf("%s is the hook script an older DefenseClaw wrote and has %d names (hard links), and the stub is not in it. To finish: %s",
			path, links, c.hardLinkStep(path))
	case state == removedScriptOwned:
		return fmt.Errorf("%s is still the hook script an older DefenseClaw wrote", path)
	}
	return fmt.Errorf("%s was not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first %d lines, or not a regular file), and it may still run the old hook. To finish: %s",
		path, removedMarkerLines, c.foreignStep())
}

// removedDataDirGone reports whether the data directory itself is gone.
func removedDataDirGone(dataDir string) bool {
	if strings.TrimSpace(dataDir) == "" {
		return false
	}
	_, err := os.Lstat(dataDir)
	return errors.Is(err, os.ErrNotExist)
}

// hardLinkStep is the manual step for a script with more than one name.
func (c removedOnlyConnector) hardLinkStep(path string) string {
	list := "find / -xdev -samefile " + path + " lists them"
	if runtime.GOOS == "windows" {
		list = "fsutil hardlink list " + path + " lists them"
	}
	return "delete every other name of this file (" + list + "), then run " + c.teardownCommand() + ", which writes the stub and revokes the tokens"
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
	if err := c.hookLeft(opts); err != nil {
		return fmt.Errorf("%s cleanup incomplete: %w", c.name, err)
	}
	if err := c.stubSealed(opts); err != nil {
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
	state, links, _, err := c.scriptStateAndLinks(script)
	tokenStep := c.teardownCommand()
	switch {
	case err != nil:
		add(script, fmt.Sprintf("could not be read (%v)", err), "delete it once nothing above runs it")
	case state == removedScriptStub && c.stubUnusable(script) != nil:
		add(script, RemovedStubUnusableWhat, c.teardownCommand()+", which puts it right")
	case state == removedScriptStub:
		add(script, "the stub that blocks every "+c.label+" call", "delete it once nothing above runs it")
	case state == removedScriptOwned && links > 1:
		add(script, fmt.Sprintf("still the hook script an older DefenseClaw wrote, with %d names (hard links); teardown leaves it and its tokens, so every name still reaches the gateway, which blocks every call", links),
			c.hardLinkStep(script))
		tokenStep = "follow the step for " + script + " first"
	case state == removedScriptOwned:
		add(script, "still the hook script an older DefenseClaw wrote", c.teardownCommand())
	case state == removedScriptForeign:
		add(script, "not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first lines, or not a regular file); teardown keeps its tokens, so an old hook here still reaches the gateway, which blocks every call",
			c.foreignStep())
		tokenStep = "follow the step for " + script + " first"
	case state == removedScriptAbsent:
		if _, live := c.registrationRunsScript(opts); live {
			add(script, RemovedScriptGoneWhat, c.teardownCommand()+", which writes the stub that blocks every call; or "+c.configStep)
		}
	}
	if c.name == removedOpenHandsID {
		record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
		if _, err := os.Lstat(record); err == nil {
			add(record, "the runtime settings of the removed hook; DefenseClaw no longer reads it", "delete it")
		}
	}
	backups := filepath.Join(opts.DataDir, "connector_backups", c.name)
	if _, err := os.Lstat(backups); err == nil {
		add(backups, "the copies of your files DefenseClaw saved before its setup changed them (pristine_bytes, base64)",
			"copy back what you need, then delete this folder")
	}
	for _, saved := range c.editedCopies(opts.DataDir) {
		add(saved, "your edited "+c.script+", as it was when the teardown replaced it with the stub that blocks every call",
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

// RemovedScriptGoneWhat describes a removed connector's script that is gone
// while an agent config still runs or imports it: that agent does not block
// its calls. doctor fails on it (removed_connectors.SCRIPT_GONE_WHAT).
const RemovedScriptGoneWhat = "gone, while an agent config above still runs or imports it, so DefenseClaw does not block those calls"

// RemovedStubUnusableWhat describes a removed connector's stub that the agent
// may not run or load, or that another account may change (stubUnusable):
// that agent may let its calls through. doctor fails on it
// (removed_connectors.STUB_UNUSABLE_WHAT).
const RemovedStubUnusableWhat = "the stub, but with a mode or owner that may keep the agent from running or loading it, so DefenseClaw may not block those calls"

// stubUse is what the agent does with the stub: runs the OpenHands hook,
// imports the OmniGent module.
func (c removedOnlyConnector) stubUse() string {
	if c.name == removedOmnigentID {
		return "load"
	}
	return "run"
}

// stubUnusable says why the agent may not run or load the stub at path, or
// another account may change it (nil when neither, and always on Windows,
// where no mode bit or owner check applies; removedStubMetadataRefusal): its
// owner cannot read it, an OpenHands stub is not executable by its owner (the
// hook then fails to start, and OpenHands lets the call through), others may
// write it, or another account than the hooks folder's owner owns it.
func (c removedOnlyConnector) stubUnusable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	folder, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	return removedStubMetadataRefusal(info, folder, c.mode)
}

// repairStub puts right a stub the agent may not run or load (stubUnusable).
// A stub with one name is replaced by a fresh one of its own, with the mode,
// renamed over the path. A stub with more names gets the mode through the
// file itself, so every name gets it; one that another account owns is left,
// with the step.
func (c removedOnlyConnector) repairStub(dataDir string) error {
	path := c.scriptPath(dataDir)
	state, links, _, err := c.scriptStateAndLinks(path)
	if err != nil || state != removedScriptStub || c.stubUnusable(path) == nil {
		return nil // hookLeft reports anything else
	}
	if links <= 1 {
		if err := atomicReplaceFileNoFollow(path, []byte(c.tombstone), c.mode); err != nil {
			return fmt.Errorf("put right the stub at %s, which %s may not %s: %w", path, c.label, c.stubUse(), err)
		}
		return nil
	}
	file, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return fmt.Errorf("open the stub at %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	folder, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !c.isStub(data) {
		return fmt.Errorf("%s changed while it was read", path)
	}
	if err := removedInPlaceRefusal(info, folder); err != nil {
		return fmt.Errorf("the stub at %s has %d names (hard links) and %v, so its mode cannot be put right. To finish: %s",
			path, links, err, c.hardLinkStep(path))
	}
	if err := file.Chmod(c.mode); err != nil {
		return fmt.Errorf("set the mode of the stub at %s: %w", path, err)
	}
	return nil
}

func (c removedOnlyConnector) configWhat() string {
	if c.name == removedOmnigentID {
		return "OmniGent still imports DefenseClaw's policy module from here; it denies every request"
	}
	return "OpenHands still runs DefenseClaw's hook from here; it blocks every call"
}

// configNames reports whether an agent config still runs or imports the
// script. It checks the bytes and the decoded values (JSON for hooks.json,
// YAML for config.yaml), so a name written with escapes is found too. The
// error says why a file that does not name it could not be checked: too
// large, or not JSON or YAML.
func (c removedOnlyConnector) configNames(data []byte) (bool, error) {
	return c.configNamesWith(data, c.textNames)
}

// configNamesWith is configNames with names deciding what names the script.
func (c removedOnlyConnector) configNamesWith(data []byte, names func(string) bool) (bool, error) {
	if names(string(data)) {
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
	return removedValueNames(doc, names), nil
}

// scriptNames reports whether one config text runs or imports the script
// file itself: OpenHands' hook script, OmniGent's policy module. A Windows
// registration of the native launcher (--connector openhands) needs no
// script: the launcher reaches the retired route, which blocks every call.
func (c removedOnlyConnector) scriptNames(text string) bool {
	lower := strings.ToLower(text)
	if c.name == removedOmnigentID {
		return strings.Contains(lower, removedOmnigentModuleName)
	}
	return strings.Contains(lower, removedOpenHandsHookScript)
}

// registrationRunsScript returns the first agent config that still runs or
// imports the script, or one that could not be read or checked (it may), and
// true; "", false when none does.
func (c removedOnlyConnector) registrationRunsScript(opts SetupOpts) (string, bool) {
	live := c.liveRegistrations(opts)
	if len(live) == 0 {
		return "", false
	}
	return live[0], true
}

// liveRegistrations are the agent configs that still run or import the
// script, or that could not be read or checked (they may).
func (c removedOnlyConnector) liveRegistrations(opts SetupOpts) []string {
	var live []string
	for _, path := range c.configPaths(opts) {
		data, err := readRemovedConfig(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			live = append(live, path)
			continue
		}
		if names, checkErr := c.configNamesWith(data, c.scriptNames); names || checkErr != nil {
			live = append(live, path)
		}
	}
	return live
}

// restoreStubForRegistration writes the stub at the script path when the
// script is gone but an agent config still runs or imports it. OpenHands lets
// a call through when its hook command fails to start, and OmniGent cannot
// load a policy module that is not there: without the stub the registration
// a 1.0.3 setup left stopped blocking. The hooks folder must be a folder (never
// a link); it is created when it is gone.
func (c removedOnlyConnector) restoreStubForRegistration(opts SetupOpts) error {
	path := c.scriptPath(opts.DataDir)
	state, _, _, err := c.scriptStateAndLinks(path)
	if err != nil || state != removedScriptAbsent {
		return nil // replaceScript and hookLeft report what is there
	}
	config, live := c.registrationRunsScript(opts)
	if !live {
		return nil
	}
	hooks := filepath.Dir(path)
	if info, err := os.Lstat(hooks); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(hooks, 0o700); err != nil {
			return fmt.Errorf("%s is gone and %s still runs or imports it; create %s for the stub that blocks every call: %w", path, config, hooks, err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect %s: %w", hooks, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s is gone and %s still runs or imports it, but %s is not a folder, so the stub that blocks every call cannot be written. To finish: %s",
			path, config, hooks, c.configStep)
	}
	if err := atomicReplaceFileNoFollow(path, []byte(c.tombstone), c.mode); err != nil {
		return fmt.Errorf("%s is gone and %s still runs or imports it; write the stub that blocks every call there: %w", path, config, err)
	}
	return nil
}

// stubDigest is the hook contract lock digest of what is at the script path:
// the stub's, or "" when nothing is there. ok is false for anything else.
func (c removedOnlyConnector) stubDigest(dataDir string) (digest string, ok bool, err error) {
	state, _, data, err := c.scriptStateAndLinks(c.scriptPath(dataDir))
	switch {
	case err != nil:
		return "", false, err
	case state == removedScriptAbsent:
		return "", true, nil
	case state == removedScriptStub:
		return "sha256:" + sha256Hex(data), true, nil
	}
	return "", false, nil
}

// sealStub records in the connector's hook contract lock entry what is at
// its script path once hookLeft passed: the stub's digest, or no digest when
// nothing is there. The entry an older setup wrote sealed the old hook, so
// the lock named a hook that was no longer there. A stub that an agent config
// still runs is sealed in an entry of its own even when the lock or the entry
// is gone, with every such config, and the seal is read back (stubSealed).
func (c removedOnlyConnector) sealStub(opts SetupOpts) error {
	digest, ok, err := c.stubDigest(opts.DataDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", c.scriptPath(opts.DataDir), err)
	}
	if !ok {
		return fmt.Errorf("%s does not hold the stub that blocks every call", c.scriptPath(opts.DataDir))
	}
	var configs []string
	if digest != "" {
		configs = c.liveRegistrations(opts)
	}
	if err := sealRemovedConnectorScript(opts.DataDir, c.name, c.script, digest, configs, opts.ManagedEnterprise); err != nil {
		return fmt.Errorf("seal %s in the hook contract lock: %w", c.script, err)
	}
	if err := c.stubSealed(opts); err != nil {
		return fmt.Errorf("seal %s in the hook contract lock: %w", c.script, err)
	}
	return nil
}

// stubSealed fails while the connector's hook contract lock entry does not
// record what sealStub would: the stub's digest for its script and every agent
// config that still runs it (with such a config, no lock or no entry seals
// nothing), or no digest when nothing is at the path.
func (c removedOnlyConnector) stubSealed(opts SetupOpts) error {
	digest, ok, err := c.stubDigest(opts.DataDir)
	if err != nil || !ok {
		return nil // hookLeft reports it
	}
	entry, err := removedConnectorLockEntry(opts.DataDir, c.name, opts.ManagedEnterprise)
	if err != nil {
		return fmt.Errorf("read the hook contract lock: %w", err)
	}
	if entry == nil {
		if digest == "" {
			return nil
		}
		if live := c.liveRegistrations(opts); len(live) > 0 {
			return fmt.Errorf("the hook contract lock has no %s entry that seals the stub at %s, which %s runs; run %s", c.name, c.scriptPath(opts.DataDir), live[0], c.teardownCommand())
		}
		return nil
	}
	recorded, has := entry.HookScriptDigests[c.script]
	switch {
	case digest == "" && has:
		return fmt.Errorf("the hook contract lock still seals %s (%s), which is gone; run %s", c.script, recorded, c.teardownCommand())
	case digest != "" && recorded != digest:
		return fmt.Errorf("the hook contract lock seals %s as %q, not the stub at %s; run %s", c.script, recorded, c.scriptPath(opts.DataDir), c.teardownCommand())
	}
	if digest != "" {
		for _, config := range c.liveRegistrations(opts) {
			if !removedLockNamesConfig(*entry, config) {
				return fmt.Errorf("the hook contract lock entry of %s does not name %s, which runs the stub; run %s", c.name, config, c.teardownCommand())
			}
		}
	}
	return nil
}

// removedLockNamesConfig reports whether a lock entry names config among its
// hook config paths.
func removedLockNamesConfig(entry HookContractLockEntry, config string) bool {
	for _, path := range entry.Locations.HookConfigPaths {
		if sameManagedTargetPath(removedAbsolute(path), config) {
			return true
		}
	}
	return false
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
	workspaces := []string{opts.WorkspaceDir}
	if strings.TrimSpace(opts.DataDir) != "" {
		paths = append(paths, managedFileBackupTargetPath(opts.DataDir, c.name, "config", ""))
		if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
			for _, path := range entry.Locations.HookConfigPaths {
				if strings.EqualFold(filepath.Base(path), file) {
					paths = append(paths, removedAbsolute(path))
				}
			}
			if entry.RegistrationPosture != nil {
				workspaces = append(workspaces, entry.RegistrationPosture.WorkspaceDir)
			}
		}
	}
	// The agent may read its default config as well as the explicit one.
	if home := strings.TrimSpace(opts.ConfigHome); home != "" {
		paths = append(paths, filepath.Join(removedAbsolute(home), file))
	}
	paths = append(paths, homePath(defaultDir, file))
	if c.name == removedOpenHandsID {
		// A 1.0.x setup with a pinned workspace (claw.workspace_dir, or the
		// one its lock entry records) wrote the repo-local
		// <workspace>/.openhands/hooks.json instead of the home one, unless
		// the workspace was inside the data directory.
		for _, root := range workspaces {
			if root = removedAbsolute(root); root != "" && workspaceRootOutsideDataDir(root, opts.DataDir) {
				paths = append(paths, filepath.Join(root, defaultDir, file))
			}
		}
	}
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
