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

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A change spool lives under the managed bundle directory. Prepare both
// boundaries before reserving room; creating just the leaf inherits the
// parent ACL from etc on a never-bundled install (GAP-0374).
func prepareChangeSpoolDirectory(dir string, prepareParent, prepare func(string) error) error {
	if err := prepareParent(filepath.Dir(dir)); err != nil {
		return err
	}
	return prepare(dir)
}

// The root trust anchor and credential commands leave one change event per
// change in the change spool; the gateway reports each as an audit event
// (config.trust_anchors.changed, config.secret.changed or
// config.secret.change_failed). The events below never hold a credential
// value or a hash of one.

// codeChangeUnrecorded warns that the change event of a run (a change or
// its refusal) could not be written, so the gateway will not report it.
// The command checks the spool before it changes anything, so this is a
// failure between that check and the write.
const codeChangeUnrecorded = "change_unrecorded"

func changeUnrecordedWarning(err error) enterprisebundle.Warning {
	return enterprisebundle.Warning{Code: codeChangeUnrecorded,
		Message: "the audit change event of this run could not be written, so the gateway will not report it: " + err.Error()}
}

// codeChangeReleaseUnflushed warns that a run that changed nothing could
// not remove the room it reserved for its change event durably: after a
// power loss the gateway may report the run as an interrupted change.
const codeChangeReleaseUnflushed = "change_release_unflushed"

func changeReleaseUnflushedWarning(err error) enterprisebundle.Warning {
	return enterprisebundle.Warning{Code: codeChangeReleaseUnflushed,
		Message: "this run changed nothing, but the room it reserved for its audit change event could not be removed durably, so after a power loss the gateway may report it as an interrupted change: " + err.Error()}
}

// warnChangeReleaseUnflushed prints change_release_unflushed on w (stderr
// when nil) for a run whose result document has no warnings to carry it.
func warnChangeReleaseUnflushed(w io.Writer, err error) {
	if err == nil {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	warning := changeReleaseUnflushedWarning(err)
	fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
}

// secretFailureCode is the errors[].code a failed secret command reports:
// the refusal's own code, invalid_arguments for a usage exit, state_invalid
// otherwise.
func secretFailureCode(err error, invalidExit int) string {
	var refusal *secretRefusal
	var view *managedViewRefusal
	switch {
	case errors.As(err, &refusal):
		return refusal.code
	case errors.As(err, &view):
		return view.code
	case commandExitCode(err) == invalidExit:
		return "invalid_arguments"
	default:
		return string(enterprisebundle.CodeStateInvalid)
	}
}

// secretChangeEvent is the change event of one secret set or remove. err
// is a failure (failureCode its code): a failure once the change was
// attempted (attempted, or the codes change_failed and restart_failed) is
// failed, any other a refusal. changed reports whether a successful run
// changed anything: a set of the stored value and a removal of an absent
// credential record nothing (ok false). A refused name is left out.
func secretChangeEvent(action, name string, changed bool, failureCode string, err error, attempted bool) (enterprisestatus.ChangeEvent, bool) {
	outcome := enterprisestatus.ChangeApplied
	switch {
	case err != nil && (attempted || failureCode == "change_failed" || failureCode == "restart_failed"):
		outcome = enterprisestatus.ChangeFailed
	case err != nil:
		outcome = enterprisestatus.ChangeRefused
	case !changed:
		return enterprisestatus.ChangeEvent{}, false
	}
	if action != enterprisestatus.ChangeActionSet && action != enterprisestatus.ChangeActionRemove {
		return enterprisestatus.ChangeEvent{}, false
	}
	ev := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindSecret, action, outcome, failureCode)
	if managed.ValidCredentialName(name) {
		ev.SecretName = name
	}
	ev.EventID = ev.ContentID()
	return ev, true
}

// anchorsChangeEvent is the applied change event of an anchor install that
// replaced previous (nil when there was none or it was unreadable) with
// installed; ok is false for identical bytes.
func anchorsChangeEvent(previous, installed []byte) (enterprisestatus.ChangeEvent, bool) {
	if previous != nil && bytes.Equal(previous, installed) {
		return enterprisestatus.ChangeEvent{}, false
	}
	ev := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall,
		enterprisestatus.ChangeApplied, "")
	ev.SHA256 = anchorsSHA256(installed)
	if previous != nil {
		ev.PreviousSHA256 = anchorsSHA256(previous)
	}
	ev.KeyIDsAdded, ev.KeyIDsRemoved = enterprisestatus.ChangedKeyIDs(anchorKeyIDs(previous), anchorKeyIDs(installed))
	ev.EventID = ev.ContentID()
	return ev, true
}

// anchorsFailureEvent is the change event of a refused (nothing written) or
// failed anchor install; installed is the file still installed (nil: none).
func anchorsFailureEvent(code string, failed bool, installed []byte) (enterprisestatus.ChangeEvent, bool) {
	outcome := enterprisestatus.ChangeRefused
	if failed {
		outcome = enterprisestatus.ChangeFailed
	}
	ev := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, outcome, code)
	if installed != nil {
		ev.SHA256 = anchorsSHA256(installed)
	}
	ev.EventID = ev.ContentID()
	return ev, true
}

func anchorsSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func anchorKeyIDs(raw []byte) []string {
	if raw == nil {
		return nil
	}
	anchors, err := enterprisebundle.DecodeAnchors(raw)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(anchors.Keys))
	for _, key := range anchors.Keys {
		ids = append(ids, key.KeyID)
	}
	return ids
}
