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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// managedConfigRecordMaxBytes bounds the config read for the record.
const managedConfigRecordMaxBytes = 8 << 20

// managedConfigRecordLockWait bounds the guardian's wait for config.yaml.lock,
// and managedConfigRecordHold the whole record, while the guardian holds
// lifecycle.lock: it always lets lifecycle.lock go well before a Go lifecycle
// step's 5 s wait for it ends (GAP-0646 review 3). A busy writer lock defers
// the record to the next cycle, which is logged.
const (
	managedConfigRecordLockWait = time.Second
	managedConfigRecordHold     = 2 * time.Second
)

// managedConfigRecordDeferredTo is why the last cycle could not record an
// unrecorded config.yaml, so the guardian log says it once per state.
var managedConfigRecordDeferredTo string

// managedConfigOwnership is who owns config.yaml when the hook guardian finds
// bytes config.generation.json does not record (GAP-0646). With release set
// the guardian holds the lifecycle off and records the edit itself;
// otherwise reason says why it cannot now: a lifecycle run holds
// lifecycle.lock, an install transaction is pending, or the guardian cannot
// tell (the lifecycle folder or lifecycle.lock cannot be read).
type managedConfigOwnership struct {
	release func()
	reason  string
	// restored is set when the owner puts config.yaml back (the recovery of
	// a pending install transaction): what is on disk now is not kept.
	restored bool
}

// recordUnrecordedManagedConfig records a managed config.yaml that the caller
// has already loaded, but that config.generation.json does not record, as the
// next config generation with the actor hand-edit:unattributed. The gateway
// hot reloads such a content write (an administrator's editor, configuration
// management) within seconds and enforces it, yet the reported config
// generation stayed where it was, so status, the policy line and the audit
// trail named the previous config (GAP-0617). The Windows hook guardian runs
// as SYSTEM and calls it each cycle. The generation still says hand-edit, so
// status keeps warning that the config was changed outside the lifecycle.
//
// claim is the one rule for who owns config.yaml (GAP-0646): it is called
// only for bytes the record does not name. A lifecycle run records its own
// write as its generation with the write, so the guardian never records
// bytes while a run may own the file, or while it cannot tell. It then keeps
// them (keepManagedConfigDeferredEdit) and retries each cycle, and a
// lifecycle step that finds exactly those bytes, and did not install them
// from its approved source, records them as this hand edit, never as its own
// generation (GAP-0646 review L2, REVIEW-g646 #5). nil claims nothing
// (tests, and callers with no lifecycle).
func recordUnrecordedManagedConfig(path string, w io.Writer, claim func() managedConfigOwnership) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	raw, err := readBoundedConfigFile(path, managedConfigRecordMaxBytes)
	if err != nil {
		return
	}
	if state, err := configwrite.ReadGenerationState(path); err == nil &&
		strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(raw)) {
		managedConfigRecordDeferredTo = ""
		removeManagedConfigDeferredEdit(path)
		return
	}
	if claim != nil {
		owner := claim()
		if owner.release == nil {
			var keepErr error
			if !owner.restored {
				keepErr = keepManagedConfigDeferredEdit(path, raw, owner.reason)
			}
			if owner.reason != managedConfigRecordDeferredTo {
				if owner.restored {
					fmt.Fprintf(w, "[hook-guardian] config.yaml changed while %s; that recovery puts config.yaml back, so this is not recorded as an edit\n", owner.reason)
				} else {
					fmt.Fprintf(w, "[hook-guardian] config.yaml has a change its config generation does not record, and %s; it is not recorded now and is retried each cycle, and a lifecycle run that did not install exactly these bytes records them as a hand edit\n", owner.reason)
				}
				if keepErr != nil {
					fmt.Fprintf(w, "[hook-guardian] could not keep the unrecorded config.yaml change for the next record: %v\n", keepErr)
				}
			}
			managedConfigRecordDeferredTo = owner.reason
			return
		}
		defer owner.release()
	}
	managedConfigRecordDeferredTo = ""
	ctx, cancel := context.WithTimeout(context.Background(), managedConfigRecordHold)
	defer cancel()
	recorded, err := configwrite.RecordUnrecorded(ctx, path, raw, configwrite.Options{
		Actor:   configwrite.ActorUnattributedHandEdit,
		Reason:  "config.yaml edited outside the lifecycle; recorded by the hook guardian",
		Timeout: managedConfigRecordLockWait,
	})
	switch {
	case err != nil:
		fmt.Fprintf(w, "[hook-guardian] could not record the config generation of the edited config.yaml: %v\n", err)
	case recorded:
		removeManagedConfigDeferredEdit(path)
		if state, err := configwrite.ReadGenerationState(path); err == nil {
			fmt.Fprintf(w, "[hook-guardian] config.yaml was edited outside the lifecycle; recorded as config generation %d\n", state.Generation)
		}
	}
}

// managedConfigDeferredEdit is config.unrecorded-edit.json beside config.yaml:
// bytes the hook guardian found that config.generation.json does not record,
// and could not record then. It is the only evidence, once a lifecycle step
// finds those bytes, that they are an edit and not a lifecycle write.
type managedConfigDeferredEdit struct {
	ConfigSHA256 string `json:"config_sha256"`
	Reason       string `json:"reason"`
	SeenAt       string `json:"seen_at"`
}

// managedConfigDeferredEditMaxBytes bounds a config.unrecorded-edit.json read,
// and managedConfigDeferredEditReasonMax the reason a record repeats.
const (
	managedConfigDeferredEditMaxBytes  = 4 << 10
	managedConfigDeferredEditReasonMax = 240
)

func managedConfigDeferredEditPath(path string) string {
	return filepath.Join(filepath.Dir(path), "config.unrecorded-edit.json")
}

// keepManagedConfigDeferredEdit writes config.unrecorded-edit.json for raw
// under config.yaml.lock, only while config.yaml still holds raw and the
// record still does not name it, so a writer between its write and its
// record is never taken for an edit. An unreadable record proves nothing
// (GAP-0236) and keeps nothing. The file gets config.yaml's DACL.
func keepManagedConfigDeferredEdit(path string, raw []byte, reason string) error {
	sum := configwrite.SHA256Hex(raw)
	if kept, ok := readManagedConfigDeferredEdit(path); ok && kept.ConfigSHA256 == sum {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), managedConfigRecordHold)
	defer cancel()
	_, err := configwrite.Locked(ctx, path, configwrite.Options{
		Actor:   configwrite.ActorUnattributedHandEdit,
		Reason:  "config.yaml edited outside the lifecycle",
		Timeout: managedConfigRecordLockWait,
	}, func() (bool, error) {
		current, err := os.ReadFile(path)
		if err != nil || configwrite.SHA256Hex(current) != sum {
			return false, err
		}
		state, err := configwrite.ReadGenerationState(path)
		if err == nil && strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), sum) {
			return false, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		data, err := json.Marshal(managedConfigDeferredEdit{ConfigSHA256: sum, Reason: boundedDeferredEditReason(reason),
			SeenAt: time.Now().UTC().Format(time.RFC3339)})
		if err != nil {
			return false, err
		}
		return false, writeFileKeepingDACL(managedConfigDeferredEditPath(path), append(data, '\n'), path)
	})
	return err
}

// readManagedConfigDeferredEdit reads config.unrecorded-edit.json; ok only
// for a regular file (not a link) that decodes with a lowercase sha256.
func readManagedConfigDeferredEdit(path string) (managedConfigDeferredEdit, bool) {
	notePath := managedConfigDeferredEditPath(path)
	if info, err := os.Lstat(notePath); err != nil || !info.Mode().IsRegular() {
		return managedConfigDeferredEdit{}, false
	}
	raw, err := readBoundedConfigFile(notePath, managedConfigDeferredEditMaxBytes)
	if err != nil {
		return managedConfigDeferredEdit{}, false
	}
	var note managedConfigDeferredEdit
	if err := json.Unmarshal(raw, &note); err != nil || !managedConfigSHA256Pattern.MatchString(note.ConfigSHA256) {
		return managedConfigDeferredEdit{}, false
	}
	note.Reason = boundedDeferredEditReason(note.Reason)
	return note, true
}

var managedConfigSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// boundedDeferredEditReason is reason on one line, at most
// managedConfigDeferredEditReasonMax bytes.
func boundedDeferredEditReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(reason))
	if len(reason) > managedConfigDeferredEditReasonMax {
		reason = strings.ToValidUTF8(reason[:managedConfigDeferredEditReasonMax], "")
	}
	return reason
}

// removeManagedConfigDeferredEdit removes config.unrecorded-edit.json once the
// record names the bytes on disk: what it kept is recorded or gone.
func removeManagedConfigDeferredEdit(path string) {
	_ = os.Remove(managedConfigDeferredEditPath(path))
}

// managedConfigDeferredEditOptions is how a lifecycle step (the transaction's
// config step, a rollback's record) records raw, a config.yaml it found
// unrecorded and did not install from its approved source: as the hand edit
// the hook guardian kept for exactly these bytes (ok), bound to them, with a
// reason that names step. Bytes the guardian never kept keep the step's own
// options: an upgrade still adopts a config an earlier build left
// unrecorded.
func managedConfigDeferredEditOptions(path string, raw []byte, approvedSHA256, step string) (configwrite.Options, bool) {
	sum := configwrite.SHA256Hex(raw)
	if strings.EqualFold(approvedSHA256, sum) {
		return configwrite.Options{}, false
	}
	note, ok := readManagedConfigDeferredEdit(path)
	if !ok || note.ConfigSHA256 != sum {
		return configwrite.Options{}, false
	}
	return configwrite.Options{
		Actor:        configwrite.ActorUnattributedHandEdit,
		Reason:       "config.yaml edited outside the lifecycle, found unrecorded by the hook guardian while " + note.Reason + "; recorded by " + step,
		RecordSHA256: sum,
	}, true
}

// writeFileKeepingDACL replaces path with data, giving the new file the
// DACL of sibling before it is renamed into place, so it is never readable
// by more than sibling is. Each write stages in its own exclusively created
// file beside path: two lifecycle runs that finish at the same time shared
// path+".tmp" before, so one could publish the other's bytes or fail on a
// staging file the other had already renamed (GAP-1404).
func writeFileKeepingDACL(path string, data []byte, sibling string) error {
	restore, err := keepConfigDACL(sibling)
	if err != nil {
		return err
	}
	staging, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporary := staging.Name()
	_, writeErr := staging.Write(data)
	if closeErr := staging.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(temporary)
		return writeErr
	}
	if err := restore(temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// readBoundedConfigFile reads path, refusing a file over limit bytes.
func readBoundedConfigFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return raw, nil
}
