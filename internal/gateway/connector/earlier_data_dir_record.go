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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// earlierDataDirRecorded are the files below a data folder whose sha256
// `config set data_dir` records, in the list in the install home, for the
// folder it moves the stores away from (move_recorded_record_paths in
// cli/defenseclaw/commands/cmd_uninstall.py). Uninstall removes such a file
// from an earlier folder only while it still has the recorded digest.
var earlierDataDirRecorded = [...]string{
	"claudecode_backup.json",
	"codex_config_backup.json",
	"codex_backup.json",
	hermesLifecycleLockName,
	"hermes-plugin-entrypoints.json",
	"hooks/.hookcfg.hermes",
}

// earlierDataDirsMaxBytes is the largest list the Python reader accepts
// (_STORE_HISTORY_MAX_BYTES); a list over it names nothing, so the writer
// never produces one.
const earlierDataDirsMaxBytes = 256 * 1024

var errEarlierDataDirsListFull = errors.New("the list of earlier data folders would be larger than uninstall reads")

var earlierDataDirsMu sync.Mutex

// RecordEarlierDataDirWrite records the digest of body, the bytes DefenseClaw
// has just written to path, in the list of earlier data folders when path is
// one of the files that list tracks (earlierDataDirRecorded) below a folder it
// names. A gateway that keeps running in a folder after `config set data_dir`
// moved away from it rewrites such files; recording the write, in the step
// that makes it, lets uninstall tell a rewrite by DefenseClaw (removed) from
// an edit by the account (kept, and named). It is the one place the connector
// writers and the plugin answer store record a write.
//
// A write below a folder the list does not name, and a list this process
// cannot read the way the Python writer reads it, record nothing. A failure
// to record is returned for the caller to report; the old digest stays, no
// longer matches the file, and uninstall keeps the file and names it.
func RecordEarlierDataDirWrite(path string, body []byte) error {
	folder, rel, ok := earlierDataDirRecordedPath(path)
	if !ok {
		return nil
	}
	digest := sha256Hex(body)
	earlierDataDirsMu.Lock()
	defer earlierDataDirsMu.Unlock()
	for _, home := range installHomeCandidates() {
		if err := recordInEarlierDataDirsList(home, folder, rel, digest); err != nil {
			return err
		}
	}
	return nil
}

// earlierDataDirRecordedPath splits path into the data folder and the
// slash-separated record name below it, when it ends in a tracked name.
func earlierDataDirRecordedPath(path string) (folder, rel string, ok bool) {
	if !filepath.IsAbs(path) {
		return "", "", false
	}
	path = filepath.Clean(path)
	for _, name := range earlierDataDirRecorded {
		suffix := string(filepath.Separator) + filepath.FromSlash(name)
		if parent, found := strings.CutSuffix(path, suffix); found && parent != "" {
			return parent, name, true
		}
	}
	return "", "", false
}

func sameDataFolder(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	realA, errA := filepath.EvalSymlinks(a)
	realB, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && realA == realB
}

// recordInEarlierDataDirsList sets backups[folder][rel] to digest in the list
// kept in home. It does nothing when home keeps no readable list, when the
// list does not name folder, and when the digest is already there.
func recordInEarlierDataDirsList(home, folder, rel, digest string) error {
	raw, ok := readStablePrivateStateFile(home, hermesEarlierDataDirsFile, earlierDataDirsMaxBytes)
	if !ok {
		return nil
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || document == nil {
		return nil
	}
	var folders []any
	_ = json.Unmarshal(document["folders"], &folders)
	listed := false
	for _, entry := range folders {
		if name, isString := entry.(string); isString && filepath.IsAbs(name) && sameDataFolder(name, folder) {
			listed = true
		}
	}
	backups := map[string]json.RawMessage{}
	if rawBackups, present := document["backups"]; present && json.Unmarshal(rawBackups, &backups) != nil {
		return nil
	}
	if backups == nil {
		backups = map[string]json.RawMessage{}
	}
	key := folder
	for name := range backups {
		if filepath.IsAbs(name) && sameDataFolder(name, folder) {
			key = name
			listed = true
		}
	}
	if !listed {
		return nil
	}
	names := map[string]json.RawMessage{}
	if rawNames, present := backups[key]; present && json.Unmarshal(rawNames, &names) != nil {
		return nil
	}
	if names == nil {
		names = map[string]json.RawMessage{}
	}
	var recorded string
	if json.Unmarshal(names[rel], &recorded) == nil && recorded == digest {
		return nil
	}
	var err error
	if names[rel], err = json.Marshal(digest); err != nil {
		return err
	}
	if backups[key], err = json.Marshal(names); err != nil {
		return err
	}
	if document["backups"], err = json.Marshal(backups); err != nil {
		return err
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > earlierDataDirsMaxBytes {
		return errEarlierDataDirsListFull
	}
	return atomicWriteFileNoFollow(filepath.Join(home, hermesEarlierDataDirsFile), body, 0o600)
}

// recordEmptyLockCreated records the lifecycle lock a lock holder has just
// opened, when it is the empty file Setup creates.
func recordEmptyLockCreated(lockPath string, file *os.File) {
	if info, err := file.Stat(); err == nil && info.Mode().IsRegular() && info.Size() == 0 {
		_ = RecordEarlierDataDirWrite(lockPath, nil)
	}
}
