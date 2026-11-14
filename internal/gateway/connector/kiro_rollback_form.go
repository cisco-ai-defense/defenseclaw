// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Releases before 1.0.9 own the per-user Windows Kiro command only in the
// form without the launcher-start answer and match their entries by exact
// command. After a rollback to one of them, its setup added its own entry
// beside this release's, and its teardown left this release's behind; with
// the launcher gone that entry blocks every Kiro tool call (rel-1-0-6
// GAP-0676, the GAP-1284 rule). The rollback converter rewrites this
// release's entries into the target release's form first, and the restore of
// an aborted rollback puts them back.
//
// That form differs by release (the tags 1.0.0, 1.0.2, 1.0.4 to 1.0.8
// rendered: testdata/kiro_windows_release_hook_forms.json): 1.0.8 renders
// preStartAnswerWindowsKiroHookCommand, and 1.0.0 to 1.0.7 render it with the
// earlier Constrained Language fallback end (legacyWindowsAwaitedHookCommand),
// which is the only form they own. Writing the 1.0.8 form for a rollback to
// 1.0.5 left entries 1.0.5 could not remove, which outlived the Kiro
// connector (rel-1-0-10:GAP-0275). 1.0.8 and later own both forms.

// kiroRollbackTargetOwnsPreStartForm reports whether the rollback target
// release owns preStartAnswerWindowsKiroHookCommand: 1.0.8 and later. An
// unknown or unparsable target gets the form every 1.0.x release owns.
func kiroRollbackTargetOwnsPreStartForm(target string) bool {
	major, minor, patch, ok := parseKiroReleaseVersion(target)
	if !ok {
		return false
	}
	return major > 1 || (major == 1 && (minor > 0 || patch >= 8))
}

// parseKiroReleaseVersion reads a DefenseClaw release number such as
// "1.0.5", "v1.0.8" or "1.0.6-rc.dm2".
func parseKiroReleaseVersion(value string) (major, minor, patch int, ok bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if cut := strings.IndexAny(value, "-+ "); cut >= 0 {
		value = value[:cut]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	numbers := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		numbers[i] = n
	}
	return numbers[0], numbers[1], numbers[2], true
}

// kiroWindowsHookFormPairs are the per-user Kiro commands this release writes
// for each launcher, paired with an earlier form. For a rollback (toEarlier)
// that is the form the target release renders; for the restore of an aborted
// rollback both earlier forms are paired, so either comes back.
func kiroWindowsHookFormPairs(launchers []string, target string, toEarlier bool) [][2]string {
	var pairs [][2]string
	for _, launcher := range uniqueNonEmptyStrings(launchers) {
		for _, surface := range []string{"", KiroHookSurfaceV3} {
			current := windowsKiroHookCommandForBinary(launcher, surface, false)
			preStart := preStartAnswerWindowsKiroHookCommand(launcher, surface)
			legacy, hasLegacy := legacyWindowsAwaitedHookCommand(preStart)
			var earlier []string
			switch {
			case !toEarlier:
				earlier = append(earlier, preStart)
				if hasLegacy {
					earlier = append(earlier, legacy)
				}
			case kiroRollbackTargetOwnsPreStartForm(target) || !hasLegacy:
				earlier = append(earlier, preStart)
			default:
				earlier = append(earlier, legacy)
				// A 1.0.8-form entry already in the file (an earlier
				// rollback, or 1.0.8 itself) is one 1.0.0-1.0.7 cannot
				// remove either.
				if preStart != legacy {
					pairs = append(pairs, [2]string{preStart, legacy})
				}
			}
			for _, form := range earlier {
				if current != form {
					pairs = append(pairs, [2]string{current, form})
				}
			}
		}
	}
	return pairs
}

// convertKiroHookFileForms rewrites, in a Kiro hook or agent JSON file,
// every JSON string that is exactly one command of pairs into its other form:
// this release's into the earlier one (toEarlier), or back. Only whole string
// values match, so a longer command that contains one is left alone, and
// the rest of the file keeps its bytes. It returns the new data and how many
// strings it rewrote.
func convertKiroHookFileForms(data []byte, pairs [][2]string, toEarlier bool) ([]byte, int) {
	changed := 0
	for _, pair := range pairs {
		from, to := pair[0], pair[1]
		if !toEarlier {
			from, to = to, from
		}
		for _, escapeHTML := range []bool{true, false} {
			oldValue, newValue := kiroJSONString(from, escapeHTML), kiroJSONString(to, escapeHTML)
			if n := bytes.Count(data, oldValue); n > 0 {
				data = bytes.ReplaceAll(data, oldValue, newValue)
				changed += n
			}
		}
	}
	return data, changed
}

func kiroJSONString(value string, escapeHTML bool) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(escapeHTML)
	_ = encoder.Encode(value)
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

// convertKiroHooksFile applies convertKiroHookFileForms to one Kiro hooks file
// under its lock and returns how many handlers it rewrote. A rollback
// conversion (toEarlier) first puts back the saved bytes of a file nobody
// edited since setup (restoreUneditedForRollback). A copy of the file is kept
// before a rollback conversion.
func convertKiroHooksFile(path, dataDir, connectorName string, pairs [][2]string, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Kiro hooks %s: %w", path, err)
	}
	_, wanted := convertKiroHookFileForms(data, pairs, toEarlier)
	if wanted == 0 {
		return 0, nil
	}
	copyName := ""
	if keepCopy != nil {
		sum := sha256.Sum256([]byte(strings.ToLower(path)))
		copyName = "kiro-" + hex.EncodeToString(sum[:6]) + ".before-rollback.json"
	}
	converted := 0
	err = withFileLockMode(path, false, func() error {
		if toEarlier {
			var keep func([]byte) error
			if keepCopy != nil {
				keep = func(current []byte) error { return keepCopy(dataDir, copyName, current) }
			}
			if done, err := restoreUneditedForRollback(dataDir, connectorName, path, keep); err != nil || done {
				if err == nil {
					converted = wanted
				}
				return err
			}
		}
		return atomicTransformFileWithStateDir(path, dataDir, 0o600,
			func(current []byte, exists bool) (atomicTransformResult, error) {
				if !exists {
					return atomicTransformResult{Remove: true}, nil
				}
				out, changed := convertKiroHookFileForms(current, pairs, toEarlier)
				if changed == 0 {
					return atomicTransformResult{Data: current}, nil
				}
				if keepCopy != nil {
					if err := keepCopy(dataDir, copyName, current); err != nil {
						return atomicTransformResult{}, fmt.Errorf("keep a copy of the Kiro hooks: %w", err)
					}
				}
				converted = changed
				return atomicTransformResult{Data: out}, nil
			})
	})
	if err != nil {
		return 0, fmt.Errorf("rewrite Kiro hooks in %s: %w", path, err)
	}
	return converted, nil
}
