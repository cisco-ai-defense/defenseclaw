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
	"strings"
)

// Releases before 1.0.9 own the per-user Windows Kiro command only in the
// form without the launcher-start answer (preStartAnswerWindowsKiroHookCommand)
// and match their entries by exact command. After a rollback to one of them,
// its setup added its own entry beside this release's, and its teardown left
// this release's behind; with the launcher gone that entry blocks every Kiro
// tool call (rel-1-0-6 GAP-0676, the GAP-1284 rule). The rollback converter
// rewrites this release's entries into the earlier form first, and the
// restore of an aborted rollback puts them back.

// kiroWindowsHookFormPairs are the per-user Kiro commands this release writes
// for each launcher, paired with the form releases before 1.0.9 wrote.
func kiroWindowsHookFormPairs(launchers []string) [][2]string {
	var pairs [][2]string
	for _, launcher := range uniqueNonEmptyStrings(launchers) {
		for _, surface := range []string{"", KiroHookSurfaceV3} {
			current := windowsKiroHookCommandForBinary(launcher, surface, false)
			earlier := preStartAnswerWindowsKiroHookCommand(launcher, surface)
			if current != earlier {
				pairs = append(pairs, [2]string{current, earlier})
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

// convertKiroConfigHookForms applies convertKiroHookFileForms to every Kiro
// hook and agent file setup or teardown handles, each under its lock, and
// keeps a copy of a file before a rollback conversion. Managed installs are
// left alone: their guardian writes the managed form, which no release
// changed.
func (c *KiroConnector) convertKiroConfigHookForms(opts SetupOpts, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	if kiroManaged(opts) {
		return 0, nil
	}
	launchers := append([]string{strings.TrimSpace(opts.HookExecutable)}, nativeHookBinaryOwnershipCandidates()...)
	pairs := kiroWindowsHookFormPairs(launchers)
	paths := append(append(c.hookCleanupPaths(opts), c.agentConfigPaths(opts)...), c.agentCleanupPaths(opts)...)
	total := 0
	for _, path := range uniqueNonEmptyStrings(paths) {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return total, fmt.Errorf("read Kiro hooks %s: %w", path, err)
		}
		if _, changed := convertKiroHookFileForms(data, pairs, toEarlier); changed == 0 {
			continue
		}
		converted := 0
		err = withFileLockMode(path, false, func() error {
			return atomicTransformFileWithStateDir(path, opts.DataDir, 0o600,
				func(current []byte, exists bool) (atomicTransformResult, error) {
					if !exists {
						return atomicTransformResult{Remove: true}, nil
					}
					out, changed := convertKiroHookFileForms(current, pairs, toEarlier)
					if changed == 0 {
						return atomicTransformResult{Data: current}, nil
					}
					if keepCopy != nil {
						sum := sha256.Sum256([]byte(strings.ToLower(path)))
						if err := keepCopy(opts.DataDir, "kiro-"+hex.EncodeToString(sum[:6])+".before-rollback.json", current); err != nil {
							return atomicTransformResult{}, fmt.Errorf("keep a copy of the Kiro hooks: %w", err)
						}
					}
					converted = changed
					return atomicTransformResult{Data: out}, nil
				})
		})
		if err != nil {
			return total, fmt.Errorf("rewrite Kiro hooks in %s: %w", path, err)
		}
		total += converted
	}
	return total, nil
}
