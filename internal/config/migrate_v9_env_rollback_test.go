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

package config

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

// GAP-0808 (#1099): when the config generation record can not be written,
// the 0.8.x migration reports a failure and puts config.yaml back; the
// inline scanner key it had moved to .env is taken back out too, so a
// failed run leaves nothing migrated. A retry then moves it once.
func TestMigrateV9FailedCommitTakesTheMovedKeyBackOutOfDotEnv(t *testing.T) {
	for name, previous := range map[string]*string{"no .env": nil, "an existing .env": ptr("OTHER_KEY=kept\n")} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("VIRUSTOTAL_API_KEY", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			configPath := filepath.Join(dir, "config.yaml")
			source := "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    use_virustotal: true\n" +
				"    virustotal_api_key: vt-test-value\nobservability: {}\n"
			if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			envPath := filepath.Join(dir, ".env")
			if previous != nil {
				if err := os.WriteFile(envPath, []byte(*previous), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// A directory where the generation record goes makes the commit fail.
			generation := cfgtxn.GenerationPath(configPath)
			if err := os.MkdirAll(filepath.Join(generation, "blocker"), 0o700); err != nil {
				t.Fatal(err)
			}

			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err == nil {
				t.Fatal("MigrateV9 succeeded with an unwritable generation record")
			}
			if raw, _ := os.ReadFile(configPath); string(raw) != source {
				t.Fatalf("config.yaml after the failed commit =\n%s", raw)
			}
			env, envErr := os.ReadFile(envPath)
			switch {
			case previous == nil && !errors.Is(envErr, fs.ErrNotExist):
				t.Fatalf(".env after the failed commit = %q (%v), want no file", env, envErr)
			case previous != nil && string(env) != *previous:
				t.Fatalf(".env after the failed commit = %q, want %q", env, *previous)
			}
			if result != nil && slices.Contains(result.Written, envPath) {
				t.Errorf("written lists %s after it was put back: %v", envPath, result.Written)
			}

			if err := os.RemoveAll(generation); err != nil {
				t.Fatal(err)
			}
			if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
				t.Fatalf("retry: %v", err)
			}
			env, _ = os.ReadFile(envPath)
			if strings.Count(string(env), "VIRUSTOTAL_API_KEY=vt-test-value") != 1 ||
				(previous != nil && !strings.HasPrefix(string(env), *previous)) {
				t.Fatalf(".env after the retry = %q", env)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// v9EnvRollbackSource is a 0.8.x config whose inline VirusTotal key the
// migration moves to .env; it writes it with previous as the .env (nil: no
// .env) and returns the config and .env paths.
func v9EnvRollbackSource(t *testing.T, previous *string) (configPath, envPath, source string) {
	t.Helper()
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath = filepath.Join(dir, "config.yaml")
	source = "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    use_virustotal: true\n" +
		"    virustotal_api_key: vt-test-value\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath = filepath.Join(dir, ".env")
	if previous != nil {
		if err := os.WriteFile(envPath, []byte(*previous), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return configPath, envPath, source
}

// swapV9Commit replaces the config commit for one test.
func swapV9Commit(t *testing.T, commit func(*cfgtxn.Txn, []byte, []byte, bool, os.FileMode, cfgtxn.Writer) (cfgtxn.GenerationState, error)) {
	t.Helper()
	saved := commitV9Config
	commitV9Config = commit
	t.Cleanup(func() { commitV9Config = saved })
}

// swapDotEnvWrite replaces the .env write for one test.
func swapDotEnvWrite(t *testing.T, write func(string, []byte, os.FileMode) error) {
	t.Helper()
	saved := writeDotEnvDurable
	writeDotEnvDurable = write
	t.Cleanup(func() { writeDotEnvDurable = saved })
}

// A credential that keys set or setup saves under .env.lock while the
// migration is between its .env write and a failed config commit survives
// the migration's undo: the migration holds .env.lock until the undo is
// done, and the writer saves after it.
func TestMigrateV9FailedCommitKeepsACredentialSavedMeanwhile(t *testing.T) {
	for name, previous := range map[string]*string{"no .env": nil, "an existing .env": ptr("OTHER_KEY=kept\n")} {
		t.Run(name, func(t *testing.T) {
			configPath, envPath, source := v9EnvRollbackSource(t, previous)
			saved := make(chan error, 1)
			swapV9Commit(t, func(*cfgtxn.Txn, []byte, []byte, bool, os.FileMode, cfgtxn.Writer) (cfgtxn.GenerationState, error) {
				if raw, _ := os.ReadFile(envPath); !strings.Contains(string(raw), "VIRUSTOTAL_API_KEY=vt-test-value") {
					t.Errorf(".env before the commit = %q, want the moved key", raw)
				}
				if release, err := cfgtxn.LockFile(context.Background(), envPath, 100*time.Millisecond); !errors.Is(err, cfgtxn.ErrFileLockBusy) {
					if release != nil {
						release()
					}
					t.Errorf("another .env writer took .env.lock during the migration (err %v)", err)
				}
				// The keys set writer: lock, read, add its credential, write.
				go func() {
					release, err := cfgtxn.LockFile(context.Background(), envPath, 30*time.Second)
					if err != nil {
						saved <- err
						return
					}
					defer release()
					raw, err := os.ReadFile(envPath)
					if err != nil && !errors.Is(err, fs.ErrNotExist) {
						saved <- err
						return
					}
					saved <- cfgtxn.WriteFileDurable(envPath, append(raw, "SAVED_BY_KEYS_SET=new-value\n"...), 0o600)
				}()
				return cfgtxn.GenerationState{}, errors.New("injected generation record failure")
			})

			if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err == nil {
				t.Fatal("MigrateV9 succeeded with a failing commit")
			}
			select {
			case err := <-saved:
				if err != nil {
					t.Fatalf("concurrent .env writer: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the concurrent .env writer never got .env.lock")
			}
			if raw, _ := os.ReadFile(configPath); string(raw) != source {
				t.Fatalf("config.yaml after the failed commit =\n%s", raw)
			}
			want := "SAVED_BY_KEYS_SET=new-value\n"
			if previous != nil {
				want = *previous + want
			}
			if env, _ := os.ReadFile(envPath); string(env) != want {
				t.Fatalf(".env = %q, want %q (the concurrent credential kept, the moved key taken back)", env, want)
			}
		})
	}
}

// When a failed commit can not put the v8 config back (a failed generation
// write followed by a failed restore), config.yaml holds the v9 file, which
// reads the scanner key from .env: the key stays and the error says so.
func TestMigrateV9KeepsTheMovedKeyWhenTheV9ConfigStays(t *testing.T) {
	for name, previous := range map[string]*string{"no .env": nil, "an existing .env": ptr("OTHER_KEY=kept\n")} {
		t.Run(name, func(t *testing.T) {
			configPath, envPath, _ := v9EnvRollbackSource(t, previous)
			swapV9Commit(t, func(_ *cfgtxn.Txn, _, candidate []byte, _ bool, mode os.FileMode, _ cfgtxn.Writer) (cfgtxn.GenerationState, error) {
				if err := cfgtxn.WriteFileDurable(configPath, candidate, mode); err != nil {
					return cfgtxn.GenerationState{}, err
				}
				return cfgtxn.GenerationState{}, errors.New("injected generation record failure; config.yaml now holds the new bytes and the previous ones could not be restored")
			})

			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err == nil {
				t.Fatal("MigrateV9 succeeded with a failing commit")
			}
			if !strings.Contains(err.Error(), "keeps the moved scanner key") {
				t.Errorf("error = %v, want it to say .env keeps the moved key", err)
			}
			if raw, _ := os.ReadFile(configPath); !strings.Contains(string(raw), "config_version: 9") || strings.Contains(string(raw), "vt-test-value") {
				t.Fatalf("config.yaml = \n%s\nwant the v9 file without the inline key", raw)
			}
			env, _ := os.ReadFile(envPath)
			if strings.Count(string(env), "VIRUSTOTAL_API_KEY=vt-test-value") != 1 ||
				(previous != nil && !strings.HasPrefix(string(env), *previous)) {
				t.Fatalf(".env = %q, want the moved key kept", env)
			}
			if result != nil && !slices.Contains(result.Written, envPath) {
				t.Errorf("written does not list %s, which still holds the moved key: %v", envPath, result.Written)
			}
		})
	}
}

// A .env write that reports an error after its rename landed (a failed
// directory fsync) is taken back like any other precommit failure. When the
// restore fails too, the error says .env still holds the key.
func TestMigrateV9AmbiguousDotEnvWriteIsTakenBack(t *testing.T) {
	cases := map[string]struct {
		previous     *string
		restoreFails bool
	}{
		"no .env":                      {},
		"an existing .env":             {previous: ptr("OTHER_KEY=kept\n")},
		"an existing .env, no restore": {previous: ptr("OTHER_KEY=kept\n"), restoreFails: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			configPath, envPath, source := v9EnvRollbackSource(t, tc.previous)
			calls := 0
			swapDotEnvWrite(t, func(path string, data []byte, mode os.FileMode) error {
				calls++
				if calls > 1 && tc.restoreFails {
					return errors.New("injected restore failure")
				}
				if err := cfgtxn.WriteFileDurable(path, data, mode); err != nil {
					return err
				}
				if calls == 1 {
					return errors.New("injected directory fsync failure")
				}
				return nil
			})

			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err == nil || !strings.Contains(err.Error(), "move the inline scanner key") {
				t.Fatalf("MigrateV9 error = %v, want the failed key move", err)
			}
			if raw, _ := os.ReadFile(configPath); string(raw) != source {
				t.Fatalf("config.yaml after the failed key move =\n%s", raw)
			}
			env, envErr := os.ReadFile(envPath)
			if tc.restoreFails {
				if !strings.Contains(err.Error(), "still holds the moved scanner key") {
					t.Errorf("error = %v, want it to say .env still holds the key", err)
				}
				if !strings.Contains(string(env), "VIRUSTOTAL_API_KEY=vt-test-value") {
					t.Errorf(".env = %q, want the key the error reports", env)
				}
				if result != nil && !slices.Contains(result.Written, envPath) {
					t.Errorf("written does not list %s: %v", envPath, result.Written)
				}
				return
			}
			switch {
			case tc.previous == nil && !errors.Is(envErr, fs.ErrNotExist):
				t.Fatalf(".env = %q (%v), want no file", env, envErr)
			case tc.previous != nil && string(env) != *tc.previous:
				t.Fatalf(".env = %q, want %q", env, *tc.previous)
			}
			if result != nil && slices.Contains(result.Written, envPath) {
				t.Errorf("written lists %s after it was put back: %v", envPath, result.Written)
			}
		})
	}
}

// The undo puts back only the bytes the migration wrote: a .env another
// writer changed meanwhile is left as it is, and the error says so.
func TestMigrateV9UndoLeavesAChangedDotEnvAlone(t *testing.T) {
	configPath, envPath, _ := v9EnvRollbackSource(t, ptr("OTHER_KEY=kept\n"))
	swapV9Commit(t, func(*cfgtxn.Txn, []byte, []byte, bool, os.FileMode, cfgtxn.Writer) (cfgtxn.GenerationState, error) {
		raw, _ := os.ReadFile(envPath)
		if err := os.WriteFile(envPath, append(raw, "LATER_KEY=later\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfgtxn.GenerationState{}, errors.New("injected generation record failure")
	})

	_, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err == nil || !strings.Contains(err.Error(), "left as it is") {
		t.Fatalf("MigrateV9 error = %v, want the changed .env left alone", err)
	}
	env, _ := os.ReadFile(envPath)
	for _, line := range []string{"OTHER_KEY=kept", "VIRUSTOTAL_API_KEY=vt-test-value", "LATER_KEY=later"} {
		if !strings.Contains(string(env), line) {
			t.Errorf(".env = %q, want %s kept", env, line)
		}
	}
}
