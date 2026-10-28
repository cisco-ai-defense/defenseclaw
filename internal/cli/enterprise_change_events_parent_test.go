// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestChangeSpoolPreparesItsBundleParentBeforeReserving(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing parent", true: "inherited parent"}[inherited], func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "lifecycle"), 0o700); err != nil {
				t.Fatal(err)
			}
			bundles := filepath.Join(root, "etc", "bundles")
			if inherited {
				if err := os.MkdirAll(bundles, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			parentProtected := false
			spoolDir := filepath.Join(bundles, enterprisestatus.ChangeEventsDirName)
			spool := enterprisestatus.ChangeSpool{
				Dir:      spoolDir,
				StateDir: filepath.Join(root, "lifecycle"),
				Prepare: func(dir string) error {
					return prepareChangeSpoolDirectory(dir, func(parent string) error {
						// The spool folder's parent is the bundle folder; a
						// reserved folder inside the spool (T6) has the spool
						// as its parent, which the first call protected.
						switch parent {
						case bundles:
							parentProtected = true
						case spoolDir:
							if !parentProtected {
								t.Fatal("a reserved folder was prepared before the bundle parent")
							}
						default:
							t.Fatalf("parent = %q", parent)
						}
						return os.MkdirAll(parent, 0o700)
					}, func(path string) error {
						if !parentProtected {
							return errors.New("bundle parent is not protected")
						}
						return os.MkdirAll(path, 0o700)
					})
				},
			}
			reservation, err := spool.Reserve(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove, "test-credential")
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.Release()
			event, ok := secretChangeEvent(enterprisestatus.ChangeActionRemove, "test-credential", true, "", nil, false)
			if !ok {
				t.Fatal("credential removal produced no change event")
			}
			if err := reservation.Write(event); err != nil {
				t.Fatal(err)
			}
			if got := len(enterprisestatus.ListChangeEventIDs(spool.Dir)); got != 1 {
				t.Fatalf("events = %d, want one", got)
			}
		})
	}
}

func TestChangeSpoolRefusesAnUnprovenBundleParent(t *testing.T) {
	refused := errors.New("bundle ACL replacement could not be verified")
	called := false
	err := prepareChangeSpoolDirectory(filepath.Join(t.TempDir(), "bundles", "change-events"),
		func(string) error { return refused },
		func(string) error { called = true; return nil })
	if !errors.Is(err, refused) || called {
		t.Fatalf("error = %v, child prepared = %t", err, called)
	}
}
