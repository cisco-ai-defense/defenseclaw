// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// grantBackupOperatorsReadForTest is an administrator's access-list change
// that keeps the bytes: it adds a read entry for Backup Operators.
func grantBackupOperatorsReadForTest(t *testing.T, path string) {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	operators, err := windows.CreateWellKnownSid(windows.WinBuiltinBackupOperatorsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(operators),
		},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func requireBackupOperatorsReadForTest(t *testing.T, path string) FileMetadata {
	t.Helper()
	metadata, err := ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metadata.SecurityDescriptor, ";;;BO)") {
		t.Fatalf("%s lost the administrator's access-list entry: %s", path, metadata.SecurityDescriptor)
	}
	return metadata
}

func readSharedFileForTest(path string) (SharedFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SharedFile{Path: path}, nil
	}
	if err != nil {
		return SharedFile{}, err
	}
	metadata, err := ReadPathMetadata(path)
	if err != nil {
		return SharedFile{}, err
	}
	return SharedFile{Path: path, Exists: true, Data: data, Metadata: metadata}, nil
}

func protectForTest(string) error { return nil }

func utf16ForTest(t *testing.T, path string) *uint16 {
	t.Helper()
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// sharedWriterForTest is a SharedFileWriter over PublishSharedFile and
// RemoveSharedFile, as the Cursor and Codex writers use them. beforeSwap runs
// just before each compare-and-swap.
func sharedWriterForTest(beforeSwap func(string)) SharedFileWriter {
	return SharedFileWriter{
		Attempts: 4,
		Read:     readSharedFileForTest,
		Write: func(base SharedFile, edit SharedEdit) (SharedWriteResult, error) {
			if edit.Remove {
				if beforeSwap != nil {
					beforeSwap(base.Path)
				}
				err := RemoveSharedFile(base, true, 1<<20, nil)
				return SharedWriteResult{Published: err == nil, Left: SharedFile{Path: base.Path}}, err
			}
			metadata := edit.Metadata
			if metadata == nil && base.Exists {
				metadata = &base.Metadata
			}
			published, swapped, err := PublishSharedFile(SharedPublish{
				Base: base, CompareMetadata: true, Data: edit.Data, Metadata: metadata,
				Protect: protectForTest, Limit: 1 << 20, TempPattern: ".shared-*.tmp", BeforeSwap: beforeSwap,
			})
			return SharedWriteResult{Published: swapped, Left: SharedFile{Path: base.Path, Exists: true, Data: edit.Data, Metadata: published}}, err
		},
	}
}

func appendRender(suffix string) SharedRender {
	return func(base SharedFile) (SharedEdit, error) {
		return SharedEdit{Data: append(append([]byte(nil), base.Data...), suffix...)}, nil
	}
}

// A compare-and-swap that expects metadata refuses a file whose access list
// or attributes changed, even with the same bytes, and keeps that file.
func TestCompareAndSwapFileRefusesChangedMetadata(t *testing.T) {
	for _, change := range []string{"access list", "attributes"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			read, err := ReadPathMetadata(path)
			if err != nil {
				t.Fatal(err)
			}
			if change == "access list" {
				grantBackupOperatorsReadForTest(t, path)
			} else if err := windows.SetFileAttributes(utf16ForTest(t, path), read.Attributes|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED); err != nil {
				t.Fatal(err)
			}
			changed, err := ReadPathMetadata(path)
			if err != nil {
				t.Fatal(err)
			}
			source := writeSwapSourceForTest(t, dir, "new")
			if _, err := CompareAndSwapFile(source, path, SwapExpectation{Exists: true, Data: []byte("old"), Metadata: &read}, 16, nil); !errors.Is(err, ErrSwapRaced) {
				t.Fatalf("swap over changed metadata: %v", err)
			}
			if _, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("old"), Metadata: &read}, 16, nil); !errors.Is(err, ErrSwapRaced) {
				t.Fatalf("removal over changed metadata: %v", err)
			}
			if now, err := ReadPathMetadata(path); err != nil || now != changed {
				t.Fatalf("the changed file was not kept: %+v err=%v", now, err)
			}
			if result, err := CompareAndSwapFile(source, path, SwapExpectation{Exists: true, Data: []byte("old"), Metadata: &changed}, 16, nil); err != nil || !result.Swapped {
				t.Fatalf("swap over the expected metadata: %+v err=%v", result, err)
			}
		})
	}
}

// An access-list change that lands between the comparison and the rename is
// not stopped by the share modes. The publication keeps it: the published
// file gets the newer access list, and the returned metadata is the file's.
func TestPublishSharedFileKeepsAnAccessListChangedAtTheSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := readSharedFileForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := swapBeforeReplace
	swapBeforeReplace = func(string) { grantBackupOperatorsReadForTest(t, path) }
	t.Cleanup(func() { swapBeforeReplace = previous })
	published, swapped, err := PublishSharedFile(SharedPublish{
		Base: base, CompareMetadata: true, Data: []byte("new"), Metadata: &base.Metadata,
		Protect: protectForTest, Limit: 16, TempPattern: ".shared-*.tmp",
	})
	if err != nil || !swapped {
		t.Fatalf("publish: swapped=%t err=%v", swapped, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "new" {
		t.Fatalf("published %q err=%v", data, err)
	}
	if now := requireBackupOperatorsReadForTest(t, path); now != published {
		t.Fatalf("returned metadata %+v, file has %+v", published, now)
	}
}

// Update renders again on a newer file, whether its bytes or only its
// metadata changed, and publishes over it with its metadata.
func TestSharedFileWriterUpdateRendersAgainOnANewerFile(t *testing.T) {
	for _, change := range []string{"content", "access list", "attributes"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "requirements.toml")
			if err := os.WriteFile(path, []byte("admin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			base, err := readSharedFileForTest(path)
			if err != nil {
				t.Fatal(err)
			}
			done := false
			writer := sharedWriterForTest(func(string) {
				if done {
					return
				}
				done = true
				switch change {
				case "content":
					if err := os.WriteFile(path, []byte("admin\nconcurrent\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "access list":
					grantBackupOperatorsReadForTest(t, path)
				default:
					if err := windows.SetFileAttributes(utf16ForTest(t, path), base.Metadata.Attributes|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED); err != nil {
						t.Fatal(err)
					}
				}
			})
			renders := 0
			write, err := writer.Update(base, func(current SharedFile) (SharedEdit, error) {
				renders++
				return appendRender("defenseclaw\n")(current)
			})
			if err != nil || !write.Written || renders != 2 {
				t.Fatalf("update: written=%t renders=%d err=%v", write.Written, renders, err)
			}
			now, err := readSharedFileForTest(path)
			if err != nil {
				t.Fatal(err)
			}
			if !now.Same(write.Published) {
				t.Fatalf("the file is not what the write published: %+v, want %+v", now, write.Published)
			}
			switch change {
			case "content":
				if string(now.Data) != "admin\nconcurrent\ndefenseclaw\n" {
					t.Fatalf("lost the concurrent save: %q", now.Data)
				}
			case "access list":
				requireBackupOperatorsReadForTest(t, path)
			default:
				if now.Metadata.Attributes&windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
					t.Fatalf("lost the concurrent attribute change: %#x", now.Metadata.Attributes)
				}
			}
		})
	}
}

// Undo puts back the replaced file, content and metadata, while the path
// holds the write. Over a newer file it keeps that file, and applies the
// rollback's own change to it when a rebase is given.
func TestSharedFileWriterUndo(t *testing.T) {
	setup := func(t *testing.T) (SharedFileWriter, SharedFileWrite, string) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if err := os.WriteFile(path, []byte("admin\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base, err := readSharedFileForTest(path)
		if err != nil {
			t.Fatal(err)
		}
		writer := sharedWriterForTest(nil)
		write, err := writer.Update(base, appendRender("defenseclaw\n"))
		if err != nil || !write.Written {
			t.Fatalf("update: %v", err)
		}
		return writer, write, path
	}
	t.Run("exact", func(t *testing.T) {
		writer, write, path := setup(t)
		if err := writer.Undo(write, nil); err != nil {
			t.Fatal(err)
		}
		if now, err := readSharedFileForTest(path); err != nil || !now.Same(write.Replaced) {
			t.Fatalf("undo did not put back the replaced file: %+v err=%v\nwant %+v", now, err, write.Replaced)
		}
	})
	for _, change := range []string{"content", "access list"} {
		t.Run("newer "+change, func(t *testing.T) {
			writer, write, path := setup(t)
			if change == "content" {
				if err := os.WriteFile(path, []byte("admin\ndefenseclaw\nconcurrent\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				grantBackupOperatorsReadForTest(t, path)
			}
			newer, err := readSharedFileForTest(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Undo(write, nil); !errors.Is(err, ErrSwapRaced) {
				t.Fatalf("undo over a newer file without a rebase: %v", err)
			}
			if now, err := readSharedFileForTest(path); err != nil || !now.Same(newer) {
				t.Fatalf("undo replaced the newer file: %+v err=%v", now, err)
			}
			rebase := func(current SharedFile) (SharedEdit, error) {
				return SharedEdit{Data: bytes.Replace(current.Data, []byte("defenseclaw\n"), nil, 1)}, nil
			}
			if err := writer.Undo(write, rebase); err != nil {
				t.Fatalf("undo with a rebase: %v", err)
			}
			now, err := readSharedFileForTest(path)
			if err != nil {
				t.Fatal(err)
			}
			want := "admin\n"
			if change == "content" {
				want = "admin\nconcurrent\n"
			} else {
				requireBackupOperatorsReadForTest(t, path)
			}
			if string(now.Data) != want {
				t.Fatalf("rebased undo left %q, want %q", now.Data, want)
			}
		})
	}
}
