// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// readNativeEditFile reads the text of a file an Edit or MultiEdit changes;
// tests replace it. ok is false for a file that cannot be read as text.
var readNativeEditFile = func(name string) (string, bool) {
	return readNativeEditFileOn(runtime.GOOS, name)
}

// readNativeEditFileOn reads name as the gateway running on goos would. On
// Windows the daemon configuration is a POSIX path the gateway cannot place
// (a missing \etc\docker\daemon.json on the current drive would read as an
// empty document and so allow an edit of the real file), so nothing is read
// and the edit is judged on the text the call carries.
func readNativeEditFileOn(goos, name string) (string, bool) {
	if goos == "windows" {
		return "", false
	}
	return readBoundedTextFile(name)
}

// withNativeEditFileContents gives the content proof of Docker's daemon
// configuration the text of the file each Edit or MultiEdit of the call
// changes, so an edit is judged on the document it leaves, as the direct write
// of that document is, and not on the pieces it is cut into. A file that does
// not exist reads as empty text. A file that cannot be read (permission, too
// large, not a regular file or not text) is left out, and its edit is judged
// on the text the call carries. A gateway whose action runs elsewhere, or on
// Windows where the file is a POSIX path it cannot place, reads nothing.
func withNativeEditFileContents(request trustedActionRequest) map[string]string {
	if request.SkipLocalFilesystemResolution || runtime.GOOS == "windows" {
		return nil
	}
	var contents map[string]string
	for target, file := range actionfacts.DockerDaemonConfigEditFiles(request.Input) {
		text, ok := readNativeEditFile(file)
		if !ok {
			continue
		}
		if contents == nil {
			contents = map[string]string{}
		}
		contents[target] = text
	}
	return contents
}

func readBoundedTextFile(name string) (string, bool) {
	file, err := os.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return "", true
	}
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(file, actionfacts.NativeEditContentLimit+1))
	if err != nil || len(data) > actionfacts.NativeEditContentLimit {
		return "", false
	}
	return string(data), true
}
