// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"
	"io"
	"testing"
)

type shortJSONLFile struct {
	written     int
	truncateTo  int64
	truncateErr error
}

func (file *shortJSONLFile) Write(value []byte) (int, error) {
	file.written = len(value) / 2
	return file.written, io.ErrShortWrite
}

func (file *shortJSONLFile) Truncate(size int64) error {
	file.truncateTo = size
	return file.truncateErr
}

func TestAppendJSONLLineRollsBackShortWriteBeforeRetry(t *testing.T) {
	file := &shortJSONLFile{}
	size := int64(41)
	n, err, rolledBack := appendJSONLLine(file, &size, []byte("{\"safe\":true}\n"))
	if !errors.Is(err, io.ErrShortWrite) || n != file.written || !rolledBack {
		t.Fatalf("append result n=%d error=%v rolledBack=%t", n, err, rolledBack)
	}
	if size != 41 || file.truncateTo != 41 {
		t.Fatalf("rollback size=%d truncateTo=%d", size, file.truncateTo)
	}
}

func TestAppendJSONLLineReportsUnrecoverableFragment(t *testing.T) {
	file := &shortJSONLFile{truncateErr: errors.New("truncate failed")}
	size := int64(41)
	n, err, rolledBack := appendJSONLLine(file, &size, []byte("{\"safe\":true}\n"))
	if !errors.Is(err, io.ErrShortWrite) || n != file.written || rolledBack {
		t.Fatalf("append result n=%d error=%v rolledBack=%t", n, err, rolledBack)
	}
	if size != 41+int64(file.written) || file.truncateTo != 41 {
		t.Fatalf("failed rollback size=%d truncateTo=%d", size, file.truncateTo)
	}
}
