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

//go:build windows

package connector

import (
	"errors"
	"os"
)

// removedSavedCopyPrivate: on Windows the saved copy is private by the
// owner-only DACL of the backup folder (ensureManagedBackupDirRestricted)
// and of the file atomicReplaceFileNoFollow creates; Go's mode bits say
// nothing about it.
func removedSavedCopyPrivate(os.FileInfo) error { return nil }

// removedInPlaceRefusal is never nil on Windows: no release wrote an
// OpenHands script there (its hooks.json runs the native launcher, which
// blocks the removed connectors), and an OmniGent module there gets the
// rename, or keeps its tokens when it has other names, so it still reaches
// the retired gateway route, which blocks every call. until 1.1, with
// removed.go.
func removedInPlaceRefusal(os.FileInfo, os.FileInfo) error {
	return errors.New("on Windows the stub is only renamed over the path")
}

// removedStubMetadataRefusal is nil on Windows: no mode bit or owner check
// decides whether an agent runs or loads a file there. until 1.1, with
// removed.go.
func removedStubMetadataRefusal(os.FileInfo, os.FileInfo, os.FileMode) error { return nil }
