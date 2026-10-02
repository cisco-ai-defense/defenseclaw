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

//go:build !unix

package workspace

import (
	"context"
	"os"
)

const oNoFollow = 0

func platformSupported() bool { return false }

func identityOf(os.FileInfo) (FileID, bool) { return FileID{}, false }

func linkCount(os.FileInfo) uint64 { return 1 }

func ownerUID(os.FileInfo) (int, bool) { return 0, false }

func lockPath(context.Context, string) (func(), error) { return nil, ErrUnsupportedPlatform }
