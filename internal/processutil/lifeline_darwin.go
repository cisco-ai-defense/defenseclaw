// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package processutil

import (
	"errors"
	"io"
	"os"
	"time"
)

// lifelineWait bounds the wait for the lifeline to close once the command's
// group is gone; tests shorten it.
var lifelineWait = time.Second

// lifelineClosed reports whether every write end of r is closed within wait.
func lifelineClosed(r *os.File, wait time.Duration) bool {
	if err := r.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return false
	}
	buf := make([]byte, 64)
	for {
		_, err := r.Read(buf)
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
	}
}
