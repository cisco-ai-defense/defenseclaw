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

package workspace

import (
	"bytes"
	"fmt"
)

// RiskZeroFilled flags a changed file whose text ends in a run of zero
// bytes: what a MicroVM stopped without a flush (the OpenShell gateway
// restarted under it) leaves of a file written in its last seconds. A pull
// brought such a file back without a word (GAP-0289).
const RiskZeroFilled RiskKind = "zero-filled"

// minZeroTail is the shortest run of trailing zero bytes zeroFilledFlags
// flags: a page the guest had not written back reads as zeros.
const minZeroTail = 16

// zeroFilledFlags flags the changed files whose content is text followed
// by at least minZeroTail zero bytes. It is information (SeverityInfo):
// nothing there runs code, but the file is likely cut short. In a sandbox
// that went down without a flush (unflushed) it also flags the files it
// brings back empty: a file written in its last seconds can come back with
// no bytes at all, which read as a plain "+0 -0" (GAP-0367).
func zeroFilledFlags(changes []TreeChange, content contentFunc, unflushed bool) []Flag {
	var out []Flag
	for _, c := range changes {
		if c.NewOID == "" || c.Status == "D" {
			continue
		}
		b, ok := content(c, true)
		if !ok {
			continue
		}
		if len(b) == 0 && unflushed {
			out = append(out, Flag{Path: c.Path, Label: c.Path, Kind: RiskZeroFilled, Severity: SeverityInfo,
				Detail: "is empty, which a MicroVM stopped without a flush can leave of a file written in its last seconds: check it"})
			continue
		}
		body := bytes.TrimRight(b, "\x00")
		if tail := len(b) - len(body); tail >= minZeroTail && len(body) > 0 && bytes.IndexByte(body, 0) < 0 {
			out = append(out, Flag{Path: c.Path, Label: c.Path, Kind: RiskZeroFilled, Severity: SeverityInfo,
				Detail: fmt.Sprintf("ends in %d zero bytes, what a MicroVM stopped without a flush leaves of a file written in its last seconds: check it", tail)})
		}
	}
	return out
}
