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

package egress

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedFeedsMatchFiles(t *testing.T) {
	for name, get := range map[string]func() []byte{"blocklist.yaml": BlocklistYAML, "allowlist.yaml": AllowlistYAML} {
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got := get()
		if !bytes.Equal(got, want) {
			t.Errorf("%s: embedded bytes differ from the file", name)
		}
		got[0] ^= 0xff
		if !bytes.Equal(get(), want) {
			t.Errorf("%s: callers can mutate the embedded feed", name)
		}
	}
}
