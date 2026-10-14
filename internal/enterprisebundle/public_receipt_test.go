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

package enterprisebundle

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestFinishedReceiptWritesPublicReceiptWithoutMessage(t *testing.T) {
	store := NewStore(t.TempDir(), t.TempDir())
	id, err := NewBundleID(time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Receive(id, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.PublicReceiptPath()); !os.IsNotExist(err) {
		t.Fatalf("an unfinished receipt was published: %v", err)
	}
	r.Principal, r.ChangeSummary = "operator:root", "tighten egress"
	const detail = "loader detail that may quote a config value"
	if err := store.Fail(r, CodeSignatureInvalid, detail); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.PublicReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), detail) {
		t.Fatalf("receipt.json carries the error message: %s", raw)
	}
	got, err := enterprisestatus.ReadPublicReceipt(store.PublicReceiptPath())
	if err != nil || got.ReceiptID != id || got.State != StateFailed || got.ErrorCode != string(CodeSignatureInvalid) ||
		got.Actor != configwrite.CurrentOSActor() || got.Principal != "operator:root" || got.ChangeSummary != "tighten egress" || got.FinishedAt == "" {
		t.Fatalf("receipt.json = %+v err=%v", got, err)
	}
	if info, err := os.Stat(store.PublicReceiptPath()); err != nil || (info.Mode().Perm() != 0o644 && os.PathSeparator == '/') {
		t.Fatalf("receipt.json mode = %v err=%v", info, err)
	}
}
