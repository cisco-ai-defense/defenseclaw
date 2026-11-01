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
	"encoding/json"
	"os"
	"path/filepath"
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
	r, err := store.Receive(id, 3, "")
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

// F10: the delivery id the caller gave is in the root-only receipt, its
// public receipt event, receipt.json, the result bundle block and the
// refusal summary.
func TestReceiptRecordsDeliveryID(t *testing.T) {
	store := testStore(t)
	const delivery = "agent-7:delivery.0042_x"
	r, err := store.Receive(testBundleID(70), 3, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if r.DeliveryID != delivery {
		t.Fatalf("receipt delivery id = %q", r.DeliveryID)
	}
	if got := r.Status(nil); got.DeliveryID != delivery || got.ReceiptID != r.ReceiptID {
		t.Fatalf("bundle block = %+v", got)
	}
	if err := store.Fail(r, CodeSignatureInvalid, "refused"); err != nil {
		t.Fatal(err)
	}
	if refusal := r.Refusal(); refusal == nil || refusal.DeliveryID != delivery {
		t.Fatalf("refusal = %+v", refusal)
	}
	private, err := readStoreFile(store.receiptPath(r.ReceiptID))
	if err != nil || !strings.Contains(string(private), `"delivery_id": "`+delivery+`"`) {
		t.Fatalf("root-only receipt %s (%v)", private, err)
	}
	event, err := enterprisestatus.ReadPublicReceipt(filepath.Join(store.PublicReceiptEventsDir(), r.ReceiptID+".json"))
	if err != nil || event.DeliveryID != delivery {
		t.Fatalf("receipt event = %+v, %v", event, err)
	}
	summary, err := enterprisestatus.ReadPublicReceipt(store.PublicReceiptPath())
	if err != nil || summary.DeliveryID != delivery || summary.LastRefusal == nil || summary.LastRefusal.DeliveryID != delivery {
		t.Fatalf("receipt.json = %+v, %v", summary, err)
	}
}

// F10: without --delivery-id no file gains a delivery_id member, so every
// output stays byte-identical to a build without the flag.
func TestReceiptWithoutDeliveryIDHasNoMember(t *testing.T) {
	store := testStore(t)
	r, err := store.Receive(testBundleID(71), 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(r, CodeSignatureInvalid, "refused"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.receiptPath(r.ReceiptID), store.PublicReceiptPath(),
		filepath.Join(store.PublicReceiptEventsDir(), r.ReceiptID+".json")} {
		raw, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(raw), "delivery_id") {
			t.Fatalf("%s: %s (%v)", path, raw, err)
		}
	}
	for _, doc := range []any{r.Status(nil), r.Refusal()} {
		raw, err := json.Marshal(doc)
		if err != nil || strings.Contains(string(raw), "delivery_id") {
			t.Fatalf("%s (%v)", raw, err)
		}
	}
}

// F10: the store refuses a delivery id the CLI would have refused, and
// writes no receipt for it.
func TestReceiveRefusesAnInvalidDeliveryID(t *testing.T) {
	store := testStore(t)
	for _, id := range []string{"has space", strings.Repeat("a", 129), "tab\tid", "café"} {
		if r, err := store.Receive(testBundleID(72), 3, id); err == nil || r != nil {
			t.Fatalf("Receive(%q) = %+v, %v; want a refusal", id, r, err)
		}
	}
	if receipts, err := store.Receipts(); err != nil || len(receipts) != 0 {
		t.Fatalf("receipts after refusals: %v, %v", receipts, err)
	}
}

// #1320: every public receipt event carries the delivery sequence of the
// device, one more for each new delivery, so receipts order without a clock.
func TestPublicReceiptEventsCarryAGrowingSeq(t *testing.T) {
	store := testStore(t)
	var seqs []uint64
	for i := 1; i <= 3; i++ {
		r, err := store.Receive(testBundleID(80+i), uint64(i), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Fail(r, CodeSignatureInvalid, "refused"); err != nil {
			t.Fatal(err)
		}
		event, err := enterprisestatus.ReadPublicReceipt(filepath.Join(store.PublicReceiptEventsDir(), r.ReceiptID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, event.Seq)
	}
	if seqs[0] == 0 || seqs[1] != seqs[0]+1 || seqs[2] != seqs[1]+1 {
		t.Fatalf("seq of three deliveries = %v, want three consecutive numbers from 1", seqs)
	}
	// receipt.json keeps the first refusal while no delivery reached staging.
	summary, err := enterprisestatus.ReadPublicReceipt(store.PublicReceiptPath())
	if err != nil || summary.Seq != seqs[0] {
		t.Fatalf("receipt.json seq = %d (%v), want %d", summary.Seq, err, seqs[0])
	}
}
