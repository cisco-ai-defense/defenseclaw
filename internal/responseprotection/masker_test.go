package responseprotection

import (
	"encoding/json"
	"testing"
)

func TestMaskJSONRowsAndCanary(t *testing.T) {
	m := New(Config{PIIFields: []string{"email", "ssn"}, MaxRows: 1, MaxBytes: 4096, CanaryRate: 1, CanaryPrefix: "TEST-CANARY"})
	result := m.Mask([]byte(`{"rows":[{"email":"a@example.com","ssn":"123"},{"email":"b@example.com"}]}`), "agent-a")
	if !result.Truncated || !result.CanaryInjected || result.RowsReturned != 1 {
		t.Fatalf("unexpected result: %+v body=%s", result, string(result.Body))
	}
	var decoded map[string]any
	if err := json.Unmarshal(result.Body, &decoded); err != nil {
		t.Fatalf("json: %v body=%s", err, result.Body)
	}
	rows := decoded["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("expected canary + one row, got %d", len(rows))
	}
	if rows[0].(map[string]any)["_defenseclaw_canary"] != true {
		t.Fatalf("missing canary: %+v", rows[0])
	}
	row := rows[1].(map[string]any)
	if row["email"] == "a@example.com" || row["ssn"] == "123" {
		t.Fatalf("PII was not masked: %+v", row)
	}
}

func TestMaskTextAndByteCap(t *testing.T) {
	m := New(Config{PIIFields: []string{"email"}, MaxBytes: 24})
	result := m.Mask([]byte(`{"email":"a@example.com","note":"long long long"}`), "agent-a")
	if !result.Truncated || len(result.Body) != 24 {
		t.Fatalf("expected byte truncation, got %+v", result)
	}
	if len(result.FieldsMasked) != 1 || result.FieldsMasked[0] != "email" {
		t.Fatalf("expected masked email, got %+v", result.FieldsMasked)
	}
}
