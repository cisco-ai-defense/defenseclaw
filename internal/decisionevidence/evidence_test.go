package decisionevidence

import (
	"encoding/json"
	"testing"
)

func TestRecordAuditStringNormalizes(t *testing.T) {
	rec := Record{Decision: "alert", Sources: []string{"agent-control", "local", "local"}}
	body := rec.AuditString()
	var decoded Record
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("json: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Fatalf("schema not set: %+v", decoded)
	}
	if len(decoded.Sources) != 2 || decoded.Sources[0] != "agent-control" || decoded.Sources[1] != "local" {
		t.Fatalf("sources not normalized: %+v", decoded.Sources)
	}
}

func TestCatalogResourceContextMap(t *testing.T) {
	ctx := CatalogResource{ResourceID: "database:customers", SensitivityDomain: "customer_pii", Registered: true, PIIFields: []string{"email"}}.ContextMap()
	if ctx["resource_id"] != "database:customers" || ctx["registered"] != true {
		t.Fatalf("unexpected context map: %+v", ctx)
	}
	fields, ok := ctx["pii_fields"].([]string)
	if !ok || fields[0] != "email" {
		t.Fatalf("unexpected pii fields: %+v", ctx["pii_fields"])
	}
}
