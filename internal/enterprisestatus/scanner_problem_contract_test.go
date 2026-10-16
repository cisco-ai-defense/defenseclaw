package enterprisestatus

import (
	"encoding/json"
	"testing"
)

func TestDamagedScannerProblemMatchesLifecycleSchema(t *testing.T) {
	result := New("verify", "standalone", "windows", "1.0.2")
	result.Scanners = &ScannerRuntime{State: "not_prepared", Problem: "skill-scanner is missing"}
	result.AddError("scanner_runtime_unavailable", "the prepared scanner runtime is damaged")
	result.Finish("windows", 1603)
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAgainstSchema(t, compileLifecycleSchema(t), document); err != nil {
		t.Fatalf("damaged scanner result violates lifecycle schema: %v\n%s", err, document)
	}
}
