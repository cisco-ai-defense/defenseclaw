package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func defaultProfile() *FallbackProfile {
	return LoadFallbackProfile("")
}

func TestEvaluateAdmissionFallback_Blocked(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "evil",
		BlockList:  []ListEntry{{TargetType: "skill", TargetName: "evil", Reason: "malware"}},
	}, defaultProfile())

	if out.Verdict != "blocked" {
		t.Errorf("verdict = %q, want blocked", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_ExplicitAllowBeatsPolicy(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "trusted",
		AllowList:  []ListEntry{{TargetType: "skill", TargetName: "trusted", Reason: "vendor"}},
	}, defaultProfile())

	if out.Verdict != "allowed" {
		t.Errorf("verdict = %q, want allowed", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_BlockBeatsAllow(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "conflict",
		BlockList:  []ListEntry{{TargetType: "skill", TargetName: "conflict", Reason: "bad"}},
		AllowList:  []ListEntry{{TargetType: "skill", TargetName: "conflict", Reason: "good"}},
	}, defaultProfile())

	if out.Verdict != "blocked" {
		t.Errorf("verdict = %q, want blocked", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_FirstPartyAllow(t *testing.T) {
	profile := defaultProfile()
	profile.FirstPartyAllow[firstPartyKey("plugin", "defenseclaw")] = firstPartyEntry{
		Reason:             "first-party",
		SourcePathContains: []string{".defenseclaw", ".openclaw/extensions"},
	}

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "defenseclaw",
		Path:       "/home/user/.openclaw/extensions/defenseclaw",
	}, profile)

	if out.Verdict != "allowed" {
		t.Errorf("verdict = %q, want allowed (first-party with provenance)", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_FirstPartyBadProvenance(t *testing.T) {
	profile := defaultProfile()
	profile.FirstPartyAllow[firstPartyKey("plugin", "defenseclaw")] = firstPartyEntry{
		Reason:             "first-party",
		SourcePathContains: []string{".defenseclaw", ".openclaw/extensions"},
	}

	// Temp dir should NOT match
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "defenseclaw",
		Path:       "/tmp/dclaw-plugin-fetch-abc123/defenseclaw",
	}, profile)

	if out.Verdict != "scan" {
		t.Errorf("verdict = %q, want scan (temp dir should not match provenance)", out.Verdict)
	}

	// Random unrelated path should NOT match
	out2 := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "defenseclaw",
		Path:       "/home/user/random/plugin",
	}, profile)

	if out2.Verdict != "scan" {
		t.Errorf("verdict = %q, want scan (no provenance match)", out2.Verdict)
	}
}

func TestEvaluateAdmissionFallback_FirstPartyNoConstraints(t *testing.T) {
	profile := defaultProfile()
	profile.FirstPartyAllow[firstPartyKey("plugin", "defenseclaw")] = firstPartyEntry{
		Reason: "first-party",
	}

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "defenseclaw",
	}, profile)

	if out.Verdict != "allowed" {
		t.Errorf("verdict = %q, want allowed (no constraints = allow)", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_FirstPartyNoBypass(t *testing.T) {
	profile := defaultProfile()
	profile.AllowListBypassScan = false
	profile.FirstPartyAllow[firstPartyKey("plugin", "defenseclaw")] = firstPartyEntry{
		Reason: "first-party",
	}

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "defenseclaw",
	}, profile)

	if out.Verdict != "scan" {
		t.Errorf("verdict = %q, want scan (bypass disabled)", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_ScanOnInstallDisabled(t *testing.T) {
	profile := defaultProfile()
	profile.ScanOnInstall = false

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "new-skill",
	}, profile)

	if out.Verdict != "allowed" {
		t.Errorf("verdict = %q, want allowed (scan disabled)", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_NoScanRequiresScan(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "new-skill",
	}, defaultProfile())

	if out.Verdict != "scan" {
		t.Errorf("verdict = %q, want scan", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_CleanScan(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "safe",
		ScanResult: &ScanResultInput{MaxSeverity: "INFO", TotalFindings: 0},
	}, defaultProfile())

	if out.Verdict != "clean" {
		t.Errorf("verdict = %q, want clean", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_HighRejected(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "risky",
		ScanResult: &ScanResultInput{MaxSeverity: "HIGH", TotalFindings: 2},
	}, defaultProfile())

	if out.Verdict != "rejected" {
		t.Errorf("verdict = %q, want rejected", out.Verdict)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("file_action = %q, want quarantine", out.FileAction)
	}
	if out.InstallAction != "block" {
		t.Errorf("install_action = %q, want block", out.InstallAction)
	}
}

func TestEvaluateAdmissionFallback_MediumWarning(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "iffy",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 1},
	}, defaultProfile())

	if out.Verdict != "warning" {
		t.Errorf("verdict = %q, want warning", out.Verdict)
	}
	if out.FileAction != "none" {
		t.Errorf("file_action = %q, want none", out.FileAction)
	}
}

func TestEvaluateAdmissionFallback_InstallBlockAloneRejects(t *testing.T) {
	profile := defaultProfile()
	profile.Actions["HIGH"] = fallbackAction{Runtime: "allow", File: "none", Install: "block"}

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "partial",
		ScanResult: &ScanResultInput{MaxSeverity: "HIGH", TotalFindings: 1},
	}, profile)

	if out.Verdict != "rejected" {
		t.Errorf("verdict = %q, want rejected (install=block should reject)", out.Verdict)
	}
	if out.RuntimeAction != "allow" {
		t.Errorf("runtime_action = %q, want allow (only install should block)", out.RuntimeAction)
	}
	if out.FileAction != "none" {
		t.Errorf("file_action = %q, want none", out.FileAction)
	}
	if out.InstallAction != "block" {
		t.Errorf("install_action = %q, want block", out.InstallAction)
	}
}

func TestEvaluateAdmissionFallback_ScannerOverride(t *testing.T) {
	profile := defaultProfile()
	profile.ScannerOverrides["mcp"] = map[string]fallbackAction{
		"MEDIUM": {Runtime: "block", File: "quarantine", Install: "block"},
	}

	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "mcp",
		TargetName: "risky-mcp",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 1},
	}, profile)

	if out.Verdict != "rejected" {
		t.Errorf("verdict = %q, want rejected (MCP override)", out.Verdict)
	}

	outSkill := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "medium-skill",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 1},
	}, profile)

	if outSkill.Verdict != "warning" {
		t.Errorf("skill verdict = %q, want warning (no MCP override for skill)", outSkill.Verdict)
	}
}

func TestEvaluateAdmissionFallback_NilProfile(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "new",
	}, nil)

	if out.Verdict != "scan" {
		t.Errorf("verdict = %q, want scan (nil profile uses defaults)", out.Verdict)
	}
}

func TestEvaluateAdmissionFallback_UnknownSeverityWarns(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "skill",
		TargetName: "odd",
		ScanResult: &ScanResultInput{MaxSeverity: "UNKNOWN", TotalFindings: 1},
	}, defaultProfile())

	if out.Verdict != "warning" {
		t.Errorf("verdict = %q, want warning (unknown severity has no block rule)", out.Verdict)
	}
}

func TestLoadFallbackProfile_FromDataJSON(t *testing.T) {
	dir := t.TempDir()
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"allow_list_bypass_scan": false,
			"scan_on_install":        false,
		},
		"actions": map[string]interface{}{
			"MEDIUM": map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
		},
		"first_party_allow_list": []map[string]interface{}{
			{
				"target_type":          "skill",
				"target_name":          "codeguard",
				"reason":               "first-party",
				"source_path_contains": []string{".defenseclaw", ".openclaw/skills"},
			},
		},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o600)

	profile := LoadFallbackProfile(dir)

	if profile.AllowListBypassScan {
		t.Error("expected AllowListBypassScan=false from data.json")
	}
	if profile.ScanOnInstall {
		t.Error("expected ScanOnInstall=false from data.json")
	}
	if act, ok := profile.Actions["MEDIUM"]; !ok || act.Runtime != "block" {
		t.Errorf("expected MEDIUM action override, got %+v", profile.Actions["MEDIUM"])
	}
	key := firstPartyKey("skill", "codeguard")
	if _, ok := profile.FirstPartyAllow[key]; !ok {
		t.Error("expected first-party entry for codeguard")
	}
}

func TestLoadFallbackProfile_FromRegoSubdir(t *testing.T) {
	dir := t.TempDir()
	regoDir := filepath.Join(dir, "rego")
	os.MkdirAll(regoDir, 0o755)

	data := map[string]interface{}{
		"config": map[string]interface{}{
			"scan_on_install": false,
		},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(filepath.Join(regoDir, "data.json"), raw, 0o600)

	profile := LoadFallbackProfile(dir)

	if profile.ScanOnInstall {
		t.Error("expected ScanOnInstall=false from rego/data.json")
	}
}

func TestLoadFallbackProfile_MissingDir(t *testing.T) {
	profile := LoadFallbackProfile("/nonexistent/path")
	if !profile.AllowListBypassScan || !profile.ScanOnInstall {
		t.Error("missing dir should return defaults")
	}
	if _, ok := profile.Actions["CRITICAL"]; !ok {
		t.Error("defaults should include CRITICAL action")
	}
}

func TestLoadFallbackProfile_EmptyDir(t *testing.T) {
	profile := LoadFallbackProfile("")
	if !profile.AllowListBypassScan {
		t.Error("empty dir should return defaults")
	}
}
