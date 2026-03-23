package unit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestDefaultSkillActions(t *testing.T) {
	actions := config.DefaultSkillActions()

	tests := []struct {
		severity        string
		wantRuntime     config.RuntimeAction
		wantFile        config.FileAction
	}{
		{"CRITICAL", config.RuntimeBlock, config.FileActionQuarantine},
		{"HIGH", config.RuntimeBlock, config.FileActionQuarantine},
		{"MEDIUM", config.RuntimeAllow, config.FileActionNone},
		{"LOW", config.RuntimeAllow, config.FileActionNone},
		{"INFO", config.RuntimeAllow, config.FileActionNone},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			action := actions.ForSeverity(tt.severity)
			if action.Runtime != tt.wantRuntime {
				t.Errorf("ForSeverity(%q).Runtime = %q, want %q", tt.severity, action.Runtime, tt.wantRuntime)
			}
			if action.File != tt.wantFile {
				t.Errorf("ForSeverity(%q).File = %q, want %q", tt.severity, action.File, tt.wantFile)
			}
		})
	}
}

func TestForSeverityCaseInsensitive(t *testing.T) {
	actions := config.DefaultSkillActions()

	variants := []string{"critical", "Critical", "CRITICAL", "cRiTiCaL"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			action := actions.ForSeverity(v)
			if action.Runtime != config.RuntimeBlock {
				t.Errorf("ForSeverity(%q).Runtime = %q, want %q", v, action.Runtime, config.RuntimeBlock)
			}
		})
	}
}

func TestForSeverityUnknownFallsBackToInfo(t *testing.T) {
	actions := config.DefaultSkillActions()
	action := actions.ForSeverity("UNKNOWN")
	if action.Runtime != config.RuntimeAllow {
		t.Errorf("ForSeverity(UNKNOWN).Runtime = %q, want %q", action.Runtime, config.RuntimeAllow)
	}
	if action.File != config.FileActionNone {
		t.Errorf("ForSeverity(UNKNOWN).File = %q, want %q", action.File, config.FileActionNone)
	}
}

func TestShouldBlockAndQuarantine(t *testing.T) {
	actions := config.DefaultSkillActions()

	if !actions.ShouldBlock("CRITICAL") {
		t.Error("expected CRITICAL to be blocked")
	}
	if !actions.ShouldBlock("HIGH") {
		t.Error("expected HIGH to be blocked")
	}
	if actions.ShouldBlock("MEDIUM") {
		t.Error("expected MEDIUM not to be blocked with default config")
	}

	if !actions.ShouldQuarantine("CRITICAL") {
		t.Error("expected CRITICAL to be quarantined")
	}
	if actions.ShouldQuarantine("LOW") {
		t.Error("expected LOW not to be quarantined with default config")
	}
}

func TestStrictPolicyBlocksMedium(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{Runtime: config.RuntimeBlock, File: config.FileActionQuarantine},
		High:     config.SeverityAction{Runtime: config.RuntimeBlock, File: config.FileActionQuarantine},
		Medium:   config.SeverityAction{Runtime: config.RuntimeBlock, File: config.FileActionQuarantine},
		Low:      config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Info:     config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
	}

	if !actions.ShouldBlock("MEDIUM") {
		t.Error("strict policy should block MEDIUM")
	}
	if !actions.ShouldQuarantine("MEDIUM") {
		t.Error("strict policy should quarantine MEDIUM")
	}
	if actions.ShouldBlock("LOW") {
		t.Error("strict policy should not block LOW")
	}
}

func TestPermissivePolicyAllowsHigh(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{Runtime: config.RuntimeBlock, File: config.FileActionQuarantine},
		High:     config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Medium:   config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Low:      config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Info:     config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
	}

	if actions.ShouldBlock("HIGH") {
		t.Error("permissive policy should not block HIGH")
	}
	if !actions.ShouldBlock("CRITICAL") {
		t.Error("permissive policy should still block CRITICAL")
	}
}

func TestQuarantineWithoutBlock(t *testing.T) {
	actions := config.SkillActionsConfig{
		Critical: config.SeverityAction{Runtime: config.RuntimeBlock, File: config.FileActionQuarantine},
		High:     config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionQuarantine},
		Medium:   config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Low:      config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
		Info:     config.SeverityAction{Runtime: config.RuntimeAllow, File: config.FileActionNone},
	}

	action := actions.ForSeverity("HIGH")
	if action.Runtime != config.RuntimeAllow {
		t.Errorf("expected HIGH runtime to be allow, got %q", action.Runtime)
	}
	if action.File != config.FileActionQuarantine {
		t.Errorf("expected HIGH file to be quarantine, got %q", action.File)
	}
}

func TestValidateAcceptsValid(t *testing.T) {
	actions := config.DefaultSkillActions()
	if err := actions.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

func TestValidateRejectsInvalidRuntime(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.Medium.Runtime = "deny"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid runtime")
	}
}

func TestValidateRejectsInvalidFile(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.High.File = "delete"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid file action")
	}
}
