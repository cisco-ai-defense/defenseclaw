package config

import (
	"fmt"
	"strings"
)

func DefaultSkillActions() SkillActionsConfig {
	return SkillActionsConfig{
		Critical: SeverityAction{Runtime: RuntimeBlock, File: FileActionQuarantine},
		High:     SeverityAction{Runtime: RuntimeBlock, File: FileActionQuarantine},
		Medium:   SeverityAction{Runtime: RuntimeAllow, File: FileActionNone},
		Low:      SeverityAction{Runtime: RuntimeAllow, File: FileActionNone},
		Info:     SeverityAction{Runtime: RuntimeAllow, File: FileActionNone},
	}
}

// ForSeverity returns the configured action for a given severity string.
// Severity is matched case-insensitively; unknown values fall back to the Info action.
func (a *SkillActionsConfig) ForSeverity(severity string) SeverityAction {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return a.Critical
	case "HIGH":
		return a.High
	case "MEDIUM":
		return a.Medium
	case "LOW":
		return a.Low
	default:
		return a.Info
	}
}

// ShouldBlock returns true if the runtime action for the given severity is "block".
func (a *SkillActionsConfig) ShouldBlock(severity string) bool {
	return a.ForSeverity(severity).Runtime == RuntimeBlock
}

// ShouldQuarantine returns true if the file action for the given severity is "quarantine".
func (a *SkillActionsConfig) ShouldQuarantine(severity string) bool {
	return a.ForSeverity(severity).File == FileActionQuarantine
}

func (a *SkillActionsConfig) Validate() error {
	entries := []struct {
		label  string
		action SeverityAction
	}{
		{"critical", a.Critical},
		{"high", a.High},
		{"medium", a.Medium},
		{"low", a.Low},
		{"info", a.Info},
	}

	for _, e := range entries {
		switch e.action.Runtime {
		case RuntimeBlock, RuntimeAllow:
		default:
			return fmt.Errorf("config: skill_actions.%s.runtime: invalid value %q (must be %q or %q)",
				e.label, e.action.Runtime, RuntimeBlock, RuntimeAllow)
		}
		switch e.action.File {
		case FileActionNone, FileActionQuarantine:
		default:
			return fmt.Errorf("config: skill_actions.%s.file: invalid value %q (must be %q or %q)",
				e.label, e.action.File, FileActionNone, FileActionQuarantine)
		}
	}
	return nil
}
