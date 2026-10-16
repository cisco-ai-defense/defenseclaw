package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestProfileWarningDoesNotCallAWindowsGroupSIDUnknown(t *testing.T) {
	group := "S-1-12-1-1111111111-2222222222-3333333333-4444444444"
	assignments := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: []string{group}}}}
	warnings := unknownAssignmentGroupsForOS(context.Background(), assignments,
		func(context.Context, string) (bool, error) { return false, nil }, nil, nil, "windows")
	if strings.Contains(strings.Join(warnings, "\n"), "not known to this host") {
		t.Fatalf("a configured SID can match the sign-in token: %v", warnings)
	}
	deleted := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: []string{"S-1-5-21-1-2-3-1104"}}}}
	warnings = unknownAssignmentGroupsForOS(context.Background(), deleted,
		func(context.Context, string) (bool, error) { return false, nil }, nil, nil, "windows")
	if !strings.Contains(strings.Join(warnings, "\n"), "not known to this host") {
		t.Fatalf("a domain SID the LSA cannot map must still be reported: %v", warnings)
	}
	unknown := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: []string{"missing-group"}}}}
	warnings = unknownAssignmentGroupsForOS(context.Background(), unknown,
		func(context.Context, string) (bool, error) { return false, nil }, nil, nil, "windows")
	if !strings.Contains(strings.Join(warnings, "\n"), "not known to this host") {
		t.Fatalf("a genuinely unknown group must still be reported: %v", warnings)
	}
}

func TestProfileWarningAcceptsAResolvedWindowsGroupSID(t *testing.T) {
	assignments := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: []string{`CORP\analysts`}}}}
	set := &guardrailProfileSet{assignments: assignments}
	set.groupSIDs = newProfileGroupSIDs(assignments, func(string) (string, error) {
		return "S-1-5-21-860-1-2-1105", nil
	}, time.Second)
	warnings := set.unknownGroupWarningsWith(
		func(context.Context, string) (bool, error) { return false, nil }, nil, nil, nil,
		func() identityCacheHealth { return identityCacheHealth{} }, time.Second,
	)
	if len(warnings) != 0 {
		t.Fatalf("the resolved SID can match the sign-in token: %v", warnings)
	}
}
