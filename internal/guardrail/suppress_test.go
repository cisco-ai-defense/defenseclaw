package guardrail

import (
	"strings"
	"testing"
)

func TestIsEpoch(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"1776052031", true},
		{"1000000000", true},
		{"2100000000", true},
		{"999999999", false},
		{"2100000001", false},
		{"notanumber", false},
		{"", false},
		{" 1776052031 ", true},
	}
	for _, tc := range tests {
		t.Run(tc.val, func(t *testing.T) {
			if got := IsEpoch(tc.val); got != tc.want {
				t.Errorf("IsEpoch(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestIsPlatformID(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want bool
	}{
		// Real NANP phone numbers — must NOT be suppressed by default.
		// These are the regressions the narrower heuristic fixes:
		// 844-908-8619 is a valid toll-free number, 212-555-1234 is a
		// valid NYC number, 415-867-5309 is a valid SF number. Treating
		// them as platform IDs meant real PII findings silently vanished.
		{"toll_free_phone", "8449088619", false},
		{"valid_nyc_phone", "2125551234", false},
		{"valid_sf_phone", "4158675309", false},
		{"valid_phone_with_country_code", "12125551234", false},

		// Not-really-phone-shaped 10/11-digit strings → still platform IDs.
		// 123... fails because area code must start with 2-9 (N11 blocks
		// and leading-1 blocks are reserved).
		{"leading_one", "1234567890", true},
		// 411 is a valid N11 service code, so the area-code check
		// rejects it and we treat the whole thing as a platform ID.
		{"n11_area_code", "4115551234", true},

		// Other platform-ID-shaped values.
		{"9_digits", "123456789", true},
		{"12_digits", "999999999999", true},

		// Out-of-range or malformed values are not platform IDs.
		{"too_short", "12345678", false},
		{"too_long", "1234567890123", false},
		{"contains_dashes", "123-456-789", false},
		{"empty", "", false},
		{"not_digits", "notdigits", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPlatformID(tc.val); got != tc.want {
				t.Errorf("IsPlatformID(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestPreJudgeStripContent(t *testing.T) {
	strips := []PreJudgeStrip{
		{
			ID:        "STRIP-SYSTEM-SENDER",
			Pattern:   `\b(cli|system|bot|admin)\b`,
			AppliesTo: []string{"pii"},
		},
	}

	t.Run("strips matching content", func(t *testing.T) {
		got := PreJudgeStripContent("Username: cli sent a message", strips, "pii")
		if got == "Username: cli sent a message" {
			t.Error("expected 'cli' to be stripped")
		}
	})

	t.Run("does not strip for non-matching judge type", func(t *testing.T) {
		got := PreJudgeStripContent("Username: cli sent a message", strips, "injection")
		if got != "Username: cli sent a message" {
			t.Errorf("should not strip for injection judge, got %q", got)
		}
	})

	t.Run("empty strips", func(t *testing.T) {
		got := PreJudgeStripContent("test", nil, "pii")
		if got != "test" {
			t.Errorf("got %q, want test", got)
		}
	})
}

// TestPreJudgeStripContent_MessagingBridgeBanners covers the regression
// where WhatsApp / Teams / Slack style gateway status banners embedded
// a phone number or channel ID that the PII judge flagged on every
// benign user turn (e.g. a one-word "great" reply was blocked). The
// status line is transport metadata and must be stripped before the
// PII judge sees it. The injection judge is intentionally NOT covered
// by these strips so a genuine prompt-injection attempt that happens
// to reuse the "System: [...]" prefix is still evaluated in full.
func TestPreJudgeStripContent_MessagingBridgeBanners(t *testing.T) {
	strips := []PreJudgeStrip{
		{
			ID:        "STRIP-MESSAGING-BRIDGE-STATUS",
			Pattern:   `(?im)^[ \t]*System:[ \t]*\[[^\]\n]+\][ \t]+[^\n]*?\b(?:connected|disconnected|reconnected|linked|unlinked|online|offline)\b[^\n]*$`,
			AppliesTo: []string{"pii"},
		},
		{
			ID:        "STRIP-MESSAGING-BRIDGE-TIMESTAMP",
			Pattern:   `(?m)^[ \t]*\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[ \t]+\d{4}-\d{2}-\d{2}[ \t]+\d{1,2}:\d{2}(?::\d{2})?(?:[ \t]+[A-Z]{2,5})?\][ \t]*`,
			AppliesTo: []string{"pii"},
		},
	}

	cases := []struct {
		name     string
		input    string
		wantGone []string
		wantKeep []string
	}{
		{
			name: "whatsapp connect banner + timestamped user reply",
			input: "System: [2026-04-22 12:03:21 EDT] WhatsApp gateway connected as +12069795695.\n" +
				"[Wed 2026-04-22 12:03 EDT] great",
			wantGone: []string{"+12069795695", "WhatsApp gateway", "Wed 2026-04-22"},
			wantKeep: []string{"great"},
		},
		{
			name:     "whatsapp disconnect banner with status code",
			input:    "System: [2026-04-22 08:07:02 EDT] WhatsApp gateway disconnected (status 499)",
			wantGone: []string{"WhatsApp gateway", "disconnected"},
		},
		{
			name:     "telegram bot linked banner",
			input:    "System: [2026-04-22 09:00] Telegram bot linked as @alice_bot.",
			wantGone: []string{"@alice_bot", "Telegram"},
		},
		{
			name:     "benign user sentence with the word connected is NOT stripped",
			input:    "I just connected my laptop to the wifi — all good.",
			wantKeep: []string{"I just connected my laptop"},
		},
		{
			name:     "status banner without an action keyword is NOT stripped",
			input:    "System: [2026-04-22 12:03] everything looks fine here.",
			wantKeep: []string{"everything looks fine here"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PreJudgeStripContent(tc.input, strips, "pii")
			for _, needle := range tc.wantGone {
				if strings.Contains(got, needle) {
					t.Errorf("expected %q to be stripped, still present in: %q", needle, got)
				}
			}
			for _, needle := range tc.wantKeep {
				if !strings.Contains(got, needle) {
					t.Errorf("expected %q to be preserved, missing from: %q", needle, got)
				}
			}

			// Strips must only apply to PII judge: the injection judge
			// needs the full text to detect manipulation attempts.
			injection := PreJudgeStripContent(tc.input, strips, "injection")
			if injection != tc.input {
				t.Errorf("strips leaked into injection judge:\n  in:  %q\n  out: %q", tc.input, injection)
			}
		})
	}
}

func TestFilterPIIEntities(t *testing.T) {
	supps := []FindingSuppression{
		{
			ID:             "SUPP-USERNAME-METADATA",
			FindingPattern: "JUDGE-PII-USER",
			EntityPattern:  `^(cli|system|bot|admin|root)$`,
			Reason:         "System metadata",
		},
		{
			ID:             "SUPP-PHONE-EPOCH",
			FindingPattern: "JUDGE-PII-PHONE",
			EntityPattern:  `^\d{10}$`,
			Condition:      "is_epoch",
			Reason:         "Unix timestamp",
		},
		{
			ID:             "SUPP-PHONE-PLATFORM-ID",
			FindingPattern: "JUDGE-PII-PHONE",
			EntityPattern:  `^\d{9,12}$`,
			Condition:      "is_platform_id",
			Reason:         "Platform ID",
		},
		{
			ID:             "SUPP-IP-PRIVATE",
			FindingPattern: "JUDGE-PII-IP",
			EntityPattern:  `^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)`,
			Reason:         "Private IP",
		},
		{
			ID:             "SUPP-EMAIL-CHATID",
			FindingPattern: "JUDGE-PII-EMAIL",
			EntityPattern:  `^19:[a-f0-9\-]+@unq\.gbl\.spaces$`,
			Reason:         "Teams chatId",
		},
	}

	tests := []struct {
		name       string
		entities   []PIIEntity
		wantKept   int
		wantSuppID string
	}{
		{
			name: "cli username suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-USER", Entity: "cli"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-USERNAME-METADATA",
		},
		{
			name: "system username suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-USER", Entity: "system"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-USERNAME-METADATA",
		},
		{
			name: "real username kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-USER", Entity: "john.doe"},
			},
			wantKept: 1,
		},
		{
			name: "epoch phone suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-PHONE", Entity: "1776052031"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-PHONE-EPOCH",
		},
		{
			// Telegram-style numeric ID (9 digits, no valid NANP
			// structure) should still be suppressed.
			name: "telegram ID phone suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-PHONE", Entity: "123456789"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-PHONE-PLATFORM-ID",
		},
		{
			// Real-looking NANP phone must NOT be suppressed anymore.
			// This was the regression the narrower IsPlatformID fixes.
			name: "real NANP phone kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-PHONE", Entity: "8449088619"},
			},
			wantKept: 1,
		},
		{
			name: "real phone with country code kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-PHONE", Entity: "+15551234567"},
			},
			wantKept: 1,
		},
		{
			name: "private IP suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-IP", Entity: "127.0.0.1"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-IP-PRIVATE",
		},
		{
			name: "10.x IP suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-IP", Entity: "10.0.0.5"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-IP-PRIVATE",
		},
		{
			name: "public IP kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-IP", Entity: "8.8.8.8"},
			},
			wantKept: 1,
		},
		{
			name: "Teams chatId email suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-EMAIL", Entity: "19:f1604ab8-a5fa-484f-a6a4-88745b4695bf@unq.gbl.spaces"},
			},
			wantKept:   0,
			wantSuppID: "SUPP-EMAIL-CHATID",
		},
		{
			name: "real email kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-EMAIL", Entity: "user@example.com"},
			},
			wantKept: 1,
		},
		{
			name: "SSN always kept",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-SSN", Entity: "123-45-6789"},
			},
			wantKept: 1,
		},
		{
			name: "mixed kept and suppressed",
			entities: []PIIEntity{
				{FindingID: "JUDGE-PII-USER", Entity: "cli"},
				{FindingID: "JUDGE-PII-SSN", Entity: "123-45-6789"},
				{FindingID: "JUDGE-PII-IP", Entity: "127.0.0.1"},
			},
			wantKept: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kept, suppressed := FilterPIIEntities(tc.entities, supps)
			if len(kept) != tc.wantKept {
				t.Errorf("kept count = %d, want %d", len(kept), tc.wantKept)
			}
			if tc.wantSuppID != "" && len(suppressed) > 0 {
				if suppressed[0].SuppressionID != tc.wantSuppID {
					t.Errorf("suppression ID = %q, want %q", suppressed[0].SuppressionID, tc.wantSuppID)
				}
			}
		})
	}
}

func TestFilterToolFindings(t *testing.T) {
	supps := []ToolSuppression{
		{
			ToolPattern:      `^(graph_auth_status|session_status)$`,
			SuppressFindings: []string{"JUDGE-PII-USER"},
			Reason:           "Status tool metadata",
		},
	}

	t.Run("matching tool suppressed", func(t *testing.T) {
		entities := []PIIEntity{
			{FindingID: "JUDGE-PII-USER", Entity: "admin"},
		}
		kept, suppressed := FilterToolFindings("graph_auth_status", entities, supps)
		if len(kept) != 0 {
			t.Errorf("kept = %d, want 0", len(kept))
		}
		if len(suppressed) != 1 {
			t.Errorf("suppressed = %d, want 1", len(suppressed))
		}
	})

	t.Run("non-matching tool kept", func(t *testing.T) {
		entities := []PIIEntity{
			{FindingID: "JUDGE-PII-USER", Entity: "admin"},
		}
		kept, _ := FilterToolFindings("users_list", entities, supps)
		if len(kept) != 1 {
			t.Errorf("kept = %d, want 1", len(kept))
		}
	})

	t.Run("non-matching finding kept", func(t *testing.T) {
		entities := []PIIEntity{
			{FindingID: "JUDGE-PII-EMAIL", Entity: "user@example.com"},
		}
		kept, _ := FilterToolFindings("graph_auth_status", entities, supps)
		if len(kept) != 1 {
			t.Errorf("kept = %d, want 1", len(kept))
		}
	})
}

func TestFilterPIIEntities_MorePrivateIPs(t *testing.T) {
	supps := []FindingSuppression{
		{
			ID:             "SUPP-IP-PRIVATE",
			FindingPattern: "JUDGE-PII-IP",
			EntityPattern:  `^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)`,
			Reason:         "Private IP",
		},
	}

	tests := []struct {
		ip       string
		wantKept int
	}{
		{"192.168.1.1", 0},
		{"192.168.0.100", 0},
		{"172.16.0.1", 0},
		{"172.31.255.254", 0},
		{"172.15.0.1", 1},
		{"172.32.0.1", 1},
		{"10.255.255.255", 0},
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			entities := []PIIEntity{{FindingID: "JUDGE-PII-IP", Entity: tc.ip}}
			kept, _ := FilterPIIEntities(entities, supps)
			if len(kept) != tc.wantKept {
				t.Errorf("IP %s: kept=%d, want %d", tc.ip, len(kept), tc.wantKept)
			}
		})
	}
}

func TestCompileRegexCache(t *testing.T) {
	re1 := compileRegex(`^test$`)
	if re1 == nil {
		t.Fatal("expected non-nil regex")
	}
	re2 := compileRegex(`^test$`)
	if re1 != re2 {
		t.Error("expected same pointer from cache")
	}

	bad := compileRegex(`[invalid`)
	if bad != nil {
		t.Error("expected nil for invalid regex")
	}
}

func TestPreJudgeStripContent_InvalidPattern(t *testing.T) {
	strips := []PreJudgeStrip{
		{ID: "BAD", Pattern: `[invalid`, AppliesTo: []string{"pii"}},
	}
	got := PreJudgeStripContent("hello world", strips, "pii")
	if got != "hello world" {
		t.Errorf("invalid pattern should not modify content, got %q", got)
	}
}

func TestCheckCondition_Unknown(t *testing.T) {
	if checkCondition("unknown_condition", "test") {
		t.Error("unknown condition should return false")
	}
}
