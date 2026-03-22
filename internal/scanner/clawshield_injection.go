package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ClawShieldInjectionScanner detects prompt injection attacks using a 3-tier approach.
// Ported from github.com/Jason-Cyr/OpenClawSecurity — all logic runs natively in-process.
type ClawShieldInjectionScanner struct{}

func NewClawShieldInjectionScanner() *ClawShieldInjectionScanner {
	return &ClawShieldInjectionScanner{}
}

func (s *ClawShieldInjectionScanner) Name() string              { return "clawshield-injection" }
func (s *ClawShieldInjectionScanner) Version() string            { return "1.0.0" }
func (s *ClawShieldInjectionScanner) SupportedTargets() []string { return []string{"skill", "code"} }

// Tier 1 — compiled regex patterns.
var (
	csRoleOverridePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)`),
		regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)`),
		regexp.MustCompile(`(?im)^system\s*:\s*(?:you\s+are|ignore|forget|override|disregard|from\s+now\s+on)`),
		regexp.MustCompile(`(?i)forget\s+(all\s+)?(your\s+)?(instructions|rules|training|guidelines)`),
		regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
		regexp.MustCompile(`(?i)override\s*:`),
		regexp.MustCompile(`(?i)disregard\s+(all\s+)?(above|previous|prior)`),
	}

	csInstructionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)do\s+not\s+follow\s+(the\s+)?(previous|above|prior)`),
		regexp.MustCompile(`(?i)instead\s+(you\s+should|please|do|just)\s+`),
		regexp.MustCompile(`(?i)^actually\s*,`),
		regexp.MustCompile(`(?i)^correction\s*:`),
		regexp.MustCompile(`(?i)update\s+your\s+(behavior|instructions|rules)`),
	}

	csDelimiterPatterns = []*regexp.Regexp{
		regexp.MustCompile("(?i)```system"),
		regexp.MustCompile(`(?i)---\s*\n\s*system\s*:`),
		regexp.MustCompile(`<<SYS>>`),
		regexp.MustCompile(`\[INST\]`),
		regexp.MustCompile(`</s>`),
		regexp.MustCompile(`<\|im_start\|>`),
		regexp.MustCompile(`<\|endoftext\|>`),
	}
)

// Tier 2 — imperative verbs for density analysis.
var csImperativeVerbs = map[string]bool{
	"do": true, "execute": true, "run": true, "ignore": true,
	"forget": true, "override": true, "bypass": true, "disable": true,
	"enable": true, "output": true, "print": true, "write": true,
	"send": true, "delete": true, "create": true, "modify": true,
	"reveal": true, "show": true, "display": true, "list": true,
	"dump": true, "export": true, "extract": true, "repeat": true,
}

// Tier 3 — zero-width Unicode characters.
var csZeroWidthChars = []rune{
	'\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060',
	'\u200E', '\u200F', '\u202A', '\u202C',
}

func (s *ClawShieldInjectionScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name(), Target: target, Timestamp: start}

	files, err := csCollectTextFiles(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: clawshield-injection: %w", err)
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, csInjectionScanContent(content, f)...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func csInjectionScanContent(content []byte, path string) []Finding {
	text := string(content)
	normalized := norm.NFKC.String(text)

	var findings []Finding

	// Tier 1: pattern match on raw + normalized text.
	findings = append(findings, csInjTier1(text, content, path, "")...)
	if normalized != text {
		suffix := " (detected after NFKC normalization)"
		findings = append(findings, csInjTier1(normalized, content, path, suffix)...)
	}

	// Tier 2: statistical analysis.
	findings = append(findings, csInjTier2(text, content, path)...)

	// Tier 3: Unicode analysis.
	findings = append(findings, csInjTier3(text, content, path)...)

	return findings
}

func csInjTier1(text string, raw []byte, path, suffix string) []Finding {
	var findings []Finding

	for _, p := range csRoleOverridePatterns {
		if loc := p.FindStringIndex(text); loc != nil {
			findings = append(findings, Finding{
				ID:          "CS-INJ-role_override",
				Severity:    SeverityCritical,
				Title:       "Prompt injection: role override attempt" + suffix,
				Description: "Pattern matched: " + csTruncateMatch(text[loc[0]:loc[1]]),
				Location:    csLocation(path, raw, loc[0]),
				Remediation: "Validate and sanitize all user-supplied content before passing to the agent",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "role_override", "clawshield"},
			})
		}
	}

	for _, p := range csInstructionPatterns {
		if loc := p.FindStringIndex(text); loc != nil {
			findings = append(findings, Finding{
				ID:          "CS-INJ-instruction_injection",
				Severity:    SeverityHigh,
				Title:       "Prompt injection: instruction override attempt" + suffix,
				Description: "Pattern matched: " + csTruncateMatch(text[loc[0]:loc[1]]),
				Location:    csLocation(path, raw, loc[0]),
				Remediation: "Validate and sanitize all user-supplied content before passing to the agent",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "instruction_injection", "clawshield"},
			})
		}
	}

	for _, p := range csDelimiterPatterns {
		if loc := p.FindStringIndex(text); loc != nil {
			findings = append(findings, Finding{
				ID:          "CS-INJ-delimiter_injection",
				Severity:    SeverityCritical,
				Title:       "Prompt injection: delimiter/framing injection" + suffix,
				Description: "Pattern matched: " + csTruncateMatch(text[loc[0]:loc[1]]),
				Location:    csLocation(path, raw, loc[0]),
				Remediation: "Reject or escape model-specific delimiter tokens in user input",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "delimiter_injection", "clawshield"},
			})
		}
	}

	return findings
}

func csInjTier2(text string, raw []byte, path string) []Finding {
	var findings []Finding

	// Base64 decode + recursive tier-1 scan.
	b64Pat := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	for _, match := range b64Pat.FindAllString(text, 10) {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(match)
		}
		if err != nil || !utf8.Valid(decoded) {
			continue
		}
		decodedText := string(decoded)
		for _, p := range csRoleOverridePatterns {
			if p.MatchString(decodedText) {
				findings = append(findings, Finding{
					ID:          "CS-INJ-base64_injection",
					Severity:    SeverityCritical,
					Title:       "Prompt injection: base64-encoded injection detected",
					Description: "A role override pattern was found inside a base64-encoded blob",
					Location:    path,
					Remediation: "Decode and inspect base64 content before passing to the agent",
					Scanner:     "clawshield-injection",
					Tags:        []string{"injection", "base64", "clawshield"},
				})
				break
			}
		}
	}

	// Imperative verb density.
	words := strings.Fields(strings.ToLower(text))
	if len(words) > 5 {
		count := 0
		for _, w := range words {
			if csImperativeVerbs[strings.Trim(w, ".,!?:;\"'()")] {
				count++
			}
		}
		density := float64(count) / float64(len(words))
		if density > 0.4 {
			findings = append(findings, Finding{
				ID:          "CS-INJ-imperative_density",
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("Suspicious imperative verb density: %.1f%%", density*100),
				Description: "High density of imperative command verbs may indicate injection payload",
				Location:    path,
				Remediation: "Review content for embedded instructions",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "statistical", "clawshield"},
			})
		}
	}

	// Shannon entropy.
	if len(text) > 50 {
		entropy := csTextEntropy(text)
		if entropy > 5.5 {
			findings = append(findings, Finding{
				ID:          "CS-INJ-high_entropy",
				Severity:    SeverityLow,
				Title:       fmt.Sprintf("High text entropy: %.2f (threshold: 5.5)", entropy),
				Description: "High Shannon entropy may indicate obfuscated or encoded content",
				Location:    path,
				Remediation: "Inspect for encoded payloads",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "entropy", "clawshield"},
			})
		}
	}

	_ = raw
	return findings
}

func csInjTier3(text string, raw []byte, path string) []Finding {
	var findings []Finding

	// Zero-width character detection.
	for _, r := range text {
		for _, zw := range csZeroWidthChars {
			if r == zw {
				findings = append(findings, Finding{
					ID:          "CS-INJ-zero_width_chars",
					Severity:    SeverityHigh,
					Title:       fmt.Sprintf("Zero-width Unicode character detected (U+%04X)", r),
					Description: "Invisible Unicode characters can be used to hide injected instructions",
					Location:    path,
					Remediation: "Strip zero-width characters from user-supplied input",
					Scanner:     "clawshield-injection",
					Tags:        []string{"injection", "unicode", "clawshield"},
				})
				goto doneZeroWidth
			}
		}
	}
doneZeroWidth:

	// Unicode tag character detection (U+E0000–U+E007F).
	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			findings = append(findings, Finding{
				ID:          "CS-INJ-unicode_tags",
				Severity:    SeverityCritical,
				Title:       fmt.Sprintf("Unicode tag character detected (U+%05X)", r),
				Description: "Unicode tag block characters are invisible and can encode hidden instructions",
				Location:    path,
				Remediation: "Reject any content containing Unicode tag block characters (U+E0000–U+E007F)",
				Scanner:     "clawshield-injection",
				Tags:        []string{"injection", "unicode", "clawshield"},
			})
			break
		}
	}

	// Homoglyph / mixed-script detection.
	var hasLatin, hasCyrillic, hasGreek bool
	for _, r := range text {
		if r >= 'A' && r <= 'z' {
			hasLatin = true
		}
		if r >= 0x0400 && r <= 0x04FF {
			hasCyrillic = true
		}
		if r >= 0x0370 && r <= 0x03FF {
			hasGreek = true
		}
	}
	if hasLatin && (hasCyrillic || hasGreek) {
		findings = append(findings, Finding{
			ID:          "CS-INJ-homoglyph",
			Severity:    SeverityHigh,
			Title:       "Mixed Unicode scripts detected (possible homoglyph attack)",
			Description: "Latin characters mixed with Cyrillic or Greek may be a homoglyph substitution attack",
			Location:    path,
			Remediation: "Normalize text to a single script before processing",
			Scanner:     "clawshield-injection",
			Tags:        []string{"injection", "homoglyph", "unicode", "clawshield"},
		})
	}

	_ = raw
	return findings
}

func csTextEntropy(s string) float64 {
	freq := make(map[rune]float64)
	total := 0.0
	for _, r := range s {
		freq[r]++
		total++
	}
	entropy := 0.0
	for _, count := range freq {
		p := count / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
