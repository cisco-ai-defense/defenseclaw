package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// ClawShieldPIIScanner detects personally identifiable information across 10 categories.
// Ported from github.com/Jason-Cyr/OpenClawSecurity — all logic runs natively in-process.
type ClawShieldPIIScanner struct{}

func NewClawShieldPIIScanner() *ClawShieldPIIScanner { return &ClawShieldPIIScanner{} }

func (s *ClawShieldPIIScanner) Name() string              { return "clawshield-pii" }
func (s *ClawShieldPIIScanner) Version() string            { return "1.0.0" }
func (s *ClawShieldPIIScanner) SupportedTargets() []string { return []string{"skill", "code"} }

type csPIIRule struct {
	id         string
	category   string
	pattern    *regexp.Regexp
	severity   Severity
	validator  func(string) bool
	contextPat *regexp.Regexp
	remediation string
}

var csPIIRules = []csPIIRule{
	// Credit cards (Luhn-validated)
	{id: "CS-PII-CC-VISA", category: "credit_card", pattern: regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), severity: SeverityCritical, validator: csLuhnCheck, remediation: "Remove credit card numbers; use a payment tokenization service"},
	{id: "CS-PII-CC-MC", category: "credit_card", pattern: regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), severity: SeverityCritical, validator: csLuhnCheck, remediation: "Remove credit card numbers; use a payment tokenization service"},
	{id: "CS-PII-CC-AMEX", category: "credit_card", pattern: regexp.MustCompile(`\b3[47][0-9]{13}\b`), severity: SeverityCritical, validator: csLuhnCheck, remediation: "Remove credit card numbers; use a payment tokenization service"},
	{id: "CS-PII-CC-DISC", category: "credit_card", pattern: regexp.MustCompile(`\b(?:6011|65[0-9]{2}|64[4-9][0-9])[0-9]{12}\b`), severity: SeverityCritical, validator: csLuhnCheck, remediation: "Remove credit card numbers; use a payment tokenization service"},
	{id: "CS-PII-CC-FMT", category: "credit_card", pattern: regexp.MustCompile(`\b[0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}\b`), severity: SeverityCritical, remediation: "Remove credit card numbers; use a payment tokenization service"},

	// SSN
	{id: "CS-PII-SSN-DASH", category: "ssn", pattern: regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`), severity: SeverityCritical, remediation: "Remove SSNs; never store or transmit in plaintext"},
	{id: "CS-PII-SSN-SPACE", category: "ssn", pattern: regexp.MustCompile(`\b[0-9]{3}\s[0-9]{2}\s[0-9]{4}\b`), severity: SeverityCritical, remediation: "Remove SSNs; never store or transmit in plaintext"},

	// Email
	{id: "CS-PII-EMAIL", category: "email", pattern: regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`), severity: SeverityMedium, remediation: "Avoid hardcoding email addresses; use configuration or environment variables"},

	// Phone (US — requires separator to avoid false positives on timestamps)
	{id: "CS-PII-PHONE-1", category: "phone", pattern: regexp.MustCompile(`\b(?:\+1[\s.-]?)?\(?[0-9]{3}\)[\s.-]?[0-9]{3}[\s.-][0-9]{4}\b`), severity: SeverityMedium, remediation: "Remove phone numbers from code and logs"},
	{id: "CS-PII-PHONE-2", category: "phone", pattern: regexp.MustCompile(`\b(?:\+1[\s.-]?)?[0-9]{3}[\s.-][0-9]{3}[\s.-][0-9]{4}\b`), severity: SeverityMedium, remediation: "Remove phone numbers from code and logs"},

	// IPv4
	{id: "CS-PII-IP", category: "ip_address", pattern: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`), severity: SeverityLow, remediation: "Avoid hardcoding IP addresses; use configuration"},

	// Date of birth (context-gated)
	{id: "CS-PII-DOB-MDY", category: "dob", pattern: regexp.MustCompile(`\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/(?:19|20)[0-9]{2}\b`), severity: SeverityMedium, contextPat: regexp.MustCompile(`(?i)born|dob|birth|date\s+of\s+birth|birthday`), remediation: "Remove date of birth data from code"},
	{id: "CS-PII-DOB-ISO", category: "dob", pattern: regexp.MustCompile(`\b(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\b`), severity: SeverityMedium, contextPat: regexp.MustCompile(`(?i)born|dob|birth|date\s+of\s+birth|birthday`), remediation: "Remove date of birth data from code"},

	// Passport (context-gated)
	{id: "CS-PII-PASSPORT", category: "passport", pattern: regexp.MustCompile(`\b[A-Z][0-9]{8}\b`), severity: SeverityHigh, contextPat: regexp.MustCompile(`(?i)passport`), remediation: "Remove passport numbers from code"},

	// Driver's license (context-gated)
	{id: "CS-PII-DL-1", category: "drivers_license", pattern: regexp.MustCompile(`\b[A-Z][0-9]{7,8}\b`), severity: SeverityHigh, contextPat: regexp.MustCompile(`(?i)driver|license|licence|DL|DMV`), remediation: "Remove driver's license numbers from code"},
	{id: "CS-PII-DL-2", category: "drivers_license", pattern: regexp.MustCompile(`\b[A-Z]{2}[0-9]{6,8}\b`), severity: SeverityHigh, contextPat: regexp.MustCompile(`(?i)driver|license|licence|DL|DMV`), remediation: "Remove driver's license numbers from code"},

	// Bank account (context-gated)
	{id: "CS-PII-BANK", category: "bank_account", pattern: regexp.MustCompile(`\b[0-9]{8,17}\b`), severity: SeverityHigh, contextPat: regexp.MustCompile(`(?i)account|routing|iban|swift|bank|acct`), remediation: "Remove bank account numbers from code"},

	// Medical ID (context-gated)
	{id: "CS-PII-MED", category: "medical_id", pattern: regexp.MustCompile(`\b[A-Z]{2,3}[0-9]{6,10}\b`), severity: SeverityHigh, contextPat: regexp.MustCompile(`(?i)medical|patient|health|insurance|medicare|medicaid|npi|mrn`), remediation: "Remove medical IDs from code"},
}

func (s *ClawShieldPIIScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name(), Target: target, Timestamp: start}

	files, err := csCollectTextFiles(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: clawshield-pii: %w", err)
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, csPIIScanContent(content, f)...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func csPIIScanContent(content []byte, path string) []Finding {
	text := string(content)
	var findings []Finding

	for _, rule := range csPIIRules {
		if rule.contextPat != nil && !rule.contextPat.MatchString(text) {
			continue
		}

		matches := rule.pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			match := text[loc[0]:loc[1]]

			if rule.validator != nil && !rule.validator(match) {
				continue
			}

			findings = append(findings, Finding{
				ID:          rule.id,
				Severity:    rule.severity,
				Title:       fmt.Sprintf("PII detected: %s", rule.category),
				Description: fmt.Sprintf("Matched value: %s", csRedactPII(match)),
				Location:    csLocation(path, content, loc[0]),
				Remediation: rule.remediation,
				Scanner:     "clawshield-pii",
				Tags:        []string{"pii", rule.category, "clawshield"},
			})
		}
	}

	return findings
}

// csLuhnCheck implements the Luhn algorithm for credit card validation.
func csLuhnCheck(number string) bool {
	cleaned := strings.NewReplacer(" ", "", "-", "").Replace(number)
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(cleaned) - 1; i >= 0; i-- {
		digit := int(cleaned[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

// csRedactPII partially masks PII values for safe logging.
func csRedactPII(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
