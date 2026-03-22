package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"
)

// ClawShieldSecretsScanner detects leaked credentials and API keys across 13+ providers.
// Ported from github.com/Jason-Cyr/OpenClawSecurity — all logic runs natively in-process.
type ClawShieldSecretsScanner struct{}

func NewClawShieldSecretsScanner() *ClawShieldSecretsScanner { return &ClawShieldSecretsScanner{} }

func (s *ClawShieldSecretsScanner) Name() string              { return "clawshield-secrets" }
func (s *ClawShieldSecretsScanner) Version() string            { return "1.0.0" }
func (s *ClawShieldSecretsScanner) SupportedTargets() []string { return []string{"skill", "code"} }

type csSecretRule struct {
	id          string
	provider    string
	pattern     *regexp.Regexp
	severity    Severity
	remediation string
}

var csSecretRules = []csSecretRule{
	// AWS
	{id: "CS-SEC-AWS-KEY", provider: "aws", pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), severity: SeverityCritical, remediation: "Rotate the key and store in AWS Secrets Manager or environment variables"},
	{id: "CS-SEC-AWS-SECRET", provider: "aws", pattern: regexp.MustCompile(`(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['":\s=]*[A-Za-z0-9/+=]{40}`), severity: SeverityCritical, remediation: "Rotate the secret and use IAM roles or environment variables"},
	{id: "CS-SEC-AWS-SESSION", provider: "aws", pattern: regexp.MustCompile(`(?i)aws_session_token['":\s=]*[A-Za-z0-9/+=]{100,}`), severity: SeverityCritical, remediation: "Session tokens are short-lived; rotate immediately and audit access"},
	{id: "CS-SEC-AWS-ARN", provider: "aws", pattern: regexp.MustCompile(`\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/:.]+\b`), severity: SeverityMedium, remediation: "Avoid hardcoding ARNs; use configuration or IAM roles"},

	// GCP
	{id: "CS-SEC-GCP-KEY", provider: "gcp", pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), severity: SeverityHigh, remediation: "Revoke the key in GCP console and use Workload Identity"},
	{id: "CS-SEC-GCP-SA", provider: "gcp", pattern: regexp.MustCompile(`"type"\s*:\s*"service_account"`), severity: SeverityCritical, remediation: "Never commit service account JSON; use Workload Identity Federation"},
	{id: "CS-SEC-GCP-OAUTH", provider: "gcp", pattern: regexp.MustCompile(`(?i)client_secret['":\s=]*[A-Za-z0-9\-_]{24,}`), severity: SeverityHigh, remediation: "Rotate the OAuth client secret and store in Secret Manager"},

	// Azure
	{id: "CS-SEC-AZ-STORAGE", provider: "azure", pattern: regexp.MustCompile(`(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{44,}`), severity: SeverityCritical, remediation: "Rotate the storage key and use Managed Identity"},
	{id: "CS-SEC-AZ-CONN", provider: "azure", pattern: regexp.MustCompile(`(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:User ID|Password)\s*=\s*[^;]+`), severity: SeverityCritical, remediation: "Use Azure AD authentication instead of connection string passwords"},
	{id: "CS-SEC-AZ-SECRET", provider: "azure", pattern: regexp.MustCompile(`(?i)(?:azure|AZURE)[\w_]*(?:SECRET|KEY|PASSWORD)['":\s=]*[A-Za-z0-9\-_.~]{30,}`), severity: SeverityHigh, remediation: "Store in Azure Key Vault; use Managed Identity to access"},
	{id: "CS-SEC-AZ-SAS", provider: "azure", pattern: regexp.MustCompile(`\bsig=[A-Za-z0-9%+/=]{30,}&`), severity: SeverityHigh, remediation: "Use short-lived SAS tokens and regenerate immediately"},

	// GitHub
	{id: "CS-SEC-GH-PAT", provider: "github", pattern: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), severity: SeverityCritical, remediation: "Revoke the token at github.com/settings/tokens"},
	{id: "CS-SEC-GH-OAUTH", provider: "github", pattern: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`), severity: SeverityCritical, remediation: "Revoke the OAuth token via GitHub API"},
	{id: "CS-SEC-GH-FINE", provider: "github", pattern: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`), severity: SeverityCritical, remediation: "Revoke the fine-grained PAT at github.com/settings/tokens"},
	{id: "CS-SEC-GH-APP", provider: "github", pattern: regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`), severity: SeverityHigh, remediation: "Regenerate the GitHub App installation token"},
	{id: "CS-SEC-GH-REFRESH", provider: "github", pattern: regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`), severity: SeverityCritical, remediation: "Revoke the refresh token via GitHub API"},

	// GitLab
	{id: "CS-SEC-GL-PAT", provider: "gitlab", pattern: regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`), severity: SeverityCritical, remediation: "Revoke at gitlab.com/-/profile/personal_access_tokens"},
	{id: "CS-SEC-GL-PROJ", provider: "gitlab", pattern: regexp.MustCompile(`\bglptt-[A-Za-z0-9\-_]{20,}\b`), severity: SeverityHigh, remediation: "Revoke the project token in GitLab project settings"},
	{id: "CS-SEC-GL-OAUTH", provider: "gitlab", pattern: regexp.MustCompile(`\bglsoat-[A-Za-z0-9\-_]{20,}\b`), severity: SeverityCritical, remediation: "Revoke the OAuth token via GitLab API"},

	// Slack
	{id: "CS-SEC-SLACK-BOT", provider: "slack", pattern: regexp.MustCompile(`\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b`), severity: SeverityCritical, remediation: "Revoke the bot token in Slack app settings"},
	{id: "CS-SEC-SLACK-USER", provider: "slack", pattern: regexp.MustCompile(`\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b`), severity: SeverityCritical, remediation: "Revoke the user token in Slack app settings"},
	{id: "CS-SEC-SLACK-WH", provider: "slack", pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), severity: SeverityHigh, remediation: "Regenerate the webhook URL in Slack app settings"},

	// Stripe
	{id: "CS-SEC-STRIPE-LIVE", provider: "stripe", pattern: regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`), severity: SeverityCritical, remediation: "Roll the key in Stripe dashboard immediately"},
	{id: "CS-SEC-STRIPE-TEST", provider: "stripe", pattern: regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`), severity: SeverityMedium, remediation: "Test keys have limited risk but should still be kept out of source"},
	{id: "CS-SEC-STRIPE-PUB", provider: "stripe", pattern: regexp.MustCompile(`\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b`), severity: SeverityLow, remediation: "Publishable keys are public-facing but confirm intended exposure"},
	{id: "CS-SEC-STRIPE-RESTR", provider: "stripe", pattern: regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`), severity: SeverityHigh, remediation: "Roll the restricted key in Stripe dashboard"},

	// Twilio
	{id: "CS-SEC-TWILIO-SID", provider: "twilio", pattern: regexp.MustCompile(`\bAC[0-9a-f]{32}\b`), severity: SeverityHigh, remediation: "Rotate credentials in Twilio console"},
	{id: "CS-SEC-TWILIO-AUTH", provider: "twilio", pattern: regexp.MustCompile(`(?i)twilio[\w_]*(?:auth|token)['":\s=]*[0-9a-f]{32}`), severity: SeverityCritical, remediation: "Rotate the auth token in Twilio console"},
	{id: "CS-SEC-TWILIO-KEY", provider: "twilio", pattern: regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), severity: SeverityHigh, remediation: "Revoke the API key in Twilio console"},

	// SendGrid
	{id: "CS-SEC-SENDGRID", provider: "sendgrid", pattern: regexp.MustCompile(`\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b`), severity: SeverityCritical, remediation: "Revoke the API key in SendGrid settings"},

	// Mailgun
	{id: "CS-SEC-MAILGUN", provider: "mailgun", pattern: regexp.MustCompile(`\bkey-[A-Za-z0-9]{32}\b`), severity: SeverityCritical, remediation: "Revoke the API key in Mailgun settings"},

	// NPM / PyPI
	{id: "CS-SEC-NPM", provider: "npm", pattern: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), severity: SeverityCritical, remediation: "Revoke the token at npmjs.com/settings/tokens"},
	{id: "CS-SEC-PYPI", provider: "pypi", pattern: regexp.MustCompile(`\bpypi-[A-Za-z0-9\-_]{50,}\b`), severity: SeverityCritical, remediation: "Revoke the token at pypi.org/manage/account/token/"},

	// Generic
	{id: "CS-SEC-KEY-RSA", provider: "generic", pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), severity: SeverityCritical, remediation: "Remove the private key; use a certificate store or secrets manager"},
	{id: "CS-SEC-KEY-EC", provider: "generic", pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), severity: SeverityCritical, remediation: "Remove the private key; use a certificate store or secrets manager"},
	{id: "CS-SEC-KEY-DSA", provider: "generic", pattern: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), severity: SeverityCritical, remediation: "Remove the private key; use a certificate store or secrets manager"},
	{id: "CS-SEC-KEY-GENERIC", provider: "generic", pattern: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), severity: SeverityCritical, remediation: "Remove the private key; use a certificate store or secrets manager"},
	{id: "CS-SEC-JWT", provider: "generic", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b`), severity: SeverityHigh, remediation: "Do not hardcode JWT tokens; they expire but may encode sensitive claims"},
	{id: "CS-SEC-BASIC-AUTH", provider: "generic", pattern: regexp.MustCompile(`(?i)(?:authorization|auth)\s*[:=]\s*basic\s+[A-Za-z0-9+/=]{10,}`), severity: SeverityHigh, remediation: "Never hardcode Basic auth credentials; use environment variables"},
	{id: "CS-SEC-BEARER", provider: "generic", pattern: regexp.MustCompile(`(?i)(?:authorization|auth)\s*[:=]\s*bearer\s+[A-Za-z0-9\-_.+/=]{20,}`), severity: SeverityHigh, remediation: "Do not hardcode bearer tokens; load from environment at runtime"},
	{id: "CS-SEC-PASSWORD", provider: "generic", pattern: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*[^\s;,'"]{8,}`), severity: SeverityHigh, remediation: "Move passwords to environment variables or a secrets manager"},
}

func (s *ClawShieldSecretsScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name(), Target: target, Timestamp: start}

	files, err := csCollectTextFiles(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: clawshield-secrets: %w", err)
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, csSecretsScanContent(content, f)...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func csSecretsScanContent(content []byte, path string) []Finding {
	text := string(content)
	var findings []Finding

	for _, rule := range csSecretRules {
		matches := rule.pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			match := text[loc[0]:loc[1]]
			findings = append(findings, Finding{
				ID:          rule.id,
				Severity:    rule.severity,
				Title:       fmt.Sprintf("Secret detected: %s (%s)", rule.id, rule.provider),
				Description: fmt.Sprintf("Matched value: %s", csTruncateSecret(match)),
				Location:    csLocation(path, content, loc[0]),
				Remediation: rule.remediation,
				Scanner:     "clawshield-secrets",
				Tags:        []string{"secret", rule.provider, "clawshield"},
			})
		}
	}

	return findings
}

// csTruncateSecret shows first 8 + "..." + last 4 chars for audit logging.
func csTruncateSecret(s string) string {
	if len(s) <= 16 {
		return s[:4] + "..." + s[len(s)-2:]
	}
	return s[:8] + "..." + s[len(s)-4:]
}
