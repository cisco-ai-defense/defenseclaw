package inspect

import (
	"regexp"
	"strings"
)

type detector struct {
	scan func(raw, lower string) []Finding
}

func regexDetector(ruleID, category, desc string, sev Severity, patterns ...*regexp.Regexp) detector {
	return detector{
		scan: func(raw, _ string) []Finding {
			var out []Finding
			for _, p := range patterns {
				if loc := p.FindString(raw); loc != "" {
					out = append(out, Finding{
						RuleID:      ruleID,
						Category:    category,
						Severity:    sev,
						Description: desc,
						Match:       truncate(loc, 80),
					})
				}
			}
			return out
		},
	}
}

func keywordDetector(ruleID, category, desc string, sev Severity, keywords []string) detector {
	return detector{
		scan: func(_, lower string) []Finding {
			for _, kw := range keywords {
				if strings.Contains(lower, kw) {
					return []Finding{{
						RuleID:      ruleID,
						Category:    category,
						Severity:    sev,
						Description: desc,
						Match:       kw,
					}}
				}
			}
			return nil
		},
	}
}

func buildSecretDetectors() []detector {
	return []detector{
		regexDetector("SEC-AWS-KEY", "secret", "AWS access key", SeverityCritical,
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`)),
		regexDetector("SEC-AWS-SECRET", "secret", "AWS secret key pattern", SeverityCritical,
			regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*\S{20,}`)),
		regexDetector("SEC-GITHUB-TOKEN", "secret", "GitHub token", SeverityHigh,
			regexp.MustCompile(`gh[pous]_[A-Za-z0-9_]{36,}`)),
		regexDetector("SEC-OPENAI-KEY", "secret", "OpenAI API key", SeverityHigh,
			regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)),
		regexDetector("SEC-ANTHROPIC-KEY", "secret", "Anthropic API key", SeverityHigh,
			regexp.MustCompile(`sk-ant-[A-Za-z0-9\-]{20,}`)),
		regexDetector("SEC-PRIVATE-KEY", "secret", "Private key block", SeverityCritical,
			regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)),
		regexDetector("SEC-GENERIC-TOKEN", "secret", "Generic secret assignment", SeverityMedium,
			regexp.MustCompile(`(?i)(api[_\-]?key|secret|token|password|passwd|credentials?)\s*[=:]\s*["']?\S{16,}`)),
		regexDetector("SEC-JWT", "secret", "JSON Web Token", SeverityMedium,
			regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`)),
		regexDetector("SEC-CONNECTION-STRING", "secret", "Connection string with credentials", SeverityHigh,
			regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s@]+:[^\s@]+@[^\s]+`)),
	}
}

func buildPIIDetectors() []detector {
	return []detector{
		regexDetector("PII-SSN", "pii", "US Social Security Number", SeverityHigh,
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)),
		regexDetector("PII-CREDIT-CARD", "pii", "Credit card number (Luhn-like)", SeverityHigh,
			regexp.MustCompile(`\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`)),
		regexDetector("PII-PHONE", "pii", "Phone number pattern", SeverityMedium,
			regexp.MustCompile(`\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)),
		regexDetector("PII-EMAIL-BULK", "pii", "Multiple email addresses in content", SeverityMedium,
			regexp.MustCompile(`(?i)(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b.*){3,}`)),
	}
}

func buildInjectionDetectors() []detector {
	return []detector{
		keywordDetector("INJ-IGNORE", "injection", "Prompt injection: ignore instructions", SeverityHigh,
			[]string{"ignore previous instructions", "ignore all previous", "ignore above instructions", "disregard previous instructions", "disregard all previous"}),
		keywordDetector("INJ-ROLE-OVERRIDE", "injection", "Prompt injection: role override", SeverityCritical,
			[]string{"you are now", "act as root", "new system prompt", "override system prompt", "forget your instructions", "you are no longer"}),
		keywordDetector("INJ-JAILBREAK", "injection", "Jailbreak attempt", SeverityCritical,
			[]string{"do anything now", "dan mode", "jailbreak", "developer mode enabled", "pretend you have no restrictions"}),
		regexDetector("INJ-DELIMITER", "injection", "Delimiter injection (markdown/XML fence)", SeverityMedium,
			regexp.MustCompile("(?i)(```system|<\\|im_start\\|>system|<system>|\\[INST\\]|<\\|system\\|>)")),
	}
}

func buildExfilDetectors() []detector {
	return []detector{
		keywordDetector("EXFIL-PASSWD", "exfiltration", "Reading password/shadow files", SeverityCritical,
			[]string{"/etc/passwd", "/etc/shadow", "/etc/master.passwd"}),
		keywordDetector("EXFIL-SSH-KEY", "exfiltration", "Reading SSH private keys", SeverityCritical,
			[]string{".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa"}),
		keywordDetector("EXFIL-ENV", "exfiltration", "Environment variable dumping", SeverityHigh,
			[]string{"printenv", "export | grep", "env | grep", "/proc/self/environ"}),
		keywordDetector("EXFIL-WEBHOOK", "exfiltration", "Exfiltration via webhook", SeverityHigh,
			[]string{"webhook.site", "requestbin.com", "hookbin.com", "ngrok.io", "burpcollaborator"}),
		keywordDetector("EXFIL-CLOUD-META", "exfiltration", "Cloud metadata service access", SeverityCritical,
			[]string{"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}),
	}
}

func buildCommandDetectors() []detector {
	return []detector{
		keywordDetector("CMD-DESTRUCTIVE", "command", "Destructive command", SeverityCritical,
			[]string{"rm -rf /", "rm -rf /*", "mkfs.", ":(){:|:&};:", "dd if=/dev/zero", "chmod -R 777 /"}),
		keywordDetector("CMD-REVERSE-SHELL", "command", "Reverse shell attempt", SeverityCritical,
			[]string{"bash -i >& /dev/tcp/", "nc -e /bin/sh", "python -c 'import socket,subprocess", "/bin/sh -i", "mkfifo /tmp/f"}),
		keywordDetector("CMD-CRED-DUMP", "command", "Credential dumping tool", SeverityHigh,
			[]string{"mimikatz", "secretsdump", "hashdump", "lsass", "sam dump"}),
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
