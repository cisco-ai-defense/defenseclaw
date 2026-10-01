package inspect

import (
	"strings"
)

type Severity int

const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "NONE"
	}
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Match       string   `json:"match,omitempty"`
}

type InspectResult struct {
	Findings []Finding `json:"findings"`
	Clean    bool      `json:"clean"`
}

func (r InspectResult) MaxSeverity() Severity {
	max := SeverityNone
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

type Inspector struct {
	secretDetectors    []detector
	piiDetectors       []detector
	injectionDetectors []detector
	exfilDetectors     []detector
	commandDetectors   []detector
}

func NewInspector() *Inspector {
	return &Inspector{
		secretDetectors:    buildSecretDetectors(),
		piiDetectors:       buildPIIDetectors(),
		injectionDetectors: buildInjectionDetectors(),
		exfilDetectors:     buildExfilDetectors(),
		commandDetectors:   buildCommandDetectors(),
	}
}

func (ins *Inspector) Inspect(content string) InspectResult {
	var findings []Finding
	lower := strings.ToLower(content)

	for _, d := range ins.secretDetectors {
		if matches := d.scan(content, lower); len(matches) > 0 {
			for _, m := range matches {
				findings = append(findings, m)
			}
		}
	}
	for _, d := range ins.piiDetectors {
		if matches := d.scan(content, lower); len(matches) > 0 {
			for _, m := range matches {
				findings = append(findings, m)
			}
		}
	}
	for _, d := range ins.injectionDetectors {
		if matches := d.scan(content, lower); len(matches) > 0 {
			for _, m := range matches {
				findings = append(findings, m)
			}
		}
	}
	for _, d := range ins.exfilDetectors {
		if matches := d.scan(content, lower); len(matches) > 0 {
			for _, m := range matches {
				findings = append(findings, m)
			}
		}
	}
	for _, d := range ins.commandDetectors {
		if matches := d.scan(content, lower); len(matches) > 0 {
			for _, m := range matches {
				findings = append(findings, m)
			}
		}
	}

	return InspectResult{
		Findings: findings,
		Clean:    len(findings) == 0,
	}
}
