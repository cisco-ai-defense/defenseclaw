package modelcatalog

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hwprofile"
	"github.com/defenseclaw/defenseclaw/internal/usecases"
)

// useCaseKeywords maps use case names to keyword lists for routing signals.
var useCaseKeywords = map[string][]string{
	"coding":              {"code", "function", "debug", "refactor", "implement", "test", "script", "parse", "compile", "lint", "api", "endpoint"},
	"general_reasoning":   {"explain", "analyze", "compare", "summarize", "reason", "think", "evaluate", "assess"},
	"security":            {"vulnerability", "security", "exploit", "cve", "patch", "hardening", "audit", "compliance"},
	"data_analysis":       {"data", "query", "sql", "statistics", "chart", "visualization", "dataset", "aggregate"},
	"devops_sre":          {"deploy", "kubernetes", "docker", "terraform", "ci/cd", "pipeline", "monitoring", "incident"},
	"research_writing":    {"write", "document", "paper", "article", "blog", "report", "presentation", "outline"},
	"agentic_automation":  {"automate", "workflow", "agent", "pipeline", "orchestrate", "task", "batch", "schedule"},
	"multimodal":          {"image", "screenshot", "diagram", "photo", "picture", "visual", "scan"},
}

// GenerateRoutingConfig creates a routing config from the profiler's output.
func GenerateRoutingConfig(
	profile *hwprofile.SystemProfile,
	ucs []usecases.InferredUseCase,
	recs []ModelRecommendation,
) config.RoutingConfig {
	rc := config.RoutingConfig{
		Enabled: true,
	}

	// Build models[] from recommendations (local models that fit)
	seen := map[string]bool{}
	for _, rec := range recs {
		if rec.Tier != "local" || !rec.FitsHardware || rec.OllamaTag == "" {
			continue
		}
		alias := sanitizeAlias(rec.OllamaTag)
		if seen[alias] {
			continue
		}
		seen[alias] = true
		rc.Models = append(rc.Models, config.RoutingModelBackend{
			Name:     alias,
			Provider: "ollama",
			Model:    rec.OllamaTag,
			BaseURL:  "http://127.0.0.1:11434/v1",
			Auth:     "none",
			Capabilities: inferCapabilities(rec.UseCase),
		})
	}

	// Build signals{} from use case taxonomy
	for _, uc := range ucs {
		if uc.Confidence < 0.3 {
			continue
		}
		kws, ok := useCaseKeywords[uc.Name]
		if !ok || len(kws) == 0 {
			continue
		}
		rc.Signals.Keywords = append(rc.Signals.Keywords, config.RoutingKeywordSignal{
			Name:     uc.Name + "_signal",
			Keywords: kws,
			Operator: "OR",
		})
	}

	// Build decisions[] mapping signals → model_refs
	for _, uc := range ucs {
		if uc.Confidence < 0.3 {
			continue
		}
		localRef := bestLocalRef(recs, uc.Name)
		if localRef == "" {
			continue
		}
		priority := 100
		if uc.Frequency == "primary" {
			priority = 90
		}
		rc.Decisions = append(rc.Decisions, config.RoutingDecisionRule{
			Name:     "route_" + uc.Name,
			Priority: priority,
			Conditions: []config.RoutingCondition{{
				Type:          "keyword",
				Name:          uc.Name + "_signal",
				MinConfidence: 0.7,
			}},
			Operator:  "AND",
			ModelRefs: []string{localRef},
		})
	}

	return rc
}

func sanitizeAlias(tag string) string {
	r := strings.NewReplacer(":", "-", "/", "-", ".", "-")
	return r.Replace(strings.ToLower(tag))
}

func inferCapabilities(useCase string) []string {
	switch useCase {
	case "coding":
		return []string{"coding", "implementation"}
	case "general_reasoning":
		return []string{"reasoning", "analysis"}
	case "security":
		return []string{"security", "classification"}
	case "data_analysis":
		return []string{"data", "analysis"}
	default:
		return []string{useCase}
	}
}

func bestLocalRef(recs []ModelRecommendation, useCase string) string {
	for _, r := range recs {
		if r.Tier == "local" && r.UseCase == useCase && r.OllamaTag != "" {
			return sanitizeAlias(r.OllamaTag)
		}
	}
	return ""
}
