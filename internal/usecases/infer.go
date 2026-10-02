package usecases

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// signalUseCaseWeights maps AI Discovery signal categories to use case contributions.
var signalUseCaseWeights = map[string]map[string]float64{
	inventory.SignalSupportedConnector: {
		"coding":              0.3,
		"devops_sre":          0.2,
		"agentic_automation":  0.2,
	},
	inventory.SignalMCPServer: {
		"coding":              0.1,
		"data_analysis":       0.1,
		"devops_sre":          0.1,
		"research_writing":    0.1,
	},
	inventory.SignalLocalModel: {
		"security":            0.2,
		"coding":              0.2,
		"general_reasoning":   0.1,
	},
	inventory.SignalPackageDependency: {
		"coding":              0.1,
		"agentic_automation":  0.2,
		"data_analysis":       0.1,
	},
	inventory.SignalEnvVarName: {
		"coding":              0.1,
		"general_reasoning":   0.1,
	},
	inventory.SignalShellHistoryMatch: {
		"coding":              0.1,
		"devops_sre":          0.1,
	},
	inventory.SignalWorkspaceArtifact: {
		"coding":              0.2,
		"security":            0.1,
	},
	inventory.SignalDesktopApp: {
		"coding":              0.1,
		"general_reasoning":   0.1,
	},
	inventory.SignalLocalAIEndpoint: {
		"coding":              0.1,
		"general_reasoning":   0.1,
	},
	inventory.SignalActiveProcess: {
		"coding":              0.05,
	},
	inventory.SignalEditorExtension: {
		"coding":              0.15,
	},
}

// InferUseCases analyzes AI Discovery signals and returns scored use cases.
func InferUseCases(signals []inventory.AISignal) []InferredUseCase {
	scores := map[string]*InferredUseCase{}

	for _, sig := range signals {
		weights, ok := signalUseCaseWeights[sig.Category]
		if !ok {
			continue
		}
		refined := refineByContent(sig, weights)
		for ucName, weight := range refined {
			uc, exists := scores[ucName]
			if !exists {
				uc = &InferredUseCase{Name: ucName}
				scores[ucName] = uc
			}
			contribution := weight * sig.Confidence
			uc.Confidence += contribution
			uc.Evidence = append(uc.Evidence,
				fmt.Sprintf("%s:%s (%.2f)", sig.Category, sig.Name, contribution))
		}
	}

	var result []InferredUseCase
	for _, uc := range scores {
		uc.Confidence = math.Min(1.0, uc.Confidence)
		switch {
		case uc.Confidence > 0.6:
			uc.Frequency = "primary"
		case uc.Confidence > 0.3:
			uc.Frequency = "secondary"
		default:
			uc.Frequency = "occasional"
		}
		if uc.Confidence > 0.1 {
			result = append(result, *uc)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Confidence > result[j].Confidence
	})
	return result
}

// refineByContent inspects signal Name/Product/Component to sharpen use-case scoring.
func refineByContent(sig inventory.AISignal, base map[string]float64) map[string]float64 {
	refined := make(map[string]float64, len(base))
	for k, v := range base {
		refined[k] = v
	}
	name := strings.ToLower(sig.Name)

	switch sig.Category {
	case inventory.SignalSupportedConnector:
		switch {
		case strings.Contains(name, "claude") || strings.Contains(name, "cursor") ||
			strings.Contains(name, "copilot") || strings.Contains(name, "codex"):
			refined["coding"] += 0.2
		case strings.Contains(name, "devin") || strings.Contains(name, "openhands"):
			refined["agentic_automation"] += 0.2
		case strings.Contains(name, "hermes"):
			refined["devops_sre"] += 0.1
		}

	case inventory.SignalMCPServer:
		switch {
		case strings.Contains(name, "github") || strings.Contains(name, "gitlab"):
			refined["coding"] += 0.2
		case strings.Contains(name, "jira") || strings.Contains(name, "atlassian"):
			refined["devops_sre"] += 0.1
		case strings.Contains(name, "postgres") || strings.Contains(name, "bigquery"):
			refined["data_analysis"] += 0.2
		case strings.Contains(name, "confluence") || strings.Contains(name, "notion"):
			refined["research_writing"] += 0.1
		case strings.Contains(name, "datadog") || strings.Contains(name, "grafana"):
			refined["devops_sre"] += 0.2
		}

	case inventory.SignalLocalModel:
		if sig.Model != nil {
			id := strings.ToLower(sig.Model.ID)
			switch {
			case strings.Contains(id, "coder") || strings.Contains(id, "codestral"):
				refined["coding"] += 0.3
			case strings.Contains(id, "guard") || strings.Contains(id, "secjudge"):
				refined["security"] += 0.3
			case strings.Contains(id, "llava") || strings.Contains(id, "pixtral"):
				refined["multimodal"] += 0.3
			case strings.Contains(id, "qwen"):
				refined["coding"] += 0.1
				refined["general_reasoning"] += 0.1
			}
		}

	case inventory.SignalPackageDependency:
		if sig.Component != nil {
			switch strings.ToLower(sig.Component.Name) {
			case "langchain", "crewai", "autogen-agentchat":
				refined["agentic_automation"] += 0.3
			case "pandas", "numpy", "scikit-learn":
				refined["data_analysis"] += 0.2
			case "openai", "anthropic":
				refined["coding"] += 0.1
			}
		}

	case inventory.SignalEnvVarName:
		switch {
		case strings.Contains(name, "openai") || strings.Contains(name, "anthropic"):
			refined["coding"] += 0.1
		case strings.Contains(name, "aws") || strings.Contains(name, "bedrock"):
			refined["general_reasoning"] += 0.1
		}
	}

	return refined
}
