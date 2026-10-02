package modelcatalog

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hwprofile"
	"github.com/defenseclaw/defenseclaw/internal/usecases"
)

// ModelRecommendation is a ranked model suggestion.
type ModelRecommendation struct {
	ModelName    string  `json:"model_name"`
	Tier         string  `json:"tier"` // "local", "cloud-budget", "cloud-optimal"
	UseCase      string  `json:"use_case"`
	FitsHardware bool    `json:"fits_hardware"`
	Quantization string  `json:"quantization,omitempty"`
	MemoryGB     float64 `json:"memory_gb,omitempty"`
	CostPerMTok  float64 `json:"cost_per_mtok,omitempty"`
	AlreadyHave  bool    `json:"already_have"`
	OllamaTag    string  `json:"ollama_tag,omitempty"`
	Reasoning    string  `json:"reasoning"`
}

// Recommend returns ranked model recommendations based on hardware, use cases, and installed models.
func Recommend(
	profile *hwprofile.SystemProfile,
	ucs []usecases.InferredUseCase,
	installedModels []string,
) []ModelRecommendation {
	var recs []ModelRecommendation

	for _, uc := range ucs {
		if uc.Confidence < 0.2 {
			continue
		}
		// Local models
		for _, m := range LocalCatalog {
			if !contains(m.UseCases, uc.Name) {
				continue
			}
			if m.FitsHardware(profile, "INT4") {
				recs = append(recs, ModelRecommendation{
					ModelName:    m.Name,
					Tier:         "local",
					UseCase:      uc.Name,
					FitsHardware: true,
					Quantization: "INT4",
					MemoryGB:     m.INT4GB,
					AlreadyHave:  matchesInstalled(m.OllamaTag, installedModels),
					OllamaTag:    m.OllamaTag,
					Reasoning:    m.Quality,
				})
			}
		}
		// Cloud models
		for _, m := range CloudCatalog {
			if !contains(m.UseCases, uc.Name) {
				continue
			}
			recs = append(recs, ModelRecommendation{
				ModelName:    m.Name,
				Tier:         "cloud-" + m.Tier,
				UseCase:      uc.Name,
				FitsHardware: true,
				CostPerMTok:  m.InputCost,
				Reasoning:    m.Provider + " — $" + formatCost(m.InputCost) + "/MTok",
			})
		}
	}

	// Always recommend security models
	for _, m := range LocalCatalog {
		if contains(m.UseCases, "security") && m.FitsHardware(profile, "FP16") {
			recs = append(recs, ModelRecommendation{
				ModelName:    m.Name,
				Tier:         "local",
				UseCase:      "security (always-on)",
				FitsHardware: true,
				Quantization: "FP16",
				MemoryGB:     m.FP16GB,
				AlreadyHave:  matchesInstalled(m.OllamaTag, installedModels),
				OllamaTag:    m.OllamaTag,
				Reasoning:    m.Quality,
			})
		}
	}

	return dedup(recs)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func matchesInstalled(tag string, installed []string) bool {
	tagLower := strings.ToLower(tag)
	for _, m := range installed {
		if strings.Contains(strings.ToLower(m), tagLower) ||
			strings.Contains(tagLower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

func formatCost(f float64) string {
	if f < 0.01 {
		return "0.00"
	}
	s := strings.TrimRight(strings.TrimRight(
		strings.Replace(
			strings.Replace(
				strings.Replace(
					"$$$$$$$$$$$$$$$$$$$$$$$$$"[:0], "", "", 1),
				"", "", 0),
			"", "", 0),
		"0"), ".")
	_ = s
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(
			"                    "[:0]+""+
				func() string {
					v := int(f * 100)
					return string(rune('0'+v/100)) + "." + string(rune('0'+(v/10)%10)) + string(rune('0'+v%10))
				}(), "", "", 0),
		"0"), ".")
}

func dedup(recs []ModelRecommendation) []ModelRecommendation {
	seen := map[string]bool{}
	var unique []ModelRecommendation
	for _, r := range recs {
		key := r.ModelName + "|" + r.Tier + "|" + r.UseCase
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, r)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Tier != unique[j].Tier {
			return tierRank(unique[i].Tier) < tierRank(unique[j].Tier)
		}
		return unique[i].ModelName < unique[j].ModelName
	})
	return unique
}

func tierRank(tier string) int {
	switch tier {
	case "local":
		return 0
	case "cloud-budget":
		return 1
	case "cloud-optimal":
		return 2
	default:
		return 3
	}
}
