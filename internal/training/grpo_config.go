// internal/training/grpo_config.go
package training

// GrpoLocalConfig holds all settings for a grpo-local training run.
type GrpoLocalConfig struct {
	PolicyGGUF    string
	ReferenceGGUF string
	RewardGGUF    string
	TokenizerPath string

	GroupSize      int
	MaxGenLength   int
	ClipEpsilon    float64
	KLCoef         float64
	Temperature    float64
	TopP           float64
	LearningRate   float64
	GradAccumSteps int

	LoRARank    int
	LoRAAlpha   int
	LoRATargets string

	MemoryMode string
	NumThreads int

	RewardFuncs []RewardSpec

	MaxSteps        int
	CheckpointEvery int
	DatasetPath     string
	OutputDir       string
}

// RewardSpec defines a single reward function with its weight.
type RewardSpec struct {
	Type   string
	Params map[string]string
	Weight float64
}

// GrpoStats holds runtime statistics from the C engine.
type GrpoStats struct {
	Steps                int64
	TotalGenSeconds      float64
	TotalStreamSeconds   float64
	TotalBackwardSeconds float64
	BytesStreamed        uint64
	LastLoss             float32
	LastRewardMean       float32
}

// ParseRewardFuncs parses config strings like "exec:timeout=10,lang=python" into RewardSpecs.
func ParseRewardFuncs(specs []string) []RewardSpec {
	result := make([]RewardSpec, 0, len(specs))
	for _, spec := range specs {
		rs := RewardSpec{Weight: 1.0, Params: make(map[string]string)}
		// Parse "type:key=val,key=val" format
		parts := splitFirst(spec, ':')
		rs.Type = parts[0]
		if len(parts) > 1 {
			for _, kv := range splitAll(parts[1], ',') {
				pair := splitFirst(kv, '=')
				if len(pair) == 2 {
					rs.Params[pair[0]] = pair[1]
				}
			}
		}
		result = append(result, rs)
	}
	return result
}

func splitFirst(s string, sep byte) []string {
	for i := range s {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func splitAll(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := range s {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
