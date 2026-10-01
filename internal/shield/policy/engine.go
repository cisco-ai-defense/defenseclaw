package policy

import (
	"github.com/defenseclaw/defenseclaw/internal/shield/inspect"
)

type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionLog
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionBlock:
		return "BLOCK"
	case ActionLog:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}

type Verdict struct {
	Action   Action          `json:"action"`
	Reason   string          `json:"reason,omitempty"`
	Findings []inspect.Finding `json:"findings,omitempty"`
}

type Config struct {
	BlockSeverity inspect.Severity // Block at this severity or above.
	LogAll        bool             // Log every request regardless of verdict.
}

func DefaultConfig() Config {
	return Config{
		BlockSeverity: inspect.SeverityHigh,
		LogAll:        true,
	}
}

type Engine struct {
	cfg Config
}

func NewEngine(cfg Config) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Evaluate(result inspect.InspectResult) Verdict {
	if result.Clean {
		return Verdict{Action: ActionAllow}
	}

	max := result.MaxSeverity()
	if max >= e.cfg.BlockSeverity {
		return Verdict{
			Action:   ActionBlock,
			Reason:   "content matched security rule at severity " + max.String(),
			Findings: result.Findings,
		}
	}

	return Verdict{
		Action:   ActionLog,
		Reason:   "findings below block threshold",
		Findings: result.Findings,
	}
}
