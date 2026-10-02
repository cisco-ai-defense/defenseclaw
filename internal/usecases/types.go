package usecases

// InferredUseCase represents a detected usage pattern with evidence.
type InferredUseCase struct {
	Name       string   `json:"name"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Frequency  string   `json:"frequency"` // "primary", "secondary", "occasional"
}
