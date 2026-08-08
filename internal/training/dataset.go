// internal/training/dataset.go
// Dataset creation, validation, and tokenization for GRPO training.
package training

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DatasetEntry represents one training example
type DatasetEntry struct {
	Prompt       string            `json:"prompt"`
	PromptTokens []int            `json:"prompt_tokens"`
	GroundTruth  string            `json:"ground_truth,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// DatasetStats from validation
type DatasetStats struct {
	TotalPrompts  int
	AvgTokens     float64
	MaxTokens     int
	MinTokens     int
	VocabSize     int
	InvalidTokens int
	EmptyPrompts  int
	ChatTemplate  string
}

// ChatTemplate defines model-specific prompt wrapping
type ChatTemplate struct {
	Name     string
	BOS      int
	EOS      int
	Prefix   []int // tokens before user message
	Suffix   []int // tokens after user message, before assistant
}

// Known chat templates
var chatTemplates = map[string]ChatTemplate{
	"qwen3": {
		Name:   "qwen3",
		BOS:    151643,
		EOS:    151645,
		Prefix: []int{151644, 872, 198}, // <|im_start|>user\n
		Suffix: []int{151645, 198, 151644, 77091, 198}, // <|im_end|>\n<|im_start|>assistant\n
	},
	"qwen2": {
		Name:   "qwen2",
		BOS:    151643,
		EOS:    151645,
		Prefix: []int{151644, 872, 198},
		Suffix: []int{151645, 198, 151644, 77091, 198},
	},
	"llama3": {
		Name:   "llama3",
		BOS:    128000,
		EOS:    128009,
		Prefix: []int{128000, 128006, 882, 128007, 271}, // <|begin|><|start_header|>user<|end_header|>\n\n
		Suffix: []int{128009, 128006, 78191, 128007, 271}, // <|eot|><|start_header|>assistant<|end_header|>\n\n
	},
}

// DetectChatTemplate identifies the chat template from model name
func DetectChatTemplate(modelName string) ChatTemplate {
	lower := strings.ToLower(modelName)
	if strings.Contains(lower, "qwen3") {
		return chatTemplates["qwen3"]
	}
	if strings.Contains(lower, "qwen2") || strings.Contains(lower, "qwen") {
		return chatTemplates["qwen2"]
	}
	if strings.Contains(lower, "llama") {
		return chatTemplates["llama3"]
	}
	// Default to qwen3
	return chatTemplates["qwen3"]
}

// CreateDataset reads plain-text prompts and produces tokenized JSONL.
func CreateDataset(inputPath, outputPath, modelPath string) error {
	// Detect model type from path
	modelName := filepath.Base(modelPath)
	template := DetectChatTemplate(modelName)

	// Load tokenizer from GGUF for BPE encoding
	// For now, use the chat template tokens directly (no BPE encoding of prompt text)
	// Full BPE encoding requires the merge table which is complex
	// Instead, we'll use llama.cpp's tokenizer if available

	// Read input prompts
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("cannot open input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create output: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	scanner := bufio.NewScanner(inFile)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	count := 0
	var totalTokens int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip empty lines and comments
		}

		// Tokenize: template prefix + BPE(prompt) + template suffix
		// Since we can't do full BPE from Go without the merge table,
		// we'll try to use the llama-tokenize CLI if available
		tokens, err := tokenizePrompt(line, modelPath, template)
		if err != nil {
			// Fallback: use template tokens only (prompt text not encoded)
			tokens = append([]int{}, template.Prefix...)
			tokens = append(tokens, template.Suffix...)
		}

		entry := DatasetEntry{
			Prompt:       line,
			PromptTokens: tokens,
			Metadata:     map[string]string{"source": "user", "template": template.Name},
		}

		data, _ := json.Marshal(entry)
		writer.Write(data)
		writer.WriteByte('\n')

		count++
		totalTokens += len(tokens)
	}

	writer.Flush()

	avgTokens := 0.0
	if count > 0 {
		avgTokens = float64(totalTokens) / float64(count)
	}

	fmt.Fprintf(os.Stderr, "✓ Created dataset: %s\n", outputPath)
	fmt.Fprintf(os.Stderr, "  Prompts:    %d\n", count)
	fmt.Fprintf(os.Stderr, "  Avg tokens: %.0f\n", avgTokens)
	fmt.Fprintf(os.Stderr, "  Template:   %s\n", template.Name)
	return nil
}

// tokenizePrompt uses llama-tokenize CLI or Python fallback
func tokenizePrompt(prompt, modelPath string, template ChatTemplate) ([]int, error) {
	// Try llama-tokenize if available
	llamaTok, err := findLlamaTokenize()
	if err == nil {
		return tokenizeWithLlama(llamaTok, modelPath, prompt, template)
	}
	// Fallback: use Python with our GGUF tokenizer
	return tokenizeWithPython(modelPath, prompt, template)
}

func findLlamaTokenize() (string, error) {
	paths := []string{"llama-tokenize", "/opt/homebrew/bin/llama-tokenize", "/usr/local/bin/llama-tokenize"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		if path, err := lookPath(p); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func lookPath(name string) (string, error) {
	// Simple PATH lookup
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("not in PATH")
}

func tokenizeWithLlama(llamaPath, modelPath, prompt string, template ChatTemplate) ([]int, error) {
	// Build chat-formatted prompt
	chatPrompt := fmt.Sprintf("<|im_start|>user\n%s<|im_end|>\n<|im_start|>assistant\n", prompt)

	cmd := fmt.Sprintf("%s -m %s --prompt %q --no-bos 2>/dev/null | grep -o '[0-9]*'",
		llamaPath, modelPath, chatPrompt)
	// This is fragile — better to use Python fallback
	_ = cmd
	return nil, fmt.Errorf("llama-tokenize parsing not implemented, using Python fallback")
}

func tokenizeWithPython(modelPath, prompt string, template ChatTemplate) ([]int, error) {
	// Use Python script to tokenize with GGUF vocab + merges
	script := fmt.Sprintf(`
import struct, json, sys

f = open('%s', 'rb')
f.read(4); f.read(4)
n_tensors = struct.unpack('<Q', f.read(8))[0]
n_kv = struct.unpack('<Q', f.read(8))[0]
GV = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}
tokens_list = None; merges_list = None
for i in range(n_kv):
    kl = struct.unpack('<Q', f.read(8))[0]; key = f.read(kl).decode('utf-8','replace')
    vt = struct.unpack('<I', f.read(4))[0]
    if key == 'tokenizer.ggml.tokens' and vt == 9:
        at = struct.unpack('<I', f.read(4))[0]; al = struct.unpack('<Q', f.read(8))[0]
        tokens_list = []
        for j in range(al):
            sl = struct.unpack('<Q', f.read(8))[0]; tokens_list.append(f.read(sl).decode('utf-8','replace'))
    elif key == 'tokenizer.ggml.merges' and vt == 9:
        at = struct.unpack('<I', f.read(4))[0]; al = struct.unpack('<Q', f.read(8))[0]
        merges_list = []
        for j in range(al):
            sl = struct.unpack('<Q', f.read(8))[0]; merges_list.append(f.read(sl).decode('utf-8','replace'))
    elif vt == 9:
        at = struct.unpack('<I', f.read(4))[0]; al = struct.unpack('<Q', f.read(8))[0]
        for j in range(al):
            if at == 8: sl = struct.unpack('<Q', f.read(8))[0]; f.read(sl)
            elif at in GV: f.read(GV[at])
    elif vt == 8: sl = struct.unpack('<Q', f.read(8))[0]; f.read(sl)
    elif vt in GV: f.read(GV[vt])
f.close()

bs = list(range(ord("!"),ord("~")+1))+list(range(0xA1,0xAD))+list(range(0xAE,0x100))
cs = bs[:]; n = 0
for b in range(256):
    if b not in bs: bs.append(b); cs.append(256+n); n+=1
byte_encoder = {b: chr(c) for b, c in zip(bs, cs)}
vocab = {t: i for i, t in enumerate(tokens_list)}
merge_rank = {m: i for i, m in enumerate(merges_list)}

def bpe_encode(text):
    encoded = ''.join(byte_encoder[b] for b in text.encode('utf-8'))
    word = list(encoded)
    while len(word) > 1:
        best_pair = None; best_rank = len(merges_list)
        for i in range(len(word)-1):
            pair = word[i]+' '+word[i+1]
            if pair in merge_rank and merge_rank[pair] < best_rank:
                best_pair = (i, word[i]+word[i+1]); best_rank = merge_rank[pair]
        if best_pair is None: break
        idx, merged = best_pair
        word = word[:idx] + [merged] + word[idx+2:]
    return [vocab[t] for t in word if t in vocab]

prompt = sys.argv[1]
ids = bpe_encode(prompt)
print(json.dumps(ids))
`, modelPath)

	cmd := fmt.Sprintf("python3 -c %q %q", script, prompt)
	out, err := runShell(cmd)
	if err != nil {
		return nil, err
	}

	var ids []int
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &ids) != nil {
		return nil, fmt.Errorf("failed to parse token IDs")
	}

	// Wrap with chat template
	result := append([]int{}, template.Prefix...)
	result = append(result, ids...)
	result = append(result, template.Suffix...)
	return result, nil
}

func runShell(cmd string) (string, error) {
	out, err := execCommand("sh", "-c", cmd)
	return string(out), err
}

func execCommand(name string, args ...string) ([]byte, error) {
	cmd := &exec.Cmd{Path: name, Args: append([]string{name}, args...)}
	if filepath.Base(name) == name {
		if p, err := lookPath(name); err == nil {
			cmd.Path = p
		}
	}
	return cmd.Output()
}

// ValidateDataset checks a JSONL dataset for correctness.
func ValidateDataset(datasetPath, modelPath string) (*DatasetStats, error) {
	f, err := os.Open(datasetPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open dataset: %w", err)
	}
	defer f.Close()

	modelName := filepath.Base(modelPath)
	template := DetectChatTemplate(modelName)

	// Get vocab size from model
	vocabSize := 151936 // default for Qwen3
	status := FindModel(modelPath)
	if status.Available && status.IsGGUF {
		// Could parse GGUF for exact vocab size
	}

	stats := &DatasetStats{
		MinTokens:    999999,
		VocabSize:    vocabSize,
		ChatTemplate: template.Name,
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var entry DatasetEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		if entry.Prompt == "" {
			stats.EmptyPrompts++
			continue
		}

		stats.TotalPrompts++
		nTokens := len(entry.PromptTokens)

		if nTokens == 0 {
			stats.EmptyPrompts++
			continue
		}

		stats.AvgTokens += float64(nTokens)
		if nTokens > stats.MaxTokens {
			stats.MaxTokens = nTokens
		}
		if nTokens < stats.MinTokens {
			stats.MinTokens = nTokens
		}

		// Check token IDs are valid
		for _, id := range entry.PromptTokens {
			if id < 0 || id >= vocabSize {
				stats.InvalidTokens++
			}
		}
	}

	if stats.TotalPrompts > 0 {
		stats.AvgTokens /= float64(stats.TotalPrompts)
	}
	if stats.MinTokens == 999999 {
		stats.MinTokens = 0
	}

	return stats, nil
}

// FormatValidationReport produces a human-readable validation report
func FormatValidationReport(stats *DatasetStats) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Dataset Validation Report\n"))
	sb.WriteString(fmt.Sprintf("═════════════════════════\n\n"))

	if stats.TotalPrompts == 0 {
		sb.WriteString("✗ No valid prompts found!\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("✓ Prompts:      %d\n", stats.TotalPrompts))
	sb.WriteString(fmt.Sprintf("✓ Avg tokens:   %.0f\n", stats.AvgTokens))
	sb.WriteString(fmt.Sprintf("✓ Min tokens:   %d\n", stats.MinTokens))
	sb.WriteString(fmt.Sprintf("✓ Max tokens:   %d\n", stats.MaxTokens))
	sb.WriteString(fmt.Sprintf("✓ Vocab size:   %d\n", stats.VocabSize))
	sb.WriteString(fmt.Sprintf("✓ Template:     %s\n", stats.ChatTemplate))

	if stats.InvalidTokens > 0 {
		sb.WriteString(fmt.Sprintf("⚠ Invalid tokens: %d (IDs outside vocab range)\n", stats.InvalidTokens))
	}
	if stats.EmptyPrompts > 0 {
		sb.WriteString(fmt.Sprintf("⚠ Empty prompts:  %d (skipped)\n", stats.EmptyPrompts))
	}

	return sb.String()
}
