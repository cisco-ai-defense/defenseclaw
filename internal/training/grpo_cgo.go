//go:build cgo && grpo_engine

// internal/training/grpo_cgo.go
package training

/*
#cgo CFLAGS: -I${SRCDIR}/grpo_engine -O3
#cgo linux CFLAGS: -fopenmp
#cgo linux LDFLAGS: -L${SRCDIR}/grpo_engine -lgrpo_stream -lm -lgomp
#cgo darwin LDFLAGS: -L${SRCDIR}/grpo_engine -lgrpo_stream -lm -L/opt/homebrew/opt/libomp/lib -lomp
#include "grpo.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// GrpoEngine wraps the C library context.
type GrpoEngine struct {
	ctx *C.GrpoCtx
}

// NewGrpoEngine initializes the C engine with the given config.
func NewGrpoEngine(cfg GrpoLocalConfig) (*GrpoEngine, error) {
	policyPath := C.CString(cfg.PolicyGGUF)
	defer C.free(unsafe.Pointer(policyPath))

	var refPath, rewPath, tokPath *C.char
	if cfg.ReferenceGGUF != "" {
		refPath = C.CString(cfg.ReferenceGGUF)
		defer C.free(unsafe.Pointer(refPath))
	}
	if cfg.RewardGGUF != "" {
		rewPath = C.CString(cfg.RewardGGUF)
		defer C.free(unsafe.Pointer(rewPath))
	}
	if cfg.TokenizerPath != "" {
		tokPath = C.CString(cfg.TokenizerPath)
		defer C.free(unsafe.Pointer(tokPath))
	}

	var targets *C.char
	if cfg.LoRATargets != "" {
		targets = C.CString(cfg.LoRATargets)
		defer C.free(unsafe.Pointer(targets))
	}

	memMode := 0 // auto-detect
	switch cfg.MemoryMode {
	case "minimal":
		memMode = 0
	case "standard":
		memMode = 1
	case "comfort":
		memMode = 2
	}

	ccfg := C.GrpoConfig{
		policy_gguf:        policyPath,
		reference_gguf:     refPath,
		reward_gguf:        rewPath,
		tokenizer_path:     tokPath,
		memory_mode:        C.int(memMode),
		lora_rank:          C.int(cfg.LoRARank),
		lora_alpha:         C.int(cfg.LoRAAlpha),
		lora_targets:       targets,
		max_seq_len:        C.int(2048),
		num_threads:        C.int(cfg.NumThreads),
		use_direct_io:      C.int(1),
		layer_buffer_bytes: 0, // auto-size
	}

	ctx := C.grpo_init(&ccfg)
	if ctx == nil {
		return nil, fmt.Errorf("grpo_init failed")
	}
	return &GrpoEngine{ctx: ctx}, nil
}

func (e *GrpoEngine) Generate(prompt []int, maxLen int, temp, topP float32) (tokens []int, logprobs []float32, err error) {
	// Lock this goroutine to its OS thread for the duration of the long C call.
	// Without this, Go's scheduler may never reschedule us after the C function
	// blocks for seconds/minutes on large model matmuls.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output := make([]C.int, maxLen)
	lp := make([]C.float, maxLen)
	promptC := make([]C.int, len(prompt))
	for i, t := range prompt {
		promptC[i] = C.int(t)
	}

	n := C.grpo_generate(e.ctx, &promptC[0], C.int(len(prompt)),
		&output[0], C.int(maxLen), &lp[0], C.float(temp), C.float(topP))
	if n < 0 {
		return nil, nil, fmt.Errorf("generation failed")
	}

	tokens = make([]int, int(n))
	logprobs = make([]float32, int(n))
	for i := 0; i < int(n); i++ {
		tokens[i] = int(output[i])
		logprobs[i] = float32(lp[i])
	}
	return tokens, logprobs, nil
}

func (e *GrpoEngine) PolicyLogprobs(tokens []int) ([]float32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tc := make([]C.int, len(tokens))
	for i, t := range tokens {
		tc[i] = C.int(t)
	}
	lp := make([]C.float, len(tokens))
	ret := C.grpo_policy_logprobs(e.ctx, &tc[0], C.int(len(tokens)), &lp[0])
	if ret != 0 {
		return nil, fmt.Errorf("policy logprobs failed")
	}
	result := make([]float32, len(tokens))
	for i := range result {
		result[i] = float32(lp[i])
	}
	return result, nil
}

func (e *GrpoEngine) RefLogprobs(tokens []int) ([]float32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tc := make([]C.int, len(tokens))
	for i, t := range tokens {
		tc[i] = C.int(t)
	}
	lp := make([]C.float, len(tokens))
	ret := C.grpo_ref_logprobs(e.ctx, &tc[0], C.int(len(tokens)), &lp[0])
	if ret != 0 {
		return nil, fmt.Errorf("ref logprobs failed")
	}
	result := make([]float32, len(tokens))
	for i := range result {
		result[i] = float32(lp[i])
	}
	return result, nil
}

func (e *GrpoEngine) Backward(advantages, policyLP, oldLP, refLP []float32, G, seqLen int, clipEps, klCoef float32) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ret := C.grpo_backward(e.ctx,
		(*C.float)(unsafe.Pointer(&advantages[0])),
		(*C.float)(unsafe.Pointer(&policyLP[0])),
		(*C.float)(unsafe.Pointer(&oldLP[0])),
		(*C.float)(unsafe.Pointer(&refLP[0])),
		C.int(G), C.int(seqLen), C.float(clipEps), C.float(klCoef))
	if ret != 0 {
		return fmt.Errorf("backward failed")
	}
	return nil
}

func (e *GrpoEngine) AdamStep(lr, beta1, beta2, eps float32, step int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ret := C.grpo_adam_step(e.ctx, C.float(lr), C.float(beta1), C.float(beta2), C.float(eps), C.int(step))
	if ret != 0 {
		return fmt.Errorf("adam step failed")
	}
	return nil
}

func (e *GrpoEngine) SaveLoRA(path string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.grpo_save_lora(e.ctx, p) != 0 {
		return fmt.Errorf("save lora failed")
	}
	return nil
}

func (e *GrpoEngine) LoadLoRA(path string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.grpo_load_lora(e.ctx, p) != 0 {
		return fmt.Errorf("load lora failed")
	}
	return nil
}

func (e *GrpoEngine) ExportMergedGGUF(path string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.grpo_export_merged_gguf(e.ctx, p) != 0 {
		return fmt.Errorf("export merged gguf failed")
	}
	return nil
}

func (e *GrpoEngine) Stats() GrpoStats {
	s := C.grpo_stats(e.ctx)
	return GrpoStats{
		Steps:                int64(s.steps),
		TotalGenSeconds:      float64(s.total_gen_seconds),
		TotalStreamSeconds:   float64(s.total_stream_seconds),
		TotalBackwardSeconds: float64(s.total_backward_seconds),
		BytesStreamed:        uint64(s.bytes_streamed),
		LastLoss:             float32(s.last_loss),
		LastRewardMean:       float32(s.last_reward_mean),
	}
}

func (e *GrpoEngine) Close() {
	if e.ctx != nil {
		C.grpo_free(e.ctx)
		e.ctx = nil
	}
}

// Prefill runs the prompt through the model and saves KV cache state
func (e *GrpoEngine) Prefill(prompt []int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	promptC := make([]C.int, len(prompt))
	for i, t := range prompt {
		promptC[i] = C.int(t)
	}
	ret := C.grpo_prefill(e.ctx, &promptC[0], C.int(len(prompt)))
	if ret < 0 {
		return fmt.Errorf("prefill failed")
	}
	return nil
}

// GenerateContinue continues generation from current KV cache position
func (e *GrpoEngine) GenerateContinue(maxLen int, temp, topP float32) (tokens []int, logprobs []float32, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	output := make([]C.int, maxLen)
	lp := make([]C.float, maxLen)

	n := C.grpo_generate_continue(e.ctx, &output[0], C.int(maxLen),
		&lp[0], C.float(temp), C.float(topP))
	if n < 0 {
		return nil, nil, fmt.Errorf("generate_continue failed")
	}

	tokens = make([]int, int(n))
	logprobs = make([]float32, int(n))
	for i := 0; i < int(n); i++ {
		tokens[i] = int(output[i])
		logprobs[i] = float32(lp[i])
	}
	return tokens, logprobs, nil
}

// SaveKVSnapshot saves current KV cache state
func (e *GrpoEngine) SaveKVSnapshot() {
	C.grpo_save_kv_snapshot(e.ctx)
}

// RestoreKVSnapshot restores previously saved KV cache state
func (e *GrpoEngine) RestoreKVSnapshot() {
	C.grpo_restore_kv_snapshot(e.ctx)
}

// FreeKVSnapshot frees the saved KV cache snapshot
func (e *GrpoEngine) FreeKVSnapshot() {
	C.grpo_free_kv_snapshot(e.ctx)
}

// Detokenize converts token IDs to UTF-8 text using the loaded tokenizer
func (e *GrpoEngine) Detokenize(tokens []int) string {
	if len(tokens) == 0 {
		return ""
	}
	tc := make([]C.int, len(tokens))
	for i, t := range tokens {
		tc[i] = C.int(t)
	}
	buf := make([]C.char, 4096)
	n := C.grpo_detokenize(e.ctx, &tc[0], C.int(len(tokens)), &buf[0], 4096)
	if n <= 0 {
		return ""
	}
	return C.GoStringN(&buf[0], n)
}

// GrpoEngineAvailable returns true when the C engine is compiled in.
func GrpoEngineAvailable() bool { return true }
