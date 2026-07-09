# Testing Guide: Routing + Training Pipeline

## Prerequisites

```bash
# All installed by DefenseClaw:
defenseclaw setup routing --enable    # Installs vllm-sr, starts Docker container
defenseclaw setup training --enable   # Installs mlx-lm-lora + llama-server
defenseclaw setup hermes --yes        # (or any connector to start the gateway)
```

Verify:
```bash
defenseclaw setup routing --status    # Should show: enabled, port 8888
defenseclaw setup training --status   # Should show: enabled, backend mlx-lm-lora
docker ps | grep semantic             # Should show: defenseclaw-semantic-router
which llama-server                    # Should show: /opt/homebrew/bin/llama-server
```

---

## Part 1: Testing Semantic Router

### Test 1.1: Verify SR is classifying correctly

```bash
# Code query → should match code_task signal → code_route decision
curl -s http://127.0.0.1:8888/api/v1/classify/intent \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"implement a sorting function in Python"}]}' | python3 -m json.tool

# Expected: recommended_model=code, routing_decision=code_route, matched_signals.keywords=[code_task]
```

### Test 1.2: Test all routing rules

```bash
# Complex task → reasoning
curl -s http://127.0.0.1:8888/api/v1/classify/intent \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"analyze the tradeoffs between microservices and monoliths"}]}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{d[\"matched_signals\"]} → {d[\"recommended_model\"]}')"
# Expected: {'keywords': ['complex_task']} → reasoning

# Code task → code
curl -s http://127.0.0.1:8888/api/v1/classify/intent \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"debug this function that crashes"}]}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{d[\"matched_signals\"]} → {d[\"recommended_model\"]}')"
# Expected: {'keywords': ['code_task']} → code

# Default (no signals) → fast
curl -s http://127.0.0.1:8888/api/v1/classify/intent \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"what is the capital of France?"}]}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{d[\"matched_signals\"]} → {d[\"recommended_model\"]}')"
# Expected: {} → fast
```

### Test 1.3: SR health and container status

```bash
curl -s http://127.0.0.1:8888/health
# Expected: {"status": "healthy", "service": "classification-api"}

docker logs defenseclaw-semantic-router 2>&1 | tail -5
# Should show: startup_complete, decisions=reasoning_route,code_route,default_route
```

---

## Part 2: Testing Training Pipeline

### Test 2.1: Verify trace capture

After sending queries through the gateway (via hooks), check if traces are captured:

```bash
sqlite3 ~/.defenseclaw/training-store.db "SELECT category, COUNT(*) FROM training_traces GROUP BY category;"
# Expected: one row per category with counts
```

### Test 2.2: Manually insert test traces (for quick testing)

```bash
sqlite3 ~/.defenseclaw/training-store.db "
INSERT INTO training_traces (category, prompt, response, model_used, latency_ms, tokens_in, tokens_out)
VALUES 
('code_route', '[{\"role\":\"user\",\"content\":\"implement quicksort\"}]', 'def quicksort(arr): ...', 'claude-sonnet-4-6', 450, 20, 150),
('code_route', '[{\"role\":\"user\",\"content\":\"implement binary search\"}]', 'def binary_search(arr, target): ...', 'claude-sonnet-4-6', 380, 15, 120);
"
```

Repeat until you have `min_traces` (configured in config.yaml, default 500, use 10 for testing).

### Test 2.3: Check training readiness

```bash
sqlite3 ~/.defenseclaw/training-store.db \
  "SELECT category, COUNT(*) as available FROM training_traces WHERE used_for_training=0 GROUP BY category;"
# Should show: code_route|N (where N >= your min_traces threshold)
```

### Test 2.4: Run training manually

```bash
defenseclaw training run --category code_route
```

Expected output:
```
[pipeline] code_route: extracting traces (N available)...
[pipeline] code_route: training Qwen3.5-1.5B with sft (M examples)...
[pipeline] code_route: deployed code_route-vXXX.gguf
[pipeline] code_route: evaluating (5 prompts)...
[pipeline] code_route: PROMOTED (ratio=0.XX >= 0.50)
```

### Test 2.5: Verify model deployment

```bash
ls ~/.defenseclaw/models/*.gguf
# Should show: code_route-vXXX.gguf

cat ~/.defenseclaw/models/registry.json | python3 -m json.tool
# Should show version with promoted=true
```

### Test 2.6: Test LLM-as-judge evaluation independently

```bash
# Use Ollama as judge to compare two responses
curl -s http://127.0.0.1:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3:1.7b",
    "messages": [{"role":"user","content":"Rate these two responses:\nQuestion: implement quicksort\nResponse A: return sorted(arr)\nResponse B: def quicksort(arr):\n  if len(arr)<=1: return arr\n  pivot=arr[0]\n  return quicksort([x for x in arr[1:] if x<pivot])+[pivot]+quicksort([x for x in arr[1:] if x>=pivot])\n\nReturn JSON: {\"score_a\": N, \"score_b\": N}"}]
  }' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['choices'][0]['message']['content'])"
# Expected: {"score_a": 1-3, "score_b": 8-10}
```

### Test 2.7: Test llama-server hosting

```bash
# Start llama-server manually with a downloaded model
llama-server --models-dir ~/.defenseclaw/models --port 8090 --host 127.0.0.1

# Check health
curl http://127.0.0.1:8090/health
# Expected: {"status": "ok"}

# List models
curl http://127.0.0.1:8090/v1/models
# Expected: lists all .gguf files in models/ dir
```

---

## Part 3: Full End-to-End Test

### Fastest path (with pre-built model):

1. Download a small pre-quantized model:
```bash
# Option A: From Ollama (then convert)
ollama pull qwen3:1.7b

# Option B: Direct GGUF download
curl -L https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf \
  -o ~/.defenseclaw/models/code_route-v1.gguf
```

2. Start llama-server:
```bash
llama-server --models-dir ~/.defenseclaw/models --port 8090 --host 127.0.0.1 &
```

3. Test inference on local model:
```bash
curl -s http://127.0.0.1:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"code_route-v1","messages":[{"role":"user","content":"implement fibonacci"}]}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['choices'][0]['message']['content'][:200])"
```

4. Test SR → Bifrost → local model routing:
```bash
# After promotion, SR routes "code" queries to llama-server
# This is the full production path:
# User → DefenseClaw → SR (classify) → Bifrost → llama-server (local) → Response
```

---

## Troubleshooting

| Issue | Check | Fix |
|-------|-------|-----|
| SR not classifying | `docker ps \| grep semantic` | `defenseclaw setup routing --enable` |
| No traces captured | `sqlite3 ~/.defenseclaw/training-store.db "SELECT COUNT(*) FROM training_traces;"` | Ensure gateway is running + processing requests |
| Training fails (OOM) | Check model size vs available RAM | Use smaller model (1.5B) or reduce batch size |
| Training fails (deps) | `python -c "import mlx_lm"` | Use isolated venv: `python -m venv /tmp/train-venv && source /tmp/train-venv/bin/activate && pip install mlx-lm` |
| llama-server won't start | `which llama-server` | `brew install llama.cpp` |
| Eval fails | Check judge endpoint is reachable | Ensure Ollama running: `ollama ps` |
| Promotion not happening | Check threshold in config | Lower `eval_threshold` to 0.50 for testing |

---

## Quick Smoke Test (2 minutes)

```bash
# 1. Verify routing works
curl -s http://127.0.0.1:8888/api/v1/classify/intent \
  -d '{"messages":[{"role":"user","content":"implement quicksort"}]}' \
  -H "Content-Type: application/json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'✅ SR: {d[\"recommended_model\"]}' if d.get('recommended_model') else '❌ SR failed')"

# 2. Verify training store
sqlite3 ~/.defenseclaw/training-store.db "SELECT 'traces: ' || COUNT(*) FROM training_traces;" 2>/dev/null || echo "❌ No training store"

# 3. Verify llama-server binary
which llama-server && echo "✅ llama-server installed" || echo "❌ llama-server missing"

# 4. Verify Docker
docker ps --filter name=defenseclaw-semantic --format "✅ SR container: {{.Status}}" 2>/dev/null || echo "❌ No SR container"

# 5. Verify gateway
curl -s http://127.0.0.1:18970/health > /dev/null && echo "✅ Gateway healthy" || echo "❌ Gateway not running"
```
