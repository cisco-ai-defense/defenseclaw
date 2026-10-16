# Narration Script — Intelligent Model Routing

~330 words, ~2:40 speaking at natural pace. Remaining 20s is visual breathing room.

---

## Scene 1 (0:00 – 0:15)

> "This is DefenseClaw's intelligent model routing. Today every LLM request goes to the same provider — whether it's a simple greeting or complex code generation. We're going to change that with the vLLM Semantic Router."

---

## Scene 2 (0:15 – 0:55)

> "In the config, we define signal types. Embedding similarity classifies intent without relying on exact keywords. Domain detection identifies categories like programming or devops. And complexity scoring analyzes the structure of the request."

*(pause 2s)*

> "Decisions combine these signals using AND and OR operators. The code route fires when embeddings match — and it activates a LoRA adapter for specialized output. The reasoning route requires both a keyword signal AND high complexity to trigger. And a semantic cache at highest priority intercepts repeated questions before they ever hit a model."

*(pause — startup logs)*

> "DefenseClaw starts, loads the signals, wires the decision engine, and the sidecar reports healthy. We're live."

---

## Scene 3 (0:55 – 2:25)

**Request 1 (0:55 – 1:25)**

> "First request: 'optimize this SQL query with better indexing.' Notice — the word 'code' doesn't appear anywhere. But the embedding classifier understands the intent and scores it at point-nine-one similarity. It routes to qwen3 four-b and activates the LoRA code adapter. That's semantic understanding, not keyword matching."

**Request 2 (1:25 – 1:55)**

> "Second request: 'step by step, compare React vs Vue for a large SaaS dashboard.' This time two signals fire together — the keyword matches reasoning cue, AND complexity analysis flags it as high. Both required. It routes to the eight-billion parameter model and injects a chain-of-thought system prompt automatically."

**Request 3 (1:55 – 2:25)**

> "Third: the same SQL question again. The semantic cache detects ninety-eight percent similarity and serves the cached response in two milliseconds — versus twelve hundred on a fresh call. Same answer, six hundred times faster, zero compute."

---

## Scene 4 (2:25 – 3:00)

> "Here's the full pipeline. Requests flow through signal extraction — embeddings, domain, complexity — into the decision engine for multi-signal fusion. Plugins enrich the call with LoRA adapters, system prompts, or cache responses. Then it forwards to the optimal model. Classify-only, no double-hop, graceful fallback if the router is down."

*(pause 3s)*

> "DefenseClaw plus vLLM Semantic Router. Intelligent routing for every request."

---

## Tips

- Natural conversational pace
- 1s silence at the very start
- Don't rush — the video has room
- Export as WAV (44.1kHz) → `narration.wav`
