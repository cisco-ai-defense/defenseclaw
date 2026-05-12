# dctest Ollama stub

Install Ollama natively (`brew install ollama` on macOS, `curl -fsSL https://ollama.com/install.sh | sh` on Linux), then:

```bash
ollama serve &
ollama pull llama3.1
ollama pull qwen2.5
```

The matrix providers `ollama-llama-3.1` and `ollama-qwen-2.5` expect the OpenAI-compatible endpoint at `http://127.0.0.1:11434/v1`. `dctest doctor` will check reachability for any cell that selects an Ollama provider.
