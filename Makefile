.PHONY: test test-parity sweep sweep-ollama sweep-anthropic clean

# Core suite. Needs numpy only. Chroma parity tests skip if chromadb is absent.
test:
	python3 -m pytest tests/ -v

# Same findings, run against a real vector database.
test-parity:
	pip install -r requirements-optional.txt
	python3 -m pytest tests/test_chroma_parity.py -v

sweep:
	python3 -m harness.report --trials 20 --out results/asr-scripted.md --json results/asr-scripted.json

sweep-ollama:
	python3 -m harness.report --backend ollama:llama3.1:8b --trials 20 \
		--out results/asr-llama31-8b.md --json results/asr-llama31-8b.json

sweep-anthropic:
	python3 -m harness.report --backend anthropic:claude-sonnet-4-6 --trials 20 \
		--out results/asr-sonnet.md --json results/asr-sonnet.json

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
