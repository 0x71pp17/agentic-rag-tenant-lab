#!/usr/bin/env bash
# Confirms the repo layout survived download/extract intact.
# Run from the repo root: bash verify-layout.sh
set -u
missing=0
required=(
  lab/__init__.py lab/config.py lab/store.py lab/store_chroma.py lab/ingest.py
  lab/defenses.py lab/tools.py lab/agent.py lab/backends.py lab/embeddings.py
  lab/corpus.py
  attack/__init__.py attack/attacks.py
  harness/__init__.py harness/runner.py harness/report.py
  tests/test_lab.py tests/test_chroma_parity.py
  docs/how-it-works.md docs/threat-model.md
  detection/signatures.md detection/sigma/cross_tenant_retrieval.yml
  results/asr-scripted.md results/asr-scripted.json
  .github/workflows/ci.yml
  README.md SECURITY.md LICENSE Makefile requirements.txt requirements-optional.txt
  .gitignore
)
for f in "${required[@]}"; do
  if [ ! -f "$f" ]; then echo "MISSING: $f"; missing=$((missing+1)); fi
done
if [ "$missing" -gt 0 ]; then
  echo
  echo "$missing file(s) missing. Flattened or partial extract."
  echo "Dot-directories (.github) and small files are the usual casualties."
  exit 1
fi
echo "Layout OK: all 32 tracked paths present."
echo "Now run: pip install -r requirements.txt && python3 -m pytest tests/ -q"
