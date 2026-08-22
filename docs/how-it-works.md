# How it works

The repo looks like a lot of files because each layer of the system under test is
separated from the next. That separation is what makes the measurement possible:
because retrieval, defenses, tools and the model are independent, the harness can
switch any one of them off and attribute the change in attack success rate to
that one thing.

You only need to read three files to understand the whole lab: `lab/config.py`,
`lab/store.py`, and `lab/defenses.py`.

## One request, end to end

A single call to `Session.run_turn()` moves through every module in order.

```
  ticket text
      |
      v
  [1] lab/store.py        query()              retrieval, tenant-scoped
      |                                        <-- V1, V2, V3 live here
      v
  [2] lab/defenses.py     filter_chunks()      injection classifier (D2)
      |
      v
  [3] lab/defenses.py     compute_taint()      provenance (D5 input)
      |
      v
  [4] lab/defenses.py     frame_context()      instruction hierarchy (D1)
      |
      v
  [5] lab/agent.py        prompt assembly      memory + context + ticket
      |
      v
  [6] lab/backends.py     complete()           the model
      |
      v
  [7] lab/tools.py        dispatch()           gate (D5) -> validate (D4)
      |                                        -> execute -> egress check (D3)
      v
  [8] lab/tools.py        ExfilObserver        records every attacker-visible byte
      |
      v
  loop back to [6] with tool results, up to max_iterations
```

Step 8 is the measurement instrument. `ExfilObserver.saw(CANARY)` is the entire
success oracle, which is why the results do not depend on an LLM judge.

## What each file is for

**The system under test (`lab/`)**

| File | Role |
|---|---|
| `config.py` | Every vulnerability and defense as an independent boolean. The harness sweeps this. Start here. |
| `store.py` | Vector store and the `_visible()` authorization sink. V1, V2 and V3 converge on it. |
| `store_chroma.py` | The same interface backed by real ChromaDB, so the findings are testable outside my own code. Optional dependency. |
| `ingest.py` | Document to chunks. V3 (metadata loss) and V4 (mass assignment) live here. |
| `defenses.py` | D1 through D5. Each carries a docstring naming what it does not stop. |
| `tools.py` | The five agent tools, the defense pipeline they route through, and the exfil observer. |
| `agent.py` | The iterative agent loop. Assembles the prompt, runs tools, feeds results back. |
| `backends.py` | Model adapters: `scripted`, `ollama:`, `anthropic:`. |
| `embeddings.py` | Deterministic hashed embedder so the lab runs with numpy alone. |
| `corpus.py` | The synthetic two-tenant knowledge base and the canary. |

**The attacks (`attack/attacks.py`)** Five `Attack` objects. Each is data, not
code: documents to plant, turns to run, which tenant's session to run in, and
what counts as success. Adding a sixth attack means appending one object.

**The measurement (`harness/`)**

| File | Role |
|---|---|
| `runner.py` | `run_trial()` runs one isolated trial. `sweep()` runs the cartesian product. |
| `report.py` | CLI, markdown matrix, Wilson intervals, and the scripted-backend honesty guard. |

## Running it

Nothing in the default path needs a model, a GPU, or an API key.

```bash
pip install -r requirements.txt

make test     # 23 tests
make sweep    # regenerate results/asr-scripted.md
```

Restrict a sweep while you are iterating:

```bash
python3 -m harness.report --attack A3 --attack A5 --trials 50
```

Real model measurement, which is what upgrades the claims from plumbing to
findings:

```bash
ollama pull llama3.1:8b
make sweep-ollama

export ANTHROPIC_API_KEY=...
make sweep-anthropic
```

## CI

`.github/workflows/ci.yml` runs on push, pull request, and manual dispatch. No
configuration needed; push the repo and it works.

- **`test`** runs the suite across Python 3.11, 3.12 and 3.13 with pip caching.
- **`parity`** installs ChromaDB and runs the findings against a production
  vector database, which is what separates a finding about multi-tenant RAG from
  a defect in the hand-written store.
- **`matrix-regression`** regenerates the ASR matrix and diffs it against the
  committed `results/asr-scripted.md`. This is the gate that matters. If a
  defense layer regresses, or a payload is accidentally weakened, a cell changes
  and the build fails. The committed results file is a test fixture, not just
  documentation. The matrix is also written to the job summary, so you can read
  it on the Actions run page without downloading anything.

Both jobs run on standard GitHub-hosted runners, because the `scripted` backend
needs no model, no GPU and no API key. Real model measurement stays local
(`make sweep-ollama`); running it in CI would mean either shipping an API key to
Actions or maintaining a self-hosted runner with Ollama, and neither is worth it
for a repo whose whole point is that anyone can reproduce the results.

A `.gitlab-ci.yml` mirroring the same two jobs is included, for mirroring to a
GitLab instance. If you are not mirroring, delete it; nothing else references it.

## Extending it

**Add a defense.** Add a flag to `LabConfig`, implement it in `defenses.py` with
a docstring naming its failure mode, wire it into `agent.py` or `tools.py`, and
add a config to `harness/report.py`'s `CONFIGS`. The matrix picks it up.

**Add an attack.** Append an `Attack` to `attack/attacks.py` and add it to
`CORPUS`. Add a test asserting it fails against `hardened`. If it succeeds
against `hardened`, that is a result worth writing up.

**Add a vulnerability.** Add a flag to `LabConfig` and implement it in `store.py`
or `ingest.py`. Keep it defaulting to the vulnerable state so the `vulnerable`
config stays the full-bug baseline.

**Swap the embedder.** `SentenceTransformerEmbedder` is already in
`embeddings.py`. Use it when measuring rank-manipulation attacks, which do
depend on the embedding space in a way that none of A1 through A5 currently do.

## One design constraint worth knowing

Payloads must survive chunking and win a retrieval slot, or the attack silently
fails for a reason unrelated to the defenses. A5 hit both problems during
development: it first fragmented across chunks so that the half carrying the
exfil sink never ranked, and once fixed it out-competed the target secret for
top-k slots. If you add an attack and it reports 0% everywhere including
`vulnerable`, check retrieval before you check the payload:

```bash
python3 -c "
from lab.config import LabConfig
from lab.corpus import build_store, CANARY
from lab.embeddings import cosine
from attack.attacks import BY_ID
a = BY_ID['A5']; cfg = LabConfig()
store = build_store(cfg, extra=a.documents)
qv = store.embedder.embed(a.turns[0])
for s, c in sorted(((cosine(qv, c.vector), c) for c in store.chunks), key=lambda p: -p[0])[:6]:
    print(f'{s:.4f}  {c.chunk_id:32s} canary={CANARY in c.text}')
"
```
