# Security policy

## This repository contains intentionally vulnerable code

That is its purpose. `lab/` implements a multi-tenant agentic RAG system with
four deliberate authorization flaws (V1 to V4) and five defense layers (D1 to
D5), all independently togglable via `lab/config.py`, so that a measurement
harness can attribute changes in attack success rate to a specific control.

Please do not file vulnerability reports for the intended flaws. They are
documented in the README, in `docs/threat-model.md`, and in the docstrings of
`lab/store.py`, `lab/ingest.py` and `lab/defenses.py`.

## Do not deploy this

Nothing here is production code. In particular:

- `LabConfig()` defaults to the fully vulnerable configuration.
- `lab/tools.py` records outbound data by design; it is an instrument, not a
  guardrail.
- The embedder in `lab/embeddings.py` is a deterministic hash, chosen for
  reproducibility rather than retrieval quality.

## Scope

Everything in this repository is synthetic. The tenants, documents, hostnames
and the canary string are fabricated. No real system, customer, vendor or
security engagement is represented, and nothing here constitutes a vulnerability
disclosure against any product.

The findings describe general classes of weakness in multi-tenant RAG
architectures. Where a class is illustrated against a third-party library (for
example the ChromaDB adapter in `lab/store_chroma.py`), the flaw demonstrated is
in *how an application uses* that library, not in the library itself. Chroma
behaves correctly in every case tested here, including failing closed on a
missing metadata key.

## What to report

Genuine defects in the lab itself are welcome: a test that passes for the wrong
reason, a payload that succeeds for a reason unrelated to the control it
targets, an incorrect claim in the documentation, or a result that does not
reproduce. Open an issue.

If you find that a documented finding does **not** reproduce, that is the most
valuable report you can file, and it should include your Python version, whether
you ran the Chroma parity tests, and the model backend used.
