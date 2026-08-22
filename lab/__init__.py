"""The system under test: a multi-tenant agentic RAG support-triage agent.

Read `config.py` first. Every vulnerability and every defense in this package is
an independently togglable flag there, which is what lets the harness attribute
a change in attack success rate to one specific control.

This file intentionally carries content rather than being empty, because empty
files are silently dropped by some download and upload paths. Without it, the
package is not importable.
"""
