# AegisAI architecture

## 1. The problem it solves

An on-call engineer writes: *"payment-service started returning 500 errors after deployment v2.7.1 — investigate."*
AegisAI turns that sentence into an evidence-backed root cause, proves it with a counterfactual
replay, prepares a tested fix in a sandbox, and waits for a human to approve before anything
touches the repository or production.

## 2. Component map

```
                        ┌──────────────────────────────────────────────┐
  Dashboard / CLI ─────►│ FastAPI  (REST + SSE, /metrics, /a2a/*)      │
                        └───────────────┬──────────────────────────────┘
                                        │
                        ┌───────────────▼──────────────────────────────┐
                        │ LangGraph state machine (SQLite checkpoints) │
                        │ triage → recall → plan → ⟨parallel wave⟩ →    │
                        │ collect → rca → verify → fix → verify_fix →   │
                        │ approval(interrupt) → apply → report          │
                        └───────┬───────────────────────────┬──────────┘
                     A2A message/send               LLM router (fast / strong tier,
                     (local or HTTP)                cost ledger, validation + retry)
        ┌──────────┬──────────┼──────────┬──────────┬──────────┬─────────┐
    Research  Observability  Code   Database   Memory    RCA   Verification  Fix
        │          │          │        │                           │         │
        └──────────┴────MCP (in-memory or stdio) ──────────────────┴─────────┘
                   │          │        │          │         │
                 docs   observability  git    database     ops
                server     server    server    server    server (approval-gated)
                   │          │        │          │
               markdown    logs /    git repo  read-only     control-plane log
               corpus     metrics /  + tags    SQLite replica
                          traces
```

## 3. Agents

| Agent | Job | Tools (least privilege) |
|---|---|---|
| Supervisor | Triage the report into a structured brief, delegate, decide sufficiency, route | none |
| Planner | Evidence-driven waves; re-plans with discriminating queries | none |
| Memory | Similar past incidents + per-service root-cause priors | episodic store |
| Observability | Poisson change-point per error type, signature parsing, before/after metric shifts, telemetry-gap detection, metric-based onset when logs are lost | `observability.*` |
| Research | Hybrid RAG over architecture invariants, runbooks, postmortems | `docs.*` |
| Code | Diffs every deploy in the window; classifies config/code/schema changes; blames stack frames at the *deployed* revision | read-only `git.*` |
| Database | Agentic text-to-SQL: schema → SQL → static validation → read-only execution → retry → interpretation | `database.*` read-only |
| RCA | Weighted evidence rules over a failure-pattern catalogue; softmax with an explicit "insufficient evidence" hypothesis | none |
| Verification | Adversarial: temporal precedence, contradictions, margin, counterfactual replay in a sandbox; independent re-test of fixes | sandbox, traffic export |
| Fix | Minimal patch or ops action + replay-based reproduction test; applies only with an approval token | sandbox, approval-gated `git.create_fix_branch`, `ops.*` |

## 4. Control flow

1. **Triage.** Regex extraction (service, endpoint, status codes, version, time) with an LLM filling gaps.
   If the report names only an endpoint (`/audit`), the code agent resolves the owning service from configs.
2. **Wave 1 (parallel).** Observability finds the onset and signatures; research pulls invariants.
3. **Wave 2 (planned from wave-1 evidence).** Code diffs deploys and blames the exact frames; the
   database agent answers only the questions the signatures call for (e.g. `SSLError` → certificates,
   `UpstreamError` → dependency status); research searches runbooks for the signatures.
4. **RCA.** Every pattern is scored from explicit rules; confidence is a normalised distribution.
5. **Verify.** A hypothesis is *verified* only if recorded incident traffic reproduces the failure on
   the deployed revision and the failure disappears when the suspected cause is removed.
   * refuted → **reflection**: the pattern is rejected and RCA re-ranks;
   * inconclusive → **re-plan**: new wave with discriminating queries;
   * budgets exhausted → escalate to a human with the evidence collected.
6. **Fix + verify fix.** Patch in a sandbox, reproduction test must fail before and pass after,
   full suite, static checks, secret scan, path policy — re-run independently by the verifier.
7. **Approval.** `interrupt()` pauses the graph (state checkpointed to SQLite). On approval a
   single-use HMAC token bound to `(tool, run)` is minted; the gateway rejects the action without it.
8. **Report + memory.** Grounding-checked report; the outcome is written to episodic memory.

## 5. Why confidence is not an LLM number

`aegis/memory/semantic.py` holds each failure pattern's rules and weights, e.g. for
*database timeout reduced*:

| Rule | Weight |
|---|---|
| DatabaseTimeoutError spike | +2.0 |
| `db.timeout_ms` decreased shortly before onset | +3.0 |
| timeout in the error message equals the new config value | +1.5 |
| database latency unchanged | +1.0 |
| new value violates the documented invariant | +1.0 |
| database latency **increased** (points to a slow query instead) | −2.5 |

Scores are normalised with a softmax that includes a fixed "insufficient evidence" score, so weak
evidence produces low confidence instead of a confident guess. The LLM writes explanations and can
propose alternatives, but its citations are checked against real evidence ids and it cannot change scores.

## 6. Security model

* **Least privilege**: per-agent tool allow-lists enforced in the MCP gateway (`security/permissions.py`).
* **Human approval**: write tools require a single-use, HMAC-signed, run- and tool-bound token.
* **Untrusted content**: every tool result passes prompt-injection detection; offending sentences are
  replaced with a quarantine marker and logged; LLM prompts wrap tool output in `<untrusted_data>`.
* **Data protection**: PII (emails, Luhn-valid card numbers, phones) and secrets (API keys, AWS keys,
  DSN passwords, JWTs) are masked before any agent or LLM sees them; patches are secret-scanned.
* **SQL**: single SELECT/WITH only, table allow-list, no comments/PRAGMA/ATTACH, forced LIMIT,
  read-only connection (`mode=ro` + `query_only`), 5-second progress-handler timeout.
* **Sandbox**: repository code runs only in a detached worktree subprocess with a stripped
  environment and CPU / memory / file-size limits. Network isolation would need a container or nsjail.

## 7. The synthetic production world

`aegis/world/` generates a complete incident: a git monorepo with back-dated commits and deploy
tags, 24 h of logs / metrics / traces, a production read replica, and a documentation corpus.
Telemetry is produced by replaying synthetic traffic through the **same** `platform_sim` engine
that lives in the repo, against whichever revision was deployed at each minute — so stack traces
carry real line numbers, error messages carry the real config values, and a replay of recorded
traffic against a candidate fix is a faithful counterfactual.

Ten failure families × six services, with noise: red-herring deploys, deploys after the onset,
culprits bundled with harmless commits, decoy config changes, lost logs, missing or stale docs,
prompt injections in commits/docs/logs, and reporters naming the wrong version.

## 8. Honest limitations

* The benchmark is synthetic and the pattern catalogue was written alongside the generator; high
  accuracy here shows the pipeline works end to end, not that it generalises to real incidents.
  Real-world use needs a larger catalogue (or LLM-proposed hypotheses verified the same way).
* Offline runs use deterministic fallbacks for every LLM step, and token/cost figures are estimates.
  Run with `ANTHROPIC_API_KEY` set to measure real usage.
* Storage is SQLite; PostgreSQL/pgvector, Redis and OpenTelemetry export are natural next steps
  (the tracer already emits OTel spans when the SDK is installed).
