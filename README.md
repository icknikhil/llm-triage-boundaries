# llm-triage-boundaries

**An open, reproducible benchmark for the safety boundary of autonomous LLM SOC
triage.** It measures where context helps, where it stops helping, where an
attacker can manipulate the model through telemetry, and why a deterministic
authorization layer — not the LLM — must hold the authority to auto-close alerts.

> **The LLM recommends. The deterministic policy authorizes.**

100% local, vendor-neutral. Runs on a laptop with [Ollama](https://ollama.com)
and open models. No API keys, no cloud, no proprietary data.

---

## What this is, in plain English

SOC vendors increasingly promise "let the AI read alerts and auto-close the
noise." This project tests that promise like an engineer instead of trusting a
demo. It asks one question: **when, if ever, is a probabilistic model's
recommendation safe enough to authorize autonomous closure of a security
alert — and does the context that makes the model more useful also hand the
attacker a way in?**

---

## Status: pilot + tooling (read this first)

This repository is a **reproducible benchmark and a pilot study**, not a
finished large-n result. We separate claims honestly:

- **DEMONSTRATED (code + tests):** the harness, the 24-scenario corpus, the
  deterministic authorizer with a tested strong invariant + injection
  invariance, the leakage guarantee, and the statistics (Wilson CIs, paired
  McNemar).
- **PLANNED (run it to fill in):** the measured numbers across context tiers,
  models, prompts, and injection conditions. You produce these by running
  `evaluate.py` + `analyze.py` on your hardware.
- **FUTURE WORK (explicitly out of scope):** LLM usefulness/ranking quality,
  human-in-the-loop simulation, dataset scale to 50+.

The full design is in [`RESEARCH_DESIGN.md`](RESEARCH_DESIGN.md); the attacker
model is in [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## The four questions

| | Question | How it's measured |
|---|---|---|
| **Q1** | Does context improve triage? | unsafe-auto-close rate across Tier 0→1→2, paired McNemar |
| **Q2** | Does context *stop* eliminating dangerous errors? | residual LLM-alone unsafe-auto-close at full context (H2) |
| **Q3** | Can adversarial telemetry manipulate the LLM? | Attack Success Rate: injected vs clean, same scenarios |
| **Q4** | Can a deterministic layer preserve safety the LLM can't? | authorizer injection-invariance (H4) + containment (H5) |

---

## Architecture

```
            ┌──────────────────────┐
            │   Security Alert     │
            └──────────┬───────────┘
                       ↓
            ┌──────────────────────┐
            │ Context Enrichment   │  Tier 1 identity · Tier 2 lineage/prevalence
            │  (attacker-influenced│  <-- enrichment is also an ATTACK SURFACE
            │   free text)         │
            └──────────┬───────────┘
                       ↓
            ┌──────────────────────┐
            │      LLM Triage      │  RECOMMENDS verdict+confidence+action+reason
            │   (probabilistic)    │  (advisory only; reads attacker-controlled text)
            └──────────┬───────────┘
                       ↓
            ┌──────────────────────┐
            │ Deterministic Policy │  AUTHORIZES. Reads STRUCTURED signals only.
            │  (SAFETY BOUNDARY)   │  Monotonic + injection-invariant (tested).
            └──────────┬───────────┘
                       ↓
          AUTO_CLOSE  |  ANALYST_REVIEW  |  ESCALATE
```

Key property (tested in [`tests/test_guardrails.py`](tests/test_guardrails.py)):
```
final == AUTO_CLOSE  ==>  the model proposed AUTO_CLOSE
                          AND no hard structured signal fired
                          AND the verdict was not CRITICAL
```
verified by **exhaustive enumeration** of the finite decision space (this is
exhaustive testing over a finite domain, not a formal proof — stated honestly),
plus **injection invariance**: the authorizer output is identical with or without
an injection payload, because it never reads the attacker-controlled free text.

---

## Metrics (why not accuracy)

SOC error classes are asymmetric — see [`metrics.py`](metrics.py):

| Ground truth | Final action | Cost |
|---|---|---|
| safe-to-close | AUTO_CLOSE | 0 |
| safe-to-close | REVIEW/ESCALATE | low (analyst time) |
| unsafe-to-close | REVIEW/ESCALATE | 0 |
| **unsafe-to-close** | **AUTO_CLOSE** | **catastrophic** |

Primary metric = **unsafe-auto-close rate** with a 95% Wilson CI. Tier
comparisons use the **paired** McNemar test (the same scenarios appear across
tiers, so they are not independent). Expected cost folds in the asymmetry.

---

## Reproduce locally

### Prerequisites
- Python **3.11** (3.10–3.13 ok)
- [Ollama](https://ollama.com) **≥ 0.5.0** running
- One or more local models pulled

### Steps (Windows PowerShell; identical elsewhere)
```powershell
ollama pull llama3.1:8b
ollama pull qwen2.5:7b-instruct      # optional 2nd model (recommended)

python -m venv .venv
.\.venv\Scripts\Activate.ps1          # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt

# 1. No-model sanity (validates corpus + authorizer + leakage + stats)
python schema.py
python guardrails.py
python prompts.py
pytest                                # all green = methodology is sound

# 2. Offline wiring test (no Ollama)
python evaluate.py --dry-run --quick
python analyze.py

# 3. Real run — smoke first, then full
python evaluate.py --quick            # repeats=3, tiers 0&2, clean only (~minutes)
python analyze.py

python evaluate.py --models llama3.1:8b qwen2.5:7b-instruct   # full matrix (overnight)
python analyze.py --model llama3.1:8b
python analyze.py --model qwen2.5:7b-instruct
```

Or use the `Makefile`: `make setup`, `make test`, `make smoke`, `make run`, `make analyze`.

### Runtime warning
The full matrix (24 scenarios × 3 tiers × 3 conditions × N models × prompts ×
20 repeats) is thousands of inferences — run it overnight. For a submission-ready
subset: `python evaluate.py --tiers 0 2 --conditions clean naive --repeats 20`.

---

## What you get

`analyze.py` prints: the headline unsafe-auto-close rate per tier with CIs (Q1/Q2),
guardrail containment + coverage gap (H5), injection ASR + authorizer invariance
(Q3/Q4), answer stability across repeats, baselines (rules-only / LLM-T0 / LLM-T2
/ full), expected cost, and the counterfactual twin control.

---

## Takeaways for SOC engineering teams

1. **Auto-close is a policy decision, not a model capability.** Let the LLM rank
   and explain; let a deterministic policy decide what may close.
2. **Enrichment is also an attack surface.** The telemetry that helps the model is
   attacker-influenced; a structured authorizer that ignores free text is the
   layer that stays safe under injection.
3. **A probabilistic component should not hold irreversible authority.** The
   authorizer here can only ever make a decision safer, and is injection-invariant
   by construction.
4. **Report the number that matters.** Unsafe-auto-close rate with intervals, not
   accuracy.

---

## Repository layout

```
llm-triage-boundaries/
├── schema.py              data contracts (tiers, output, injection, provenance, invariants)
├── dataset.json           24 cited scenarios (8/8/8, 4 twin pairs, 2 injection cases)
├── guardrails.py          deterministic authorizer: strong invariant + injection invariance
├── prompts.py             tier renderers, frozen prompt variants, injection rendering, leakage guard
├── metrics.py             Wilson CI, paired McNemar, asymmetric cost (stdlib only)
├── evaluate.py            N-run runner across tier × condition × model × prompt -> results.json
├── analyze.py             metrics + tables (tabulate)
├── prompts/               version-controlled frozen prompt text
├── tests/                 leakage, strong-invariant (exhaustive), injection-invariance, dataset, metrics
├── RESEARCH_DESIGN.md     question, hypotheses, variables, metrics, title, abstract, slides
├── THREAT_MODEL.md        attacker capabilities and what we can/cannot claim
├── DATASET_SOURCES.md     why the corpus is hand-constructed from public sources
├── LITERATURE.md          related-work positioning (avoids 'nobody published')
├── RUNBOOK.md             step-by-step execution on your laptop
├── CFP_DefCamp_2026.md    paste-ready conference submission
├── Makefile               one-command runners
└── LICENSE                MIT (code) + CC-BY-4.0 (dataset) + attribution
```

## Data & ethics
Attacker behaviors are public facts cited per scenario (MITRE ATT&CK, Atomic Red
Team, LOLBAS); benign behaviors from official docs. All hosts/users/IPs/domains/
signers are fictional. No proprietary, customer, or employer data anywhere.
See [`DATASET_SOURCES.md`](DATASET_SOURCES.md) and [`LICENSE`](LICENSE).
