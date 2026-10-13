# Conference CFP Submission Draft

Paste-ready for Sessionize (DefCamp 2026 Wave 3) and adaptable for NullCon
Bengaluru chapter. Fill the GitHub URL in Notes once the repo is public.
**Do not present measured numbers you have not actually run** — submit the
abstract on the methodology (it is a benchmark + pilot), add results to the
slides after you run it.

---

## Session Title (primary)

**The LLM Recommends, The Policy Authorizes: Measuring the Safety Boundary of
Autonomous LLM SOC Triage Under Context and Adversarial Telemetry**

### Alternatives
1. When Should an AI Close a Security Alert? An Open Benchmark for Context,
   Injection, and Deterministic Authorization in LLM Triage
2. Enrichment Is an Attack Surface: Why LLM SOC Triage Needs a Structured
   Authorization Boundary
3. Auto-Close Is a Policy, Not a Prediction: A Reproducible Study of LLM Triage
   Safety Boundaries

---

## Track
Cyber-Operations, AI & Emerging Technologies — sub-track **AI in SOCs**
(secondary: **LLM Security**).

## Format
30-minute in-person technical talk. Live demo runs fully offline (no network).

## Target Audience & Level
**Intermediate / Level 300.** SOC analysts, detection engineers, SOAR/automation
engineers, blue-team leads evaluating LLM-assisted triage. Comfort with alert
telemetry, process lineage, and MITRE ATT&CK assumed; no ML background required.

---

## Abstract (~230 words)

SOC automation vendors increasingly promise LLMs that read alerts and auto-close
the noise. This talk asks the engineering question underneath that promise — when,
if ever, is a probabilistic model's recommendation safe enough to authorize
autonomous closure — and answers it with an open, reproducible benchmark instead
of a demo.

Every alert is evaluated across a context ladder (raw telemetry → identity →
process lineage) by local open models, each decision repeated many times to
measure stochastic instability, with the only metric that matters in a SOC: the
rate at which the pipeline auto-closes an alert that was actually malicious,
reported with confidence intervals. A counterfactual control — pairs of alerts
with identical surface telemetry but opposite truth — proves the corpus genuinely
requires context rather than rewarding surface features.

The second half turns the attacker loose. Because enrichment feeds attacker-
controlled text to the model, we measure whether injected telemetry can flip the
model toward closure — and show that a deterministic authorization layer reading
only structured, sensor-attributed signals is invariant to that injection, by
construction and by exhaustive test. The resulting architecture is explicit: the
LLM ranks and explains; a deterministic policy authorizes what may close.

This is a pilot on a public, vendor-neutral corpus with honest limitations; the
contribution is the measurement method and the open tooling anyone can rerun.

---

## Detailed Technical Outline (30 min, minute-by-minute)

**1. The promise and the trap (0:00–4:00)**
- The vendor pitch; why analysts distrust auto-close.
- Reframe: this is a measurable engineering question. The spine: *recommends vs authorizes.*
- Why accuracy is the wrong metric; define unsafe-auto-close rate + asymmetric cost.

**2. The benchmark harness (4:00–10:00)**
- Output contract (schema-constrained + re-validated).
- Context ladder (Tier 0/1/2) as the independent variable.
- The leakage guarantee + the CI test that enforces it (pre-empts "you fed it the answer").
- Live: run the harness.

**3. Context results + the counterfactual control (10:00–16:00)**
- Twin pairs: identical Tier-0, opposite truth — a *control* proving the test is fair.
- Context-ladder unsafe-auto-close rate with CIs and the paired test (Q1).
- The uncomfortable result: residual unsafe closures persist at full context (Q2) — or the honest null.

**4. Attacker view: enrichment as attack surface (16:00–23:00)**
- Threat model: what the attacker controls (command text) vs. not (sensor lineage).
- Injection results: ASR for naïve and plausible payloads; model-dependence (Q3).

**5. The authorizer + the safety property (23:00–30:00)**
- Strong invariant (final==AUTO_CLOSE ⇒ model asked + no hard signal), exhaustively tested.
- Injection invariance: the authorizer ignores free text → same decision under attack (Q4).
- Containment + the honest coverage gap; baselines (rules vs LLM vs full).
- Limitations (n, single-host, single-alert, feature conditioning); takeaway + GitHub link; Q&A.

---

## Notes to the Review Committee

This is **independent practitioner research**, built from scratch on personal
hardware using only open-source tooling (Ollama, local open models, Pydantic,
pytest) and **public data** (MITRE ATT&CK, Atomic Red Team, LOLBAS), cited per
scenario. There is **no proprietary, confidential, customer, or employer data,
tooling, or methodology** anywhere — no vendor product names, no internal
playbooks, no private telemetry.

It is deliberately falsifiable. It states hypotheses up front (including a
pre-committed position if the result is null), leads with the only metric that
matters operationally (unsafe-auto-close rate, with confidence intervals and a
paired test), and ships the code, dataset, and tests so anyone can rerun it. The
distinctive contributions are (1) a counterfactual control that proves the corpus
requires context, (2) a measured link between context enrichment and the
prompt-injection attack surface it opens, and (3) a deterministic authorization
layer that is provably (by exhaustive enumeration over a finite space) monotonic
and invariant to telemetry injection — with its coverage gap reported honestly.

I present the work as a **benchmark + pilot**, not a universal claim: results are
scoped to the evaluated open models and a 24-scenario public corpus, and I say so.
The architecture conclusion — the LLM ranks and explains, a deterministic policy
authorizes closure — is the practical takeaway for any team weighing autonomous
SOC disposition.

I can present entirely offline; the demo has no network dependency.

**Planned open-source release:** `https://github.com/<your-username>/llm-triage-boundaries`
(MIT code + CC-BY-4.0 dataset, full reproduction instructions and CI).

---

## Speaker logistics
- In-person: yes; demo fully offline.
- AV: laptop (HDMI/USB-C), terminal + slides; no internet required.
- Attach: GitHub link + a 2-minute asciinema of `evaluate.py` + `analyze.py`.
