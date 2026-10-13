# Related Work & Positioning

This exists to prevent the "nobody has done this" trap. We do **not** claim
novelty by absence. We claim a specific, narrow gap. Replace the bracketed notes
with your own reading before submission — treat this as a checklist, not a
finished survey.

## Honest framing (use this wording)

> "I did not find an **open, reproducible evaluation framework** that measures
> this specific safety boundary — LLM SOC-triage *disposition* under a context
> ladder, adversarial telemetry injection, and a deterministic authorization
> layer with a tested invariant — on local open models with public data. Prior
> work touches individual pieces; this benchmark composes them and ships the
> tooling."

## Areas to cite (and what each establishes vs. what remains open)

1. **LLMs in security operations / alert triage**
   - Vendor and practitioner write-ups on LLM-assisted triage.
   - *Open gap:* most are capability demos, not safety-boundary measurements with
     an asymmetric-cost metric and CIs.

2. **Prompt injection / indirect prompt injection**
   - Greshake et al. (indirect prompt injection); OWASP Top 10 for LLM
     Applications (LLM01 Prompt Injection).
   - *Our angle:* injection via *telemetry the attacker already controls* in a
     SOC pipeline, and a structured authorizer that is invariant to it.

3. **Structured output / constrained decoding**
   - Grammar/JSON-schema-constrained decoding (e.g. Ollama `format=`).
   - *Our use:* we constrain output AND re-validate — "the server promised" is
     not a control.

4. **Human-in-the-loop / policy gating as a safety pattern**
   - Known from access control, autonomous systems, medical AI.
   - *Our contribution is not the pattern* — it is *measuring* where the LLM adds
     value in a SOC while the deterministic layer holds closure authority, with
     the injection-invariance property made explicit and tested.

5. **Confidence calibration of LLMs**
   - Literature on poorly-calibrated self-reported confidence.
   - *Consequence for us:* we treat self-reported confidence cautiously and lead
     with the action-level unsafe-auto-close rate, not confidence.

6. **Counterfactual / minimal-pair evaluation**
   - Minimal-pair and counterfactual testing in NLP.
   - *Our use:* twins as a CONTROL proving the corpus requires context, not as
     the headline finding.

## What we explicitly do NOT claim

- We do not claim to be the first to observe that context helps triage.
- We do not claim LLMs "cannot" triage — results are scoped to evaluated models.
- We do not claim prompt injection is novel — the novel part is the SOC-telemetry
  threat model + the injection-invariant structured authorizer.

## TODO before submission
- [ ] Add 3–5 concrete citations with links for areas 1–3.
- [ ] One sentence each on how this work differs from each citation.
