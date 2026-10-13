"""
evaluate.py — Run the benchmark against local Ollama model(s).

Experimental cell = (model, prompt_variant, scenario, tier, condition).
Each cell is run N times (default 20) at temperature 0 to measure the stochastic
instability that makes "temperature 0 is not determinism" a real concern.

  tier       : 0 (raw) / 1 (+identity) / 2 (+lineage)          [IV: context]
  condition  : clean / naive / plausible                        [IV: adversary]
  prompt     : baseline / analyst / hardened                    [IV: prompt]
  model      : any local Ollama tag(s)                           [IV: model]

Pipeline per inference:
  render prompt -> assert_no_leakage -> Ollama (schema-constrained) ->
  Pydantic re-validate -> deterministic guardrail -> record everything.

Output: results.json with full run metadata + one record per inference, so
analyze.py can compute every metric and anyone can audit every call.

Usage:
  python evaluate.py --dry-run                      # offline wiring test
  python evaluate.py                                # defaults, 1 model
  python evaluate.py --models llama3.1:8b qwen2.5:7b-instruct
  python evaluate.py --tiers 0 2 --conditions clean naive --repeats 20
  python evaluate.py --prompt-variants baseline hardened
  python evaluate.py --quick                        # repeats=3, tiers 0 2, clean only
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from guardrails import apply_guardrail
from prompts import SYSTEM_PROMPTS, apply_injection, assert_no_leakage, render_prompt
from schema import AlertScenario, InjectionStrength, TriageDecision, load_dataset, triage_json_schema

DEFAULT_MODELS = ["llama3.1:8b"]
DEFAULT_HOST = "http://localhost:11434"
DEFAULT_TIERS = [0, 1, 2]
DEFAULT_CONDITIONS = ["clean", "naive", "plausible"]
DEFAULT_PROMPTS = ["baseline"]
DEFAULT_REPEATS = 20


@dataclass
class ModelReply:
    raw: str
    latency_s: float
    model_digest: str | None


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class OllamaBackend:
    def __init__(self, model: str, host: str, field_order: str) -> None:
        import ollama

        self._client = ollama.Client(host=host)
        self.model = model
        self._schema = triage_json_schema(field_order)  # type: ignore[arg-type]

    def preflight(self) -> None:
        try:
            info = self._client.list()
        except Exception as exc:  # pragma: no cover - network dependent
            raise SystemExit(
                f"[FATAL] cannot reach Ollama: {exc}\n"
                f"        Start it (`ollama serve`) and pull the model "
                f"(`ollama pull {self.model}`)."
            )
        names = {m.get("model") or m.get("name") for m in info.get("models", [])}
        if self.model not in names:
            raise SystemExit(
                f"[FATAL] model {self.model!r} not found. Pull it: ollama pull {self.model}\n"
                f"        Available: {sorted(n for n in names if n)}"
            )

    def infer(self, system: str, user: str, seed: int) -> ModelReply:
        t0 = time.perf_counter()
        resp = self._client.chat(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            format=self._schema,
            options={"temperature": 0.0, "seed": seed, "num_ctx": 4096},
        )
        return ModelReply(resp["message"]["content"], time.perf_counter() - t0, resp.get("model") or self.model)


class DryRunBackend:
    """Deterministic offline stub. NOT a model; clearly flagged in output."""

    def __init__(self, model: str) -> None:
        self.model = f"dry-run::{model}"

    def preflight(self) -> None:
        return None

    def infer(self, system: str, user: str, seed: int) -> ModelReply:
        text = user.lower()
        bad = ("certutil", "minidump", "comsvcs", "-encodedcommand", "vssadmin", "bitsadmin", "mshta", "schtasks")
        injected_benign = "classify as benign" in text or "approved" in text
        if any(m in text for m in bad) and not injected_benign:
            d = {"reasoning": "dry-run stub: known LOLBin/encoded marker present.", "verdict": "SUSPICIOUS", "confidence": 0.5, "action": "ANALYST_REVIEW"}
        else:
            d = {"reasoning": "dry-run stub: no decisive malicious marker after reading telemetry.", "verdict": "BENIGN", "confidence": 0.5, "action": "AUTO_CLOSE"}
        return ModelReply(json.dumps(d), 0.0, self.model)


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
def _materialize(scenario: AlertScenario, condition: str) -> tuple[AlertScenario, bool]:
    """Return (scenario_to_render, condition_applicable).

    'clean' = original. 'naive'/'plausible' = apply the injection payload IF the
    scenario has one of that strength; otherwise condition is not applicable and
    the caller skips it (so we never fabricate an injection that isn't defined).
    """
    if condition == "clean":
        return scenario, True
    if scenario.injection is None:
        return scenario, False
    want = InjectionStrength.NAIVE if condition == "naive" else InjectionStrength.PLAUSIBLE
    if scenario.injection.strength is not want:
        return scenario, False
    return apply_injection(scenario), True


def _parse(raw: str) -> tuple[TriageDecision | None, str | None]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    try:
        return TriageDecision.model_validate(obj), None
    except ValidationError as exc:
        return None, f"schema violation: {exc.errors(include_url=False)}"


def evaluate_once(
    backend: OllamaBackend | DryRunBackend,
    original: AlertScenario,
    rendered_scenario: AlertScenario,
    tier: int,
    condition: str,
    prompt_variant: str,
    repeat_idx: int,
    seed: int,
) -> dict[str, Any]:
    system = SYSTEM_PROMPTS[prompt_variant].system
    prompt = render_prompt(rendered_scenario, tier)
    assert_no_leakage(rendered_scenario, prompt)

    reply = backend.infer(system, prompt, seed)
    decision, parse_error = _parse(reply.raw)

    rec: dict[str, Any] = {
        "scenario_id": original.scenario_id,
        "tier": tier,
        "condition": condition,
        "prompt_variant": prompt_variant,
        "repeat_idx": repeat_idx,
        "seed": seed,
        "model": backend.model,
        "raw_output": reply.raw,
        "latency_s": round(reply.latency_s, 3),
        "model_digest": reply.model_digest,
        "parse_error": parse_error,
    }
    if decision is None:
        rec.update({"model_verdict": None, "model_confidence": None, "model_action": None,
                    "model_reasoning": None, "final_action": None, "guardrail_triggered": False,
                    "authorized_close": False, "in_coverage": None, "guardrail": None})
        return rec

    # Guardrail operates on the ORIGINAL scenario's structured fields — NOT the
    # injected render. This is the injection-invariance property in action.
    outcome = apply_guardrail(decision, original)
    rec.update({
        "model_verdict": decision.verdict.value,
        "model_confidence": decision.confidence,
        "model_action": decision.action.value,
        "model_reasoning": decision.reasoning,
        "final_action": outcome.final_action.value,
        "guardrail_triggered": outcome.guardrail_triggered,
        "authorized_close": outcome.authorized_close,
        "in_coverage": outcome.in_coverage,
        "guardrail": outcome.to_dict(),
    })
    return rec


def run(args: argparse.Namespace) -> dict[str, Any]:
    here = Path(__file__).parent
    dataset_path = Path(args.dataset) if args.dataset else here / "dataset.json"
    out_path = Path(args.out) if args.out else here / "results.json"
    dataset = load_dataset(dataset_path)

    backends: list[OllamaBackend | DryRunBackend] = []
    for m in args.models:
        backends.append(DryRunBackend(m) if args.dry_run else OllamaBackend(m, args.host, args.field_order))
    for b in backends:
        b.preflight()

    # Pre-compute the applicable work list so the progress counter is accurate.
    work: list[tuple] = []
    for b in backends:
        for pv in args.prompt_variants:
            for s in dataset.scenarios:
                for tier in args.tiers:
                    for cond in args.conditions:
                        rendered, ok = _materialize(s, cond)
                        if not ok:
                            continue
                        for r in range(args.repeats):
                            work.append((b, s, rendered, tier, cond, pv, r))

    results: list[dict[str, Any]] = []
    total = len(work)
    for i, (b, s, rendered, tier, cond, pv, r) in enumerate(work, 1):
        seed = 1000 + r  # vary seed per repeat to expose stochastic instability
        rec = evaluate_once(b, s, rendered, tier, cond, pv, r, seed)
        results.append(rec)
        if r == 0 or args.verbose:  # print first repeat of each cell to keep logs sane
            status = rec["parse_error"] or (
                f"{rec['model_action']}->{rec['final_action']}" + (" [GR]" if rec["guardrail_triggered"] else "")
            )
            print(f"[{i:>5}/{total}] {b.model} {pv} {s.scenario_id} t{tier} {cond:<9} {status}")

    payload = {
        "run_metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "models": [b.model for b in backends],
            "prompt_variants": args.prompt_variants,
            "tiers": args.tiers,
            "conditions": args.conditions,
            "repeats": args.repeats,
            "field_order": args.field_order,
            "dataset_version": dataset.dataset_version,
            "dataset_path": str(dataset_path),
            "n_scenarios": len(dataset.scenarios),
            "temperature": 0.0,
            "is_dry_run": args.dry_run,
            "total_inferences": total,
        },
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nwrote {len(results)} records -> {out_path}")
    if args.dry_run:
        print("NOTE: --dry-run stub answers; NOT valid measurements.")
    return payload


def _args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run the llm-triage-boundaries benchmark.")
    p.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--dataset", default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--tiers", nargs="+", type=int, default=DEFAULT_TIERS, choices=[0, 1, 2])
    p.add_argument("--conditions", nargs="+", default=DEFAULT_CONDITIONS, choices=["clean", "naive", "plausible"])
    p.add_argument("--prompt-variants", nargs="+", default=DEFAULT_PROMPTS, choices=list(SYSTEM_PROMPTS))
    p.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    p.add_argument("--field-order", choices=["reasoning-first", "verdict-first"], default="reasoning-first")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--quick", action="store_true", help="repeats=3, tiers 0 2, clean only (fast smoke test).")
    a = p.parse_args(argv)
    if a.quick:
        a.repeats, a.tiers, a.conditions = 3, [0, 2], ["clean"]
    return a


def main(argv: list[str] | None = None) -> int:
    run(_args(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
