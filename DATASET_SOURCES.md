# Dataset Sources & Why This Corpus Is Hand-Constructed

A reviewer will ask: *"Why build your own dataset instead of using a public one
from GitHub?"* This document is the answer, written so it can be defended on stage.

## Short answer

Attacker **behaviors** and technique **classifications** are derived from public,
permissively-licensed sources and cited per scenario. The **benchmark
construction** — context separated into tiers, a *triage-disposition* ground
truth, counterfactual twins, and adversarial injection variants — is original,
because **no public dataset provides those**.

## What each public source gives us (and its limit)

| Source | License | Provides | Why it is not plug-and-play here |
|---|---|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MIT | Canonical attacker command lines per ATT&CK technique | No benign cases, no tiered context, no triage-disposition labels |
| [MITRE ATT&CK](https://attack.mitre.org/) | ATT&CK Terms of Use | Technique IDs + descriptions | Labels *techniques*, not whether a specific instance is safe to auto-close |
| [LOLBAS](https://lolbas-project.github.io/) | project GPL-3.0 (behaviors are public facts) | Living-off-the-land binary behaviors | A catalog, not a dataset |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | (public samples) | Real malicious Windows event logs | Raw EVTX; no benign/ambiguous split; no tiering |
| [OTRF Security-Datasets / Mordor](https://github.com/OTRF/Security-Datasets) | GPL-3.0 | Recorded attack + some normal telemetry | Technique-labeled, not triage-labeled; no twins |

## What our experiment requires that none of the above ship

1. **Context split into Tiers 0/1/2** — this tiering *is* the independent variable.
2. **A triage-disposition ground truth** (`safe_to_auto_close`), not a technique label.
3. **Counterfactual twins** — identical Tier-0 telemetry, opposite disposition.
4. **Adversarial injection variants** attached to specific scenarios.

Items 3 and 4 do not exist in any public corpus; they are the original
contribution. Item 1–2 would require re-annotating any imported record anyway.

## Provenance in the data

Every scenario carries:
- `references`: the public URL(s) the behavior/technique is drawn from.
- `label_source`: an enum recording how the ground-truth label was derived
  (`ATOMIC_RED_TEAM`, `MITRE_ATTACK`, `LOLBAS`, `VENDOR_DOC`, or
  `AUTHOR_JUDGEMENT`). Genuinely ambiguous twin cases are honestly flagged
  `AUTHOR_JUDGEMENT`; malicious cases inherit external provenance (enforced by
  `tests/test_dataset.py::test_malicious_cases_cite_attack_sources`).

## Scaling path (future work)

A `build_dataset.py` generator can scaffold scenarios directly from a list of
Atomic Red Team technique IDs, baking provenance in and allowing growth to 50+
scenarios without hand-writing each. This is noted as future work; the pilot
corpus here is 24 scenarios (8 benign / 8 malicious / 8 ambiguous incl. 4 twin
pairs).

## Legal / ethics

No proprietary, confidential, customer, or employer data is used. All hostnames,
usernames, IPs, domains, and code signers are fictional. Code is MIT; the dataset
is CC-BY-4.0. See [`LICENSE`](LICENSE).
