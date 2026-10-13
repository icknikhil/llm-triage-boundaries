# Frozen prompt variants

These are the exact system prompts used in the experiment, version-controlled so
a reviewer can confirm the result is not an artifact of one hand-tuned prompt.

| file | variant name | purpose |
|---|---|---|
| `baseline.txt` | `baseline` | terse/neutral control |
| `analyst.txt` | `analyst` | analyst-persona framing (semantically equivalent task) |
| `hardened.txt` | `hardened` | explicit injection-defense instruction (measures a defense) |

**Rule:** prompts are frozen BEFORE any run. If wording changes after seeing
results, it becomes a NEW named variant — we never silently retune. The canonical
copies live in [`prompts.py`](../prompts.py); these `.txt` files are the
human-readable, diffable record and must be kept identical to the code.
