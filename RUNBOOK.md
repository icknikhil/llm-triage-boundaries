# RUNBOOK — exactly what to do on your personal laptop

Goal: go from a fresh HP Victus (Windows 11) to real, defensible numbers and a
submittable CFP. Follow top to bottom. Times are rough on a laptop GPU.

---

## PHASE -1 — Clean removal of old Ollama / AnythingLLM (~10 min, optional)

AnythingLLM is NOT needed for this project. Ollama only needs to be >= 0.5.0
(an in-place upgrade also works; a clean removal is the no-surprises path).

1. Quit Ollama: right-click the llama icon in the system tray → **Quit Ollama**.
   Quit AnythingLLM if it's open.
2. **Settings → Apps → Installed apps** → uninstall **Ollama** and **AnythingLLM**.
3. Delete leftover data (models can be many GB) in PowerShell:
```powershell
Get-Process ollama*, AnythingLLM* -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force "$env:USERPROFILE\.ollama", "$env:LOCALAPPDATA\Ollama", "$env:LOCALAPPDATA\Programs\Ollama", "$env:APPDATA\anythingllm-desktop", "$env:LOCALAPPDATA\Programs\anythingllm-desktop" -ErrorAction SilentlyContinue
[Environment]::GetEnvironmentVariable("OLLAMA_MODELS","User")   # if this prints a path, delete that folder too, then:
[Environment]::SetEnvironmentVariable("OLLAMA_MODELS",$null,"User")
[Environment]::SetEnvironmentVariable("OLLAMA_HOST",$null,"User")
```
4. Reboot, then check that `ollama --version` returns "not recognized".

## PHASE 0 — One-time install (~20 min)

1. **Python 3.11** — https://www.python.org/downloads/release/python-3119/
   → tick **"Add python.exe to PATH"** during install.
2. **Ollama** — https://ollama.com/download (Windows installer; runs as a service).
3. **Git** — https://git-scm.com/download/win (for publishing later).

Verify in a NEW PowerShell window:
```powershell
python --version      # 3.11.x
ollama --version
```

## PHASE 1 — Get the model(s) (~10 min, downloads ~5–9 GB)
```powershell
ollama pull llama3.1:8b
ollama pull qwen2.5:7b-instruct     # recommended 2nd model (makes the result about LLMs, not one model)
ollama list                         # confirm both appear
```
Note: the old tag `llama3:8b-instruct` no longer exists in the Ollama registry
(verified 2026-10-13). `llama3.1:8b` is the instruct/chat build (~4.9 GB, 4-bit),
fits an 6–8 GB laptop GPU, and is the code default. If a pull ever fails,
`llama3:8b` is a valid fallback — pass the exact tag via `--models`.
Check the server: open http://localhost:11434 in a browser → "Ollama is running".

## PHASE 2 — Project setup (~3 min)
```powershell
cd path\to\llm-triage-boundaries
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```
If activation is blocked once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` then retry.

## PHASE 3 — Prove methodology WITHOUT the model (~1 min) ← screenshot this
```powershell
python schema.py        # "OK 24 scenarios | 4 twin pairs | ..." = corpus valid
python guardrails.py    # structured-signal table per scenario
python prompts.py       # renders prompts + passes the leakage check
pytest                  # ALL GREEN = leakage guarantee + strong invariant + injection invariance proven
```
**If pytest is green, your research is methodologically sound before the LLM runs.**
Screenshot the green run for the talk ("even the safety layer is unit-tested").

## PHASE 4 — Offline wiring test (~1 min)
```powershell
python evaluate.py --dry-run --quick
python analyze.py
```
Confirms the full pipeline + report work. Output is flagged DRY-RUN (not real data).

## PHASE 5 — Real smoke test (~5–15 min)
```powershell
python evaluate.py --quick          # repeats=3, tiers 0 & 2, clean only
python analyze.py
```
Read the HEADLINE block. Sanity-check: malicious cases should mostly NOT end in
AUTO_CLOSE after the guardrail.

## PHASE 6 — The real run (overnight; start before bed)
Submission-ready subset (faster, ~1–2 hrs):
```powershell
python evaluate.py --models llama3.1:8b qwen2.5:7b-instruct --tiers 0 1 2 --conditions clean naive --repeats 20
```
Full matrix (add plausible injection + 2nd prompt; many hours):
```powershell
python evaluate.py --models llama3.1:8b qwen2.5:7b-instruct --prompt-variants baseline hardened --repeats 20
```
Then:
```powershell
python analyze.py --model llama3.1:8b
python analyze.py --model qwen2.5:7b-instruct
```

## PHASE 7 — Record hardware for reproducibility
Note in your slides/README: CPU, RAM, exact GPU + VRAM, Ollama version
(`ollama --version`), model tags, and total runtime printed by `evaluate.py`.

## PHASE 8 — Publish
```powershell
git init
git add .
git commit -m "llm-triage-boundaries v2: benchmark + pilot"
```
Create a public GitHub repo named `llm-triage-boundaries`, push, and paste the URL
into [`CFP_DefCamp_2026.md`](CFP_DefCamp_2026.md) (Notes section). Optional: a
2-minute asciinema of phases 3 + 6.

## PHASE 9 — Submit
Paste each section of [`CFP_DefCamp_2026.md`](CFP_DefCamp_2026.md) into Sessionize
(DefCamp) and/or the NullCon Bengaluru chapter form. Submit the ABSTRACT on the
methodology now; finish slides after the overnight run.

---

## If something breaks
- `ollama` not reachable → make sure the service is running; `ollama run llama3.1:8b` once.
- model not found → re-run the `ollama pull`.
- `pytest` import errors → ensure you're in the `.venv` and ran `pip install -r requirements-dev.txt`.
- JSON/schema error from `schema.py` → the dataset has a defect; the error names the field.

## Fallback plan (if you run out of time)
Submit the abstract tonight (it stands on the methodology). Run PHASE 6 later,
drop the numbers into the slides, and do the talk with real data. The abstract
does not claim results, so this is honest.
