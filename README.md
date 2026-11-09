# Sentinela Risk Lab

**Deterministic, offline player-behavior and risk analytics for betting operations, from CSV files. No AI in the analysis. Encrypted at rest, zero traces by design.**

> Built while contracted by an iGaming operator; brand names, data and figures removed.
> Built with Claude Code as a pair programmer.

**Stack:** Python 3.10–3.14, DuckDB (exact `DECIMAL` money math), Jinja2 (HTML report), WeasyPrint (PDF, optional),
`cryptography` (AES-256-GCM vault, scrypt key derivation, HMAC-SHA256 keyed pseudonyms), PyYAML (rules, contracts, studies).
**AI used:** none in the analysis. Every number comes from a fixed, hashed pipeline. Claude Code was used only as a development pair programmer.
**Data:** none included. The only data is produced in RAM by `sentinela/synthetic.py` (fictional providers, games, affiliates, seeded RNG).

Sentinela is a rebuild, for secured environments, of an earlier LLM-agent prototype ("Risk Squad") built for an iGaming operator:

| Risk Squad (original prototype) | Sentinela Risk Lab |
|---|---|
| Data via PostgreSQL MCP | Data via **CSV files** checked by **contracts** |
| LLM agents orchestrate and interpret | **CLI + study file** (YAML); fixed pipeline |
| Max 500 rows per query reach the agents | **Whole population** processed locally (DuckDB) |
| Player "risk" = ranking by \|GGR\| | **8 statistical/behavioural flags**, weighted score, tiers |
| Games section double-counted turnover | Per-game metrics from the game itself + **reconciliation proves it** |
| Payments/CRM: only JSON field lists | Deposits, withdrawals, approval, FTD, KYC, conversion |
| No behavior view | **Player behavior module**: 40+ features per player, lifecycle, value tiers, segments, cohorts, retention, deposit rhythm, all defined in an editable YAML |
| Prefix masking (`play***7890`) | **Keyed hash pseudonyms**, reversible only on this machine |
| Not reproducible (default "today − 30d") | Explicit period + **Run ID**: same inputs → byte-identical numbers |
| Needs cloud LLM + network | **Runs fully air-gapped** (dependencies bundled) |
| Files and reports in plaintext | **AES-256-GCM vault**: sanitizing ingestion, analysis only in RAM, encrypted reports, trace cleaning (see `docs/SECURITY.md`) |

The report (HTML/PDF) and CLI messages are in **pt-BR**, following the original report structure.

---

## 1. Install on Ubuntu (offline)

Requirements: Ubuntu 22.04 / 24.04 / 25.x / 26.04 on **x86_64**, installed with **full-disk encryption (LUKS)**, with `python3` (already included in Ubuntu).
No internet is needed once `wheelhouse/` is populated. **The public repository does not ship the wheel binaries (~116 MB)**: build them once on a machine with internet (`scripts/build-wheelhouse.sh`), then verify them with `cd wheelhouse && sha256sum -c SHA256SUMS.txt` (the reference hashes of the tested wheel set are committed). Without a wheelhouse, use `./install.sh --online`.

```bash
# 0) (recommended) verify the package arrived intact
cd sentinela-risk-lab
sha256sum -c SHA256SUMS.txt --quiet && echo "integrity OK"

# 1) install (creates ./.venv, never touches system Python, runs the self-test)
./install.sh

# 2) PDF support — WeasyPrint needs these system libraries (usually present on Ubuntu Desktop):
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b
#    without them you still get HTML + JSON + CSV (or PDF through Chromium if installed)

# 3) activate
source .venv/bin/activate
sentinela --version
```

Installer flags: `--no-pdf` (skip WeasyPrint) · `--online` (use PyPI instead of `wheelhouse/`) · `--no-tests`.
ARM64 machine? On a computer with internet run `ARCH=aarch64 scripts/build-wheelhouse.sh`, then copy the folder.

## 2. Create the encrypted keyring (once)

```bash
sentinela init            # asks a passphrase (≥ 12 chars) twice. There is NO recovery: keep it safe.
sentinela doctor          # checks LUKS, swap, tmpfs, network, leftovers… fix every FALHA
```

## 3. Prove the engine first (synthetic data)

```bash
sentinela demo
sentinela view --open     # decrypts the report into RAM and opens it (use a private browser window)
```

This generates a hypothetical operation in RAM (≈2.8k players, Jan–May 2026 history, analysed period May 2026)
with **planted anomalies**: bonus abusers, big winners, deposit→withdraw without play, whales, a game paying
above 100% RTP and a bad affiliate. The data goes through the same ingestion as real files and the full study
runs. The report shows that the engine finds them.

## 4. Run your own study

```bash
# the ONLY way in: cleans personal data, encrypts into the vault, erases the original and its desktop traces
 sentinela ingest ~/Downloads/export_cassino.csv --dataset activity    # leading space = not saved in history
 sentinela ingest ~/Downloads/pagamentos.csv --dataset payments --delimiter ";"
sentinela vault                                  # what is in the vault (labels, rows, PII removed)

sentinela new-study studies/june.yaml --title "Estudo Hipotético — Junho 2026"
nano studies/june.yaml                           # period + inputs: {vault: latest | <label>} (+ column_map)
sentinela validate studies/june.yaml             # contracts + behavior rules, nothing is computed
sentinela run studies/june.yaml                  # analysis in RAM → encrypted report in the vault
sentinela view --open                            # read it
sentinela export <run> --to ~/share --only pdf   # only when a plaintext copy must leave the machine
sentinela clean --traces --apply                 # wipe RAM views, shell history and recent-files traces
```

Inside the encrypted report bundle:

| File | Content |
|---|---|
| `relatorio.html` / `relatorio.pdf` | Report: executive summary, critical readings, thematic sections, data quality, glossary, methodology (PDF without metadata) |
| `relatorio.evidence.json` | **Audit trail**: every number, every parameter, content hashes, Run ID |
| `tables/*.csv` | All tables, including `player_profile.csv` and `segments/*.csv` |

## 5. Commands

| Command | What it does |
|---|---|
| `sentinela init` / `passwd` | create the encrypted keyring / change the passphrase |
| `sentinela ingest FILE --dataset X` | **only way in**: sanitize → encrypt → erase original and traces |
| `sentinela vault` / `runs` | list encrypted datasets / reports (`rm` to securely delete) |
| `sentinela view [RUN] [--open]` / `export RUN --to DIR` | read a report in RAM / explicit plaintext copy |
| `sentinela doctor` / `clean [--traces] [--apply]` | check the Linux environment / wipe RAM areas, plaintext and traces |
| `sentinela demo [--players N --seed S]` | synthetic data (in RAM) → vault → full run |
| `sentinela new-study PATH --title T` | create a study file from the template |
| `sentinela inspect CSV --dataset activity\|games\|payments\|clients` | header → contract mapping, missing columns |
| `sentinela validate STUDY` | validate all CSVs against the contracts |
| `sentinela run STUDY [--formats html,pdf,json,csv] [--strict]` | full pipeline (`--strict`: exit 1 if a reconciliation fails) |
| `sentinela features` | list the player features you can use in behavior rules |
| `sentinela export-segment STUDY SEG [--group tratamento] [--reveal]` | campaign list for a segment; `--reveal` adds real IDs (local file, mode 600) |
| `sentinela lookup STUDY P-xxxxxxxx…` | turn pseudonyms back into real IDs (**local only**, uses the key) |
| `sentinela contracts [--json]` | print the CSV contracts |

## 6. How precise is it?

Measured on 10 independent synthetic datasets (2,500 players each, seeds 1–5, 7, 42, 99, 123, 2026):

| Target | Result |
|---|---|
| Planted risk players (bonus abuse, big winners, AML cash-out), recall | **40/40 in every dataset (100%)** |
| Precision of the "flagged" list (score ≥ 3) | 83–93% (the extra flags are real statistical outliers of the simulation) |
| Broken game (−12% hold) | 8 alerts + 2 watch-list; **0 alerts on 320 honest-game tests** |
| Bad affiliate (planted abusers) | detected 10/10 |
| Reconciliation (Σ providers = Σ btags = Σ players = Σ days = total) | exact, to the cent |
| Same data on DuckDB 2.0 (Py 3.12) vs DuckDB 1.5.6 (Py 3.10) | **byte-identical evidence** |
| Behavior: lifecycle / tiers / deposits add up to the totals (R11, R12) | exact |
| Scale: 50k players, 1.48M CSV rows | full run in **3.4 s**, ~1 GB RAM (Apple M-series laptop) |

Precision comes from engineering, not from a model:
- money is summed as exact `DECIMAL(38,6)` and ratios use Python `Decimal` (no float drift: 0.10 + 0.20 = 0.30);
- the same CSV can never be read two ways: ambiguous decimal separators (`1,234`) are **refused**, not guessed;
- player hold outliers are **sample-size adjusted** ((hold − median)·√bets), so short lucky sessions are not anomalies;
- games are tested with the **standard error of a ratio estimator clustered by player** (robust to whales) against a plausible RTP band;
- every flag threshold is in `sentinela/config/rules.yaml` and its hash goes into the evidence.

Details: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## 7. Security model

Base rule: **every file that enters the system is cleaned, encrypted and leaves no readable trace.**

- **Vault**: AES-256-GCM, with keys derived from your passphrase (scrypt). Datasets, the vault index and reports are all encrypted. Tampering and truncation are detected.
- **Ingestion**: personal-data columns are removed (by header *and* content) before encryption. The original file name is never stored. The original is overwritten and deleted, along with its recent-files entry and thumbnail.
- **Analysis in RAM only** (`/dev/shm`): wiped at the end, on errors and on SIGTERM. No core dumps. DuckDB spills to RAM. No log files.
- **Pseudonyms**: player IDs become `P-…` keyed hashes; the key lives in the encrypted keyring.
- **The environment**: `sentinela doctor` checks LUKS, swap, tmpfs, network, crash reporter, leftovers and history.

Details and the machine checklist: [`docs/SECURITY.md`](docs/SECURITY.md).

## 8. Project layout

```text
sentinela-risk-lab/
├── install.sh                 # offline installer (Ubuntu)
├── requirements*.txt          # pinned, tested versions
├── wheelhouse/                # offline dependencies (not committed; rebuild with scripts/build-wheelhouse.sh; SHA256SUMS.txt kept)
├── sentinela/
│   ├── cli.py                 # commands
│   ├── security.py            # keyring, AES-256-GCM vault, RAM workspace, secure delete, hardening
│   ├── ingest.py              # sanitizing ingestion (PII removal, normalization, encryption)
│   ├── traces.py              # trace cleaning + `doctor` environment checks
│   ├── study.py               # study file (the "contract" of an analysis)
│   ├── contracts.py           # CSV validation, typing, pseudonymization
│   ├── engine.py              # metrics (executive, providers, affiliates, games, payments, clients)
│   ├── risk.py                # player risk flags and scoring
│   ├── behavior.py            # player features, lifecycle, tiers, segments, cohorts
│   ├── checks.py              # reconciliation
│   ├── insights.py            # deterministic narrative rules
│   ├── report.py / charts.py  # HTML, PDF, JSON, CSV outputs
│   ├── synthetic.py           # hypothetical data generator with planted anomalies
│   ├── config/                # contracts.yaml · rules.yaml · behavior.yaml · sections.yaml  ← tune here
│   └── templates/report.html.j2
├── studies/example-study.yaml
├── .sentinela/keyring.json    # created by `sentinela init` (encrypted key material)
├── vault/                     # encrypted datasets and report bundles (*.sntl)
├── docs/                      # CSV-CONTRACTS · BEHAVIOR · METHODOLOGY · SECURITY
└── tests/                     # 59 tests: crypto, ingestion, contracts, golden numbers, behavior, detection, privacy, reproducibility, CLI
```

Run the tests any time: `python -m unittest discover -s tests -t .`

## 9. Customizing

- **Player behavior definitions** (lifecycle, value tiers, segments, suppression, control groups): `sentinela/config/behavior.yaml`, or `behavior: ../my-behavior.yaml` in a study. See [`docs/BEHAVIOR.md`](docs/BEHAVIOR.md). `sentinela validate` checks your rules before any run.
- **Thresholds and weights**: edit `sentinela/config/rules.yaml`, or point a study at your own copy with `rules: ../my-rules.yaml`.
- **Accepted column names**: add aliases in `sentinela/config/contracts.yaml`, or use `column_map` in the study.
- **Report wording**: `sentinela/config/sections.yaml` ("Em miúdos" texts) and `sentinela/templates/report.html.j2`.

Every change shows up as a different `rules_sha256` / `contracts_sha256` in the evidence, so results are always traceable to the exact configuration that produced them.
