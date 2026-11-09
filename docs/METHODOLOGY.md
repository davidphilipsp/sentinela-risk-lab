# Methodology

Everything below is computed by `sentinela/engine.py`, `risk.py`, `checks.py` and `insights.py`.
No language model is involved. Every parameter lives in `sentinela/config/rules.yaml`.

## 1. Pipeline

```
study.yaml ─► contracts (validate, type, pseudonymize) ─► DuckDB tables
          ─► period filter ─► metrics ─► player risk ─► reconciliation ─► insight rules
          ─► evidence.json (+ hashes, Run ID) ─► HTML / PDF / CSV tables
```

**Run ID** = `sha256(version, study file, contracts, rules, every input file)`. The same Run ID always means the
same numbers. This was verified byte-for-byte on two DuckDB versions (1.5.6 and 2.0.0).

## 2. Numeric precision

- Money columns become `DECIMAL(38,6)`; sums are exact (no binary floating point).
- Ratios (hold, shares, averages) are `Decimal` divisions quantized to 10 decimal places.
- Floats are used **only** for statistical descriptors (z-scores, quantiles, slope, Gini). They are labelled as such and rounded before output, so results stay deterministic.

## 3. Metrics

| Metric | Definition |
|---|---|
| Turnover | Σ `turnover` |
| GGR | Σ `ggr` (house result: positive = house won) |
| Hold | GGR ÷ turnover |
| Average bet | turnover ÷ `total_apostas` |
| GGR per day | GGR ÷ calendar days in the period (not only days with data) |
| Player net | −GGR of the player (positive = the player won) |
| Provider share | provider turnover ÷ total turnover |
| HHI | Σ (share × 100)² over providers; >1,500 moderate, >2,500 high concentration |
| Provider hold deviation | provider hold − overall hold; flagged when share ≥ 2% and \|dev\| ≥ 2 p.p. |
| Top-10 / top-1% share | turnover of the 10 (or ⌈1%⌉) largest players ÷ total |
| Gini | 2·Σ(rank·x)/(n·Σx) − (n+1)/n over player turnover |
| Daily hold z | robust z of each day's hold vs. the other days |
| GGR trend | OLS slope of daily GGR (R² reported; only narrated if R² ≥ 0.3) |
| Deposits / withdrawals | Σ approved amounts by type |
| Approval rate | approved ÷ (approved + rejected); pending excluded |
| FTD | players whose **first approved deposit in the file** falls in the period |
| Signup → FTD | signups in the period with an approved deposit on/after signup |

## 4. Player risk

**Universe**: every player with activity **or** approved payments in the period. A player who deposits and withdraws
without playing casino is the strongest AML signal, so they are included.

**Robust z-score** (Iglewicz & Hoaglin): `z = 0.6745 · (x − median) / MAD`. The cut-off is |z| ≥ 3.5. Median and MAD
are not distorted by the very outliers being searched for, unlike mean and standard deviation.

**Size-adjusted hold**: a player's hold over *n* bets has a standard error ∝ 1/√n. The deviation therefore uses
`x = (hold − median) · √bets`. Without this, any lucky 200-spin session looks like an anomaly. With it, the extra
flags on the synthetic data dropped from 11 to 2, with no loss of recall. Only players with turnover ≥ 500 and
≥ 200 bets are tested.

| Flag | Weight | Rule (defaults) |
|---|---|---|
| `HIGH_EXPOSURE` | 3 | player net ≥ max(p99 of player net, R$ 5,000) |
| `HOLD_OUTLIER_LOW` | 2 | size-adjusted hold z ≤ −3.5 |
| `BET_SIZE_OUTLIER` | 1 | robust z of ln(average bet) ≥ 3.5 |
| `BONUS_ABUSE_PATTERN` | 2 | (turnover ≥ p90 **or** turnover ≥ 25× approved deposits) and \|hold\| ≤ 1% and ≤ 3 active days |
| `MULTI_PROVIDER_BURST` | 1 | providers used ≥ max(p99, 4) within ≤ 2 active days |
| `WITHDRAWAL_GT_DEPOSIT`* | 2 | approved withdrawals ≥ R$ 1,000 and > 1.5× approved deposits |
| `LOW_WAGER_CASHOUT`* | 2 | deposits ≥ R$ 500, withdrew, and turnover < 1× deposits |
| `FAST_CASHOUT`* | 1 | first withdrawal ≤ 1 day after first deposit |

\* only when `payments.csv` is supplied.

**Score** = Σ weights · **tiers**: alto ≥ 5 · médio ≥ 3 · baixo ≥ 1. "Flagged" means score ≥ 3.
The population statistics actually used (medians, MADs, quantiles, exposure floor, SQL of every rule) are written to
`evidence.json → results.players.params`, so any flag can be recomputed by hand.

**Affiliates**: flagged-player rate per btag ÷ overall rate = *risk multiplier*. Alert when ≥ 2× with ≥ 20 players.

> Flags are statistical evidence for investigation, not proof of fraud. The report says so explicitly.

## 5. Game hold test

A game's hold varies with its stake mix: a few high rollers dominate its variance. A plain z-score across games, or
scaling by √bets, misleads in both directions (measured on the synthetic data: plain z caught the broken game in 6 of 7 datasets, √bets scaling in only 6 of 10).
Sentinela uses the **ratio-estimator standard error clustered by player**:

```
SE(hold_g) = sqrt( n/(n−1) · Σ_i (ggr_i − hold_g · turnover_i)² ) / Σ_i turnover_i      (i = players of game g)
```

Honest games legitimately differ by a few points of RTP, so each game is compared with a **plausible band**:
median game hold ± 3 p.p. Then `band_z = distance beyond the band ÷ SE`:

- |band_z| ≥ 3.5 → **alert** (significantly outside the band)
- 2.0 ≤ |band_z| < 3.5 → **watch list** (suspicious; not enough data to prove it yet)
- games with fewer than 30 players are not tested

On 10 synthetic datasets the planted −12% hold game was caught every time (8 alerts, 2 on the watch list). No alert
fired on 320 honest-game tests.

## 6. Reconciliation checks

| ID | Check | Status |
|---|---|---|
| R1 | Σ providers = executive total (turnover, GGR) | exact, else FALHA |
| R2 | Σ players = executive total | exact, else FALHA |
| R3 | Σ btags = executive total | exact, else FALHA |
| R4 | Σ days = executive total | exact, else FALHA |
| R5 | games turnover vs activity turnover | > 100% FALHA (double count) · < 100% ALERTA (games.csv) / INFO (top_jogos) |
| R6 | days of the period with data | missing days → ALERTA (lists them) |
| R7 | activity rows outside the period | INFO (ignored, counted) |
| R8 | players with approved payments and no casino activity | ALERTA when > 0 |
| R9 | rows removed by the contract (`drop` mode) | ALERTA |
| R10 | rows kept with rule warnings | ALERTA |
| R11 | Σ lifecycle stages = player universe; Σ stages turnover = total; Σ value tiers = universe | exact, else FALHA |
| R12 | Σ lifecycle stages deposits = approved deposits of the period | exact, else FALHA |

Any FALHA produces a top-level alert: conclusions of that section are not reliable until it's fixed.

## 6b. Player behavior

Features, lifecycle, value tiers, segments, cohorts and deposit rhythm are documented in [`BEHAVIOR.md`](BEHAVIOR.md).
Their definitions live in `config/behavior.yaml` and are hashed into the Run ID like the risk rules.

## 7. Insights

`insights.py` turns evidence and thresholds into sentences. Each sentence has a `rule` id and a severity
(`alerta` / `atenção` / `info`), and every number in it is read from the evidence. The "Em miúdos" boxes are fixed
editorial text from `config/sections.yaml`.

## 8. Fixes relative to the original Risk Squad prototype

1. **Games double count**: the original summed row-level turnover once per game listed in `top_jogos`. Now game metrics come from the game itself, and `R5` detects any double count in the inputs.
2. **Row cap**: the original agents only ever saw ≤ 500 rows per query. Now the whole population is processed.
3. **Risk**: ranking by |GGR| became an 8-flag, weighted, statistically grounded score.
4. **Payments/clients**: real metrics instead of a JSON key inventory.
5. **Privacy**: prefix masking (8 real characters leaked) became a keyed hash.
6. **Reproducibility**: explicit period, input hashes, Run ID.
7. **Data quality**: contracts and reconciliation instead of trusting the source.

## 9. Limitations

- Results reflect only the CSVs supplied; FTD depends on how much payment history was exported.
- Quantile-based thresholds are relative to the population analysed. A tiny file gives unstable quantiles.
- The synthetic validation proves the engine finds the patterns it was designed for. Calibrate `rules.yaml` against your own confirmed cases before acting on a new population.
