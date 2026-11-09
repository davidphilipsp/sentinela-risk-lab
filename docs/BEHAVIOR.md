# Player behavior

The behavior module is **general and specific at once**:

| Layer | Where | Changes when… |
|---|---|---|
| **Specific**: betting-industry player features (recency, deposits, turnover, wagering multiple, payday share, days to FTD, risk…) | code (`sentinela/behavior.py`) | almost never (same industry, same kind of player) |
| **General**: lifecycle stages, value tiers, segments, suppression, control groups | `sentinela/config/behavior.yaml` | whenever your business definitions change, with **no code changes** |

All numbers come from deterministic SQL over your CSVs. No AI is involved.

## 1. Changing the definitions (your workflow)

```bash
cp sentinela/config/behavior.yaml studies/my-behavior.yaml   # your own copy
nano studies/my-behavior.yaml                                # edit stages, tiers, segments
# in the study file:   behavior: my-behavior.yaml
sentinela validate studies/june.yaml                         # catches typos BEFORE running
sentinela run studies/june.yaml
```

Each version of your definitions gets its own `behavior_sha256` in the evidence, so you always know which
definitions produced a report. You can keep several definition files (e.g. one per operator or brand) and choose
one per study.

## 2. Rule syntax

A rule (`when`) is a boolean expression over the **features** below:

```yaml
when: "value_tier = 'high' AND days_since_last_activity BETWEEN 8 AND 30"
when: "lifetime_deposit_count = 1 AND days_since_last_deposit > 7"
when: "coalesce(payday_deposit_share, 0) >= 0.6 AND deposit_count >= 2"
when: "true"           # catch-all (last lifecycle stage)
```

Allowed: feature names, numbers, `'text'`, `AND OR NOT IN IS NULL BETWEEN LIKE`, `= <> != < <= > >= + - * /`,
and the functions `coalesce abs least greatest round lower upper`.
Anything else (unknown names, `;`, comments, sub-queries, file functions) is **rejected** with a message, and close
matches are suggested: `nome desconhecido 'depositss' — você quis dizer 'deposits'?`.

Missing data: a feature that cannot be computed (e.g. `signup_date` without clients.csv) is `NULL`. Comparisons
with NULL are false, so wrap with `coalesce(...)` when you want a default.

## 3. Lifecycle

An ordered list: the **first matching rule wins**, so every player gets exactly one stage. The default stages are
industry conventions, to be replaced with yours:

`cadastrado_sem_ftd` → `depositou_sem_jogar` → `novo` (≤ 7 days of tenure) → `ativo` (played ≤ 7 days ago) →
`esfriando` (8–14) → `em_risco` (15–30) → `inativo` (31–90) → `churn` (> 90).

Recency is measured from the **last day of the study period**, not from today, so re-running an old study gives the
same answer.

## 4. Value tiers

Until the business defines tiers, they are **data-driven**: quantiles of a metric (default `deposits` in the
period) among players with value > 0. The defaults are top 10% `high`, the next 30% `medium`, the rest `low`, and
`sem_valor` for zero. Switch to `method: fixed` with your own cut-offs whenever you have them. The thresholds
actually used are printed in the report and stored in the evidence.

## 5. Segments, suppression, control groups

- A player can belong to **several** segments.
- `campaign: true` → the **suppression** rule removes players who must never be contacted (default: high risk or
  KYC rejected, a responsible-gaming safeguard). The report shows players / suppressed / eligible.
- `control_group_pct: 10` → a **deterministic holdout**: `sha256(pseudonym | segment)` decides the group. The same
  player always lands in the same group of the same segment, on any run or machine, which keeps campaign
  measurement honest. Different segments draw independently.
- Lists: `outputs/…/tables/segments/<id>.csv` (pseudonyms).
- For CRM upload: `sentinela export-segment STUDY <id> --group tratamento --reveal` writes
  `outputs/private/…csv` with **real IDs** (mode 600, only possible on the machine holding the key).

## 6. Other outputs

| Output | Meaning |
|---|---|
| Lifecycle × value-tier matrix | where the value sits: e.g. high-value players who are cooling down |
| Cohorts | by signup month (or first activity when no clients.csv): FTD rate, median days to FTD, active in period, net deposits per player |
| Retention matrix | % of each cohort that played k months after joining |
| Deposit rhythm | by day of month and weekday; payday share **vs. the calendar share of payday days** (the lift: 1.0 = no payday effect) |
| Time to FTD | buckets for players who signed up in the period |
| `tables/player_profile.csv` | one row per player with **every feature**: the base for any further analysis |

Reconciliation `R11`/`R12` proves that stages and tiers add up exactly to the totals (players, turnover, deposits).

## 7. Feature dictionary

Period = the study period. Lifetime/history = everything in the files up to the end of the period.
`sentinela features` prints this list.

| Feature | Meaning |
|---|---|
| `player_id` | pseudônimo do player |
| `btag` | afiliado (cadastro; senão o de maior turnover) |
| `kyc_status` | status KYC (clients.csv) |
| `signup_date` | data de cadastro |
| `days_since_signup` | dias desde o cadastro (até o fim do período) |
| `signed_up_in_period` | cadastrou-se no período (true/false) |
| `first_deposit_date` | data do primeiro depósito aprovado (histórico do arquivo) |
| `days_to_ftd` | dias entre cadastro e primeiro depósito |
| `ftd_in_period` | primeiro depósito ocorreu no período |
| `deposits` | depósitos aprovados no período (R$) |
| `deposit_count` | nº de depósitos aprovados no período |
| `deposit_days` | dias distintos com depósito no período |
| `avg_deposit` | depósito médio no período (R$) |
| `withdrawals` | saques aprovados no período (R$) |
| `withdrawal_count` | nº de saques aprovados no período |
| `net_deposits` | depósitos − saques no período (R$) |
| `last_deposit_date` | data do último depósito aprovado |
| `days_since_last_deposit` | dias desde o último depósito |
| `lifetime_deposits` | depósitos aprovados no histórico até o fim do período (R$) |
| `lifetime_deposit_count` | nº de depósitos aprovados no histórico |
| `lifetime_withdrawals` | saques aprovados no histórico (R$) |
| `turnover` | valor apostado no período (R$) |
| `ggr` | GGR do player no período (R$; positivo = casa ganhou) |
| `bets` | nº de apostas no período |
| `active_days` | dias com jogo no período |
| `active_days_share` | fração dos dias do período com jogo |
| `avg_bet` | aposta média no período (R$) |
| `hold` | GGR ÷ turnover do player no período |
| `providers_used` | nº de providers jogados no período |
| `top_provider` | provider com maior turnover no período |
| `first_activity_date` | primeiro dia com jogo (histórico) |
| `last_activity_date` | último dia com jogo (histórico até o fim do período) |
| `days_since_last_activity` | dias desde o último jogo |
| `lifetime_turnover` | turnover no histórico até o fim do período (R$) |
| `tenure_days` | dias de casa (desde o primeiro contato: cadastro, depósito ou jogo) |
| `wager_multiple` | turnover ÷ depósitos no período (rolagem) |
| `weekend_turnover_share` | fração do turnover em sábados e domingos |
| `payday_deposit_share` | fração dos depósitos nas janelas de payday |
| `risk_score` | score de risco (módulo de risco) |
| `risk_tier` | faixa de risco: alto | medio | baixo | nenhum |
| `value_tier` | faixa de valor (behavior.yaml) |
| `lifecycle` | estágio de ciclo de vida (behavior.yaml) |
