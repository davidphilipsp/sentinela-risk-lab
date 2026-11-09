# CSV contracts

Files enter only through `sentinela ingest FILE --dataset X` (sanitized and encrypted, see `SECURITY.md`).
The contract below is applied when a study reads the vault. Every file is validated **before** any number is computed. Source of truth: `sentinela/config/contracts.yaml`
(`sentinela contracts` prints it).

## General rules

| Topic | Rule |
|---|---|
| Header matching | case-insensitive, accents/spaces/punctuation ignored (`Situação do Depósito` = `situacao_do_deposito`) |
| Header aliases | each column accepts several names (see tables). Otherwise map explicitly with `column_map` in the study |
| Field delimiter | auto-detected (`,` `;` tab `|`) or `delimiter:` in the study |
| Decimal separator | auto-detected **only when unambiguous**. `1.234,56` → `,`; `1,234.56` → `.`; `12,5` → `,`. Files where every value looks like `1,234` or `1.234` are **refused** until you set `decimal_separator` (a guess could silently change values 1000×) |
| Money values | `R$ 1.234,56`, `(12,34)` (accounting negative) and spaces are accepted |
| Dates | `AAAA-MM-DD`, `DD/MM/AAAA`, ISO timestamps (time is discarded). Override with `date_formats:`. `MM/DD/AAAA` is **not** accepted by default (it collides with DD/MM). If your system exports US dates, set `date_formats: ["%m/%d/%Y"]`, otherwise 05/12 would be read as 5 December (days > 12 fail loudly, but days ≤ 12 would not) |
| Encoding | UTF-8 by default; `encoding: latin-1` for old Excel exports |
| Extra columns | ignored and listed in the validation report |
| Optional columns missing | filled with the documented default and listed |
| PII (`player_id`) | pseudonymized on load: `P-` + `sha256(key \| id)[:16]` |
| Direct personal data | columns such as name, e-mail, phone/celular/WhatsApp, CPF/RG/document, address/CEP, birth date, IP, card/PIX key are **detected by header and discarded at load**. Their values never enter the analysis tables, and the report lists them under "PII descartada". Ingestion removes them *before* encryption, so they are never stored |

### Severity

- **error**: the row is invalid (missing required value, wrong type, below minimum, value not allowed, duplicate key).
  With `on_contract_error: fail` (default) the run is **aborted** and the report lists line numbers and examples.
  With `on_contract_error: drop` the rows are removed, counted, and the report shows check `R9` (numbers computed without them).
- **warning**: the row is kept, counted, and shown in the data-quality section (e.g. GGR > turnover).

## activity.csv (REQUIRED)

One row per **day × player × provider**. Unique key: `dia + player_id + provider_name`.

| Column | Type | Req. | Rules | Accepted headers (aliases) |
|---|---|---|---|---|
| `dia` | date | ✔ | | date, data, day, dt, data_aposta, activity_date |
| `player_id` | string | ✔ | PII → pseudonym | user_id, userid, id_jogador, id_player, customer_id, cliente_id, player |
| `provider_name` | string | ✔ | | provider, provedor, fornecedor, vendor |
| `btag` | string | | default `(sem btag)` | affiliate, afiliado, affiliate_id, tracking_tag, utm_source |
| `turnover` | decimal | ✔ | ≥ 0 | valor_apostado, total_apostado, wager, stake, bet_amount, apostado |
| `ggr` | decimal | ✔ | warning if > turnover | gross_gaming_revenue, receita_bruta, resultado_casa |
| `total_apostas` | integer | ✔ | ≥ 0; warning if 0 with turnover > 0 | bets, apostas, qtd_apostas, num_bets, bet_count, rounds, giros |
| `top_jogos` | JSON text | | see below | top_games, jogos |

`top_jogos` is accepted as an object `{"Game": {"turnover": 50, "ggr": 5, "bets": 10}, ...}` or an array
`[{"game_name": "Game", "turnover": 50, ...}]`. Per-game metrics are read **from inside the JSON**. If the JSON only
has names, the Games section ranks by appearances and says so. Prefer `games.csv` when you have it.

## games.csv (optional, most precise Games section)

Unique key: `dia + player_id + provider_name + game_name`.

| Column | Type | Req. | Rules | Aliases |
|---|---|---|---|---|
| `dia` | date | ✔ | | date, data, day, dt |
| `player_id` | string | | default `(agregado)` if the file is already aggregated | user_id, id_jogador, customer_id |
| `provider_name` | string | | default `(sem provider)` | provider, provedor |
| `game_name` | string | ✔ | | game, jogo, nome_jogo, game_title |
| `turnover` | decimal | ✔ | ≥ 0 | valor_apostado, wager, stake |
| `ggr` | decimal | ✔ | warning if > turnover | receita_bruta, resultado_casa |
| `total_apostas` | integer | | ≥ 0 | bets, apostas, rounds, giros |

Reconciliation `R5` compares games vs activity turnover: **more** turnover in games than in activity = FAIL
(double count or misaligned exports).

## payments.csv (optional; enables cash-flow section + 3 AML flags)

One row per transaction. Unique key: `transaction_id` (only checked if present).

| Column | Type | Req. | Rules | Aliases |
|---|---|---|---|---|
| `transaction_id` | string | | unique | id, payment_id, id_transacao, txid |
| `paid_at` | date | ✔ | | date, data, created_at, data_pagamento, payment_date, dia |
| `player_id` | string | ✔ | PII | user_id, id_jogador, customer_id |
| `type` | string | ✔ | **deposit** ← deposit, deposito, depósito, dep, d, cashin, pix_in · **withdrawal** ← withdrawal, saque, w, cashout, pix_out | tipo, payment_type, kind, operation, operacao |
| `amount` | decimal | ✔ | ≥ 0 (warning if 0) | valor, value, amount_brl, montante |
| `status` | string | | default approved · **approved** ← aprovado, success, paid, pago, completed, concluido, ok · **pending** ← pendente, processing · **rejected** ← recusado, failed, declined, cancelado, estornado, refunded | situacao, state, payment_status |

A value outside these lists is an **error**. Add it to `allowed_values` in the contract when it's legitimate.
Only **approved** transactions enter money totals; approval rate = approved ÷ (approved + rejected).

## clients.csv (optional)

| Column | Type | Req. | Rules | Aliases |
|---|---|---|---|---|
| `player_id` | string | ✔ | PII, unique | user_id, id_jogador, customer_id |
| `created_at` | date | ✔ | | signup_date, data_cadastro, registration_date, registered_at, cadastro |
| `kyc_status` | string | | default `(não informado)` | kyc, status_kyc, verification_status |
| `btag` | string | | default `(sem btag)` | affiliate, afiliado, affiliate_id, utm_source |

## Example study input block

```yaml
inputs:
  activity:
    path: ../data/export_cassino.csv
    delimiter: ";"
    decimal_separator: ","
    date_formats: ["%d/%m/%Y"]
    column_map:
      "Data Movimento": dia
      "Cod Cliente": player_id
      "Fornecedor Jogo": provider_name
      "Valor Apostado (R$)": turnover
      "Resultado Casa (R$)": ggr
      "Qtd Rodadas": total_apostas
  payments:
    path: ../data/pagamentos.csv
    encoding: latin-1
```
