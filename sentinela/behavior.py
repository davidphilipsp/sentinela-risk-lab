"""Player behavior: profile features (specific) + configurable definitions (general).

* SPECIFIC — ``build_profile`` computes a fixed library of betting-industry features per
  player (recency, monetary, frequency, payday share, wagering multiple, risk...).
* GENERAL — lifecycle stages, value tiers and segments are rules over those features,
  read from behavior.yaml and compiled through a strict whitelist guard.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from datetime import timedelta
from typing import Any

from sentinela.engine import Ctx, D, one, ratio, rows

RULE_WORDS = {"and", "or", "not", "in", "is", "null", "between", "like", "ilike", "true", "false",
              "case", "when", "then", "else", "end"}
RULE_FUNCS = {"coalesce", "abs", "least", "greatest", "round", "lower", "upper"}
RULE_CHARS = re.compile(r"^[\w\s'.,()=<>!+\-*/%]*$")
PAYMENT_METRICS = {"deposits", "net_deposits", "lifetime_deposits", "avg_deposit", "withdrawals",
                   "deposit_count", "lifetime_deposit_count"}

# Feature dictionary: name -> description (documentation + rule validation + report glossary)
FEATURES: dict[str, str] = {
    "player_id": "pseudônimo do player",
    "btag": "afiliado (cadastro; senão o de maior turnover)",
    "kyc_status": "status KYC (clients.csv)",
    "signup_date": "data de cadastro",
    "days_since_signup": "dias desde o cadastro (até o fim do período)",
    "signed_up_in_period": "cadastrou-se no período (true/false)",
    "first_deposit_date": "data do primeiro depósito aprovado (histórico do arquivo)",
    "days_to_ftd": "dias entre cadastro e primeiro depósito",
    "ftd_in_period": "primeiro depósito ocorreu no período",
    "deposits": "depósitos aprovados no período (R$)",
    "deposit_count": "nº de depósitos aprovados no período",
    "deposit_days": "dias distintos com depósito no período",
    "avg_deposit": "depósito médio no período (R$)",
    "withdrawals": "saques aprovados no período (R$)",
    "withdrawal_count": "nº de saques aprovados no período",
    "net_deposits": "depósitos − saques no período (R$)",
    "last_deposit_date": "data do último depósito aprovado",
    "days_since_last_deposit": "dias desde o último depósito",
    "lifetime_deposits": "depósitos aprovados no histórico até o fim do período (R$)",
    "lifetime_deposit_count": "nº de depósitos aprovados no histórico",
    "lifetime_withdrawals": "saques aprovados no histórico (R$)",
    "turnover": "valor apostado no período (R$)",
    "ggr": "GGR do player no período (R$; positivo = casa ganhou)",
    "bets": "nº de apostas no período",
    "active_days": "dias com jogo no período",
    "active_days_share": "fração dos dias do período com jogo",
    "avg_bet": "aposta média no período (R$)",
    "hold": "GGR ÷ turnover do player no período",
    "providers_used": "nº de providers jogados no período",
    "top_provider": "provider com maior turnover no período",
    "first_activity_date": "primeiro dia com jogo (histórico)",
    "last_activity_date": "último dia com jogo (histórico até o fim do período)",
    "days_since_last_activity": "dias desde o último jogo",
    "lifetime_turnover": "turnover no histórico até o fim do período (R$)",
    "tenure_days": "dias de casa (desde o primeiro contato: cadastro, depósito ou jogo)",
    "wager_multiple": "turnover ÷ depósitos no período (rolagem)",
    "weekend_turnover_share": "fração do turnover em sábados e domingos",
    "payday_deposit_share": "fração dos depósitos nas janelas de payday",
    "risk_score": "score de risco (módulo de risco)",
    "risk_tier": "faixa de risco: alto | medio | baixo | nenhum",
}
DERIVED = {"value_tier": "faixa de valor (behavior.yaml)", "lifecycle": "estágio de ciclo de vida (behavior.yaml)"}


class RuleError(ValueError):
    pass


def compile_rule(expr: Any, allowed: set[str], where: str) -> str:
    """Validate a behavior rule against a whitelist and return safe SQL."""
    if isinstance(expr, bool):
        return "TRUE" if expr else "FALSE"
    if not isinstance(expr, str) or not expr.strip():
        raise RuleError(f"{where}: regra vazia.")
    if ";" in expr or "--" in expr or "/*" in expr or '"' in expr:
        raise RuleError(f"{where}: caracteres não permitidos (; -- /* \") em: {expr}")
    if not RULE_CHARS.match(expr):
        raise RuleError(f"{where}: caractere inválido em: {expr}")
    stripped = re.sub(r"'(?:[^']|'')*'", "''", expr)
    if "'" in stripped.replace("''", ""):
        raise RuleError(f"{where}: aspas desbalanceadas em: {expr}")
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
        low = token.lower()
        if low in RULE_WORDS or low in RULE_FUNCS or token in allowed:
            continue
        hint = difflib.get_close_matches(token, sorted(allowed), n=1)
        raise RuleError(f"{where}: nome desconhecido '{token}'"
                        + (f" — você quis dizer '{hint[0]}'?" if hint else "")
                        + " Veja a lista de features em docs/BEHAVIOR.md.")
    return f"({expr})"


def _date(d) -> str:
    return f"DATE '{d.isoformat()}'"


def _views(ctx: Ctx) -> None:
    con, end = ctx.con, _date(ctx.end)
    con.execute(f"CREATE OR REPLACE TEMP VIEW b_act_all AS SELECT * FROM activity WHERE dia <= {end}")
    if ctx.has_payments:
        con.execute(f"CREATE OR REPLACE TEMP VIEW b_pay_all AS SELECT * FROM payments "
                    f"WHERE status = 'approved' AND paid_at <= {end}")
    else:
        con.execute("CREATE OR REPLACE TEMP TABLE b_pay_all (player_id VARCHAR, paid_at DATE, type VARCHAR, "
                    "amount DECIMAL(38,6), status VARCHAR)")
    if ctx.has_clients:
        con.execute(f"CREATE OR REPLACE TEMP VIEW b_cli AS SELECT player_id, created_at, kyc_status, btag "
                    f"FROM clients WHERE created_at <= {end}")
    else:
        con.execute("CREATE OR REPLACE TEMP TABLE b_cli (player_id VARCHAR, created_at DATE, kyc_status VARCHAR, btag VARCHAR)")


def _payday_sql(windows: list[list[int]]) -> str:
    parts = [f"day(paid_at) BETWEEN {int(a)} AND {int(b)}" for a, b in windows]
    return "(" + " OR ".join(parts) + ")" if parts else "FALSE"


def build_profile(ctx: Ctx, cfg: dict[str, Any]) -> None:
    con = ctx.con
    _views(ctx)
    s, e = _date(ctx.start), _date(ctx.end)
    period_days = (ctx.end - ctx.start).days + 1
    payday = _payday_sql(cfg.get("payday_windows") or [])
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE profile_base AS
        WITH
        u AS (SELECT player_id FROM b_cli UNION SELECT player_id FROM b_act_all UNION SELECT player_id FROM b_pay_all),
        ap AS (SELECT player_id, sum(turnover) AS turnover, sum(ggr) AS ggr, sum(total_apostas) AS bets,
                      count(DISTINCT dia) AS active_days, count(DISTINCT provider_name) AS providers_used,
                      coalesce(sum(turnover) FILTER (WHERE isodow(dia) IN (6, 7)), 0) AS weekend_turnover
               FROM act GROUP BY player_id),
        tp AS (SELECT player_id, provider_name AS top_provider FROM (
                 SELECT player_id, provider_name,
                        row_number() OVER (PARTITION BY player_id ORDER BY sum(turnover) DESC, provider_name) AS rk
                 FROM act GROUP BY player_id, provider_name) WHERE rk = 1),
        aa AS (SELECT player_id, min(dia) AS first_activity_date, max(dia) AS last_activity_date,
                      sum(turnover) AS lifetime_turnover
               FROM b_act_all GROUP BY player_id),
        ab AS (SELECT player_id, btag FROM (
                 SELECT player_id, btag,
                        row_number() OVER (PARTITION BY player_id ORDER BY sum(turnover) DESC, btag) AS rk
                 FROM b_act_all GROUP BY player_id, btag) WHERE rk = 1),
        pp AS (SELECT player_id,
                      coalesce(sum(amount) FILTER (WHERE type = 'deposit'), 0) AS deposits,
                      count(*) FILTER (WHERE type = 'deposit') AS deposit_count,
                      count(DISTINCT paid_at) FILTER (WHERE type = 'deposit') AS deposit_days,
                      coalesce(sum(amount) FILTER (WHERE type = 'withdrawal'), 0) AS withdrawals,
                      count(*) FILTER (WHERE type = 'withdrawal') AS withdrawal_count,
                      coalesce(sum(amount) FILTER (WHERE type = 'deposit' AND {payday}), 0) AS payday_deposits
               FROM b_pay_all WHERE paid_at BETWEEN {s} AND {e} GROUP BY player_id),
        pl AS (SELECT player_id,
                      coalesce(sum(amount) FILTER (WHERE type = 'deposit'), 0) AS lifetime_deposits,
                      count(*) FILTER (WHERE type = 'deposit') AS lifetime_deposit_count,
                      coalesce(sum(amount) FILTER (WHERE type = 'withdrawal'), 0) AS lifetime_withdrawals,
                      min(paid_at) FILTER (WHERE type = 'deposit') AS first_deposit_date,
                      max(paid_at) FILTER (WHERE type = 'deposit') AS last_deposit_date
               FROM b_pay_all GROUP BY player_id)
        SELECT u.player_id,
               coalesce(c.btag, ab.btag, '(sem btag)') AS btag,
               coalesce(c.kyc_status, '(não informado)') AS kyc_status,
               c.created_at AS signup_date,
               {e} - c.created_at AS days_since_signup,
               coalesce(c.created_at BETWEEN {s} AND {e}, false) AS signed_up_in_period,
               pl.first_deposit_date,
               pl.first_deposit_date - c.created_at AS days_to_ftd,
               coalesce(pl.first_deposit_date BETWEEN {s} AND {e}, false) AS ftd_in_period,
               coalesce(pp.deposits, 0) AS deposits,
               coalesce(pp.deposit_count, 0) AS deposit_count,
               coalesce(pp.deposit_days, 0) AS deposit_days,
               pp.deposits / nullif(pp.deposit_count, 0) AS avg_deposit,
               coalesce(pp.withdrawals, 0) AS withdrawals,
               coalesce(pp.withdrawal_count, 0) AS withdrawal_count,
               coalesce(pp.deposits, 0) - coalesce(pp.withdrawals, 0) AS net_deposits,
               pl.last_deposit_date,
               {e} - pl.last_deposit_date AS days_since_last_deposit,
               coalesce(pl.lifetime_deposits, 0) AS lifetime_deposits,
               coalesce(pl.lifetime_deposit_count, 0) AS lifetime_deposit_count,
               coalesce(pl.lifetime_withdrawals, 0) AS lifetime_withdrawals,
               coalesce(ap.turnover, 0) AS turnover,
               coalesce(ap.ggr, 0) AS ggr,
               coalesce(ap.bets, 0) AS bets,
               coalesce(ap.active_days, 0) AS active_days,
               coalesce(ap.active_days, 0)::DOUBLE / {period_days} AS active_days_share,
               ap.turnover::DOUBLE / nullif(ap.bets, 0) AS avg_bet,
               ap.ggr::DOUBLE / nullif(ap.turnover, 0) AS hold,
               coalesce(ap.providers_used, 0) AS providers_used,
               tp.top_provider,
               aa.first_activity_date, aa.last_activity_date,
               {e} - aa.last_activity_date AS days_since_last_activity,
               coalesce(aa.lifetime_turnover, 0) AS lifetime_turnover,
               {e} - least(c.created_at, aa.first_activity_date, pl.first_deposit_date) AS tenure_days,
               ap.turnover::DOUBLE / nullif(pp.deposits, 0) AS wager_multiple,
               ap.weekend_turnover::DOUBLE / nullif(ap.turnover, 0) AS weekend_turnover_share,
               pp.payday_deposits::DOUBLE / nullif(pp.deposits, 0) AS payday_deposit_share,
               coalesce(r.risk_score, 0) AS risk_score,
               coalesce(r.risk_tier, 'nenhum') AS risk_tier
        FROM u
        LEFT JOIN b_cli c USING (player_id)
        LEFT JOIN ap USING (player_id) LEFT JOIN tp USING (player_id)
        LEFT JOIN aa USING (player_id) LEFT JOIN ab USING (player_id)
        LEFT JOIN pp USING (player_id) LEFT JOIN pl USING (player_id)
        LEFT JOIN player_risk r USING (player_id)
    """)


def _value_tiers(ctx: Ctx, cfg: dict[str, Any]) -> dict[str, Any]:
    vt = cfg["value_tiers"]
    metric = vt.get("metric", "deposits")
    note = None
    if metric in PAYMENT_METRICS and not ctx.has_payments:
        note = f"payments.csv ausente: métrica '{metric}' substituída por '{vt.get('fallback_metric', 'turnover')}'."
        metric = vt.get("fallback_metric", "turnover")
    if metric not in FEATURES or metric in ("player_id", "btag", "kyc_status", "top_provider", "risk_tier"):
        raise RuleError(f"value_tiers.metric '{metric}' não é uma feature numérica.")
    zero = vt.get("zero_label", "sem_valor")
    m = f"{metric}::DOUBLE"
    if vt.get("method", "quantile") == "fixed":
        hi, md = float(vt["fixed"]["high"]), float(vt["fixed"]["medium"])
        method = "fixed"
    else:
        q = vt["quantile"]
        th = one(ctx.con, f"SELECT quantile_cont({m}, {float(q['high'])}) AS hi, quantile_cont({m}, {float(q['medium'])}) AS md "
                          f"FROM profile_base WHERE {m} > 0")
        hi, md = th["hi"], th["md"]
        method = f"quantile (high ≥ p{round(float(q['high']) * 100)}, medium ≥ p{round(float(q['medium']) * 100)})"
    expr = (f"CASE WHEN {m} IS NULL OR {m} <= 0 THEN '{zero}' "
            + (f"WHEN {m} >= {hi!r} THEN 'high' WHEN {m} >= {md!r} THEN 'medium' " if hi is not None else "")
            + "ELSE 'low' END")
    return {"metric": metric, "method": method, "high_threshold": hi, "medium_threshold": md,
            "zero_label": zero, "sql": expr, "note": note}


def analyze_behavior(ctx: Ctx, cfg: dict[str, Any]) -> dict[str, Any]:
    con = ctx.con
    build_profile(ctx, cfg)
    tiers = _value_tiers(ctx, cfg)
    feats = set(FEATURES)

    stages = cfg.get("lifecycle") or []
    if not stages:
        raise RuleError("behavior.yaml: 'lifecycle' precisa de ao menos uma regra.")
    allowed_lc = feats | {"value_tier"}
    whens = " ".join(f"WHEN {compile_rule(st['when'], allowed_lc, 'lifecycle.' + st['id'])} THEN '{st['id']}'"
                     for st in stages)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE player_profile AS
        SELECT *, CASE {whens} ELSE 'sem_classificacao' END AS lifecycle
        FROM (SELECT *, {tiers['sql']} AS value_tier FROM profile_base)
    """)

    allowed = feats | set(DERIVED)
    sup = cfg.get("suppression") or {}
    sup_sql = compile_rule(sup["when"], allowed, "suppression") if sup.get("when") else "FALSE"
    segs = cfg.get("segments") or []
    seg_cols = []
    for sg in segs:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", str(sg.get("id", ""))):
            raise RuleError(f"segmento com id inválido: {sg.get('id')!r} (use minúsculas, números e _)")
        seg_cols.append(f"coalesce({compile_rule(sg['when'], allowed, 'segments.' + sg['id'])}, false) AS seg_{sg['id']}")
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE player_profile AS
        SELECT *, coalesce({sup_sql}, false) AS suppressed{''.join(', ' + c for c in seg_cols)}
        FROM player_profile
    """)

    universe = one(con, "SELECT count(*) AS n FROM player_profile")["n"]
    totals = one(con, "SELECT coalesce(sum(deposits),0) AS deposits, coalesce(sum(ggr),0) AS ggr, "
                      "coalesce(sum(turnover),0) AS turnover FROM player_profile")

    order = {st["id"]: i for i, st in enumerate(stages)}
    labels = {st["id"]: st.get("label", st["id"]) for st in stages}
    lc = rows(con, """
        SELECT lifecycle, count(*) AS players, sum(deposits) AS deposits, sum(net_deposits) AS net_deposits,
               sum(turnover) AS turnover, sum(ggr) AS ggr, sum(lifetime_deposits) AS lifetime_deposits
        FROM player_profile GROUP BY lifecycle
    """)
    lc.sort(key=lambda r: order.get(r["lifecycle"], 999))
    for r in lc:
        r["label"] = labels.get(r["lifecycle"], r["lifecycle"])
        r["share"] = ratio(r["players"], universe)
        r["deposit_share"] = ratio(r["deposits"], totals["deposits"])

    tier_order = {"high": 0, "medium": 1, "low": 2, tiers["zero_label"]: 3}
    vt = rows(con, f"""
        SELECT value_tier, count(*) AS players, sum(deposits) AS deposits, sum(turnover) AS turnover, sum(ggr) AS ggr,
               min({tiers['metric']}) AS metric_min, max({tiers['metric']}) AS metric_max
        FROM player_profile GROUP BY value_tier
    """)
    vt.sort(key=lambda r: tier_order.get(r["value_tier"], 9))
    for r in vt:
        r["share"] = ratio(r["players"], universe)
        r["deposit_share"] = ratio(r["deposits"], totals["deposits"])
        r["ggr_share"] = ratio(r["ggr"], totals["ggr"])

    tier_names = [r["value_tier"] for r in vt]
    matrix_raw = rows(con, "SELECT lifecycle, value_tier, count(*) AS players, sum(deposits) AS deposits "
                           "FROM player_profile GROUP BY 1, 2")
    matrix = []
    for st in [r["lifecycle"] for r in lc]:
        row = {"lifecycle": st, "label": labels.get(st, st)}
        for t in tier_names:
            cell = next((m for m in matrix_raw if m["lifecycle"] == st and m["value_tier"] == t), None)
            row[t] = cell["players"] if cell else 0
            row[f"{t}_deposits"] = cell["deposits"] if cell else D(0)
        matrix.append(row)

    seg_summary, members = [], {}
    for sg in segs:
        col = f"seg_{sg['id']}"
        campaign = bool(sg.get("campaign", False))
        s = one(con, f"""
            SELECT count(*) AS players, count(*) FILTER (WHERE suppressed) AS suppressed,
                   coalesce(sum(deposits),0) AS deposits, coalesce(sum(turnover),0) AS turnover,
                   coalesce(sum(ggr),0) AS ggr, coalesce(sum(lifetime_deposits),0) AS lifetime_deposits
            FROM player_profile WHERE {col}
        """)
        cond = f"{col} AND NOT suppressed" if campaign else col
        mem = rows(con, f"""
            SELECT player_id, lifecycle, value_tier, risk_tier, days_since_last_activity, deposits, lifetime_deposits,
                   turnover, ggr, btag
            FROM player_profile WHERE {cond} ORDER BY lifetime_deposits DESC, player_id
        """)
        pct = float(sg.get("control_group_pct") or 0) if campaign else 0.0
        for mrow in mem:
            mrow["grupo"] = control_group(mrow["player_id"], sg["id"], pct) if pct else ("lista" if campaign else "monitoramento")
        ctl = sum(1 for mrow in mem if mrow["grupo"] == "controle")
        digest = hashlib.sha256("\n".join(m["player_id"] for m in mem).encode()).hexdigest()
        members[sg["id"]] = mem
        seg_summary.append({
            "id": sg["id"], "label": sg.get("label", sg["id"]), "rule": sg["when"], "campaign": campaign,
            **s, "eligible": len(mem), "control": ctl, "treatment": len(mem) - ctl if pct else None,
            "control_group_pct": pct or None, "members_sha256": digest,
            "share": ratio(s["players"], universe),
        })

    cohorts = _cohorts(ctx, cfg)
    rhythm = _rhythm(ctx, cfg)
    return {
        "universe": universe,
        "totals": totals,
        "value_tiers": {**{k: v for k, v in tiers.items() if k != "sql"}, "tiers": vt},
        "lifecycle": lc,
        "matrix": matrix,
        "matrix_tiers": tier_names,
        "segments": seg_summary,
        "suppression": {"rule": sup.get("when"), "label": sup.get("label"),
                        "players": one(con, "SELECT count(*) AS n FROM player_profile WHERE suppressed")["n"]},
        "cohorts": cohorts,
        "rhythm": rhythm,
        "config_version": cfg.get("version"),
        "_bulk": {"members": members},
    }


def control_group(player_id: str, segment_id: str, pct: float) -> str:
    """Deterministic holdout: same player + segment = same group on every run and machine."""
    bucket = int(hashlib.sha256(f"{player_id}|{segment_id}".encode()).hexdigest()[:8], 16) % 10000
    return "controle" if bucket < pct * 100 else "tratamento"


def _cohorts(ctx: Ctx, cfg: dict[str, Any]) -> dict[str, Any]:
    con = ctx.con
    c = cfg.get("cohorts") or {}
    grain = "week" if c.get("grain") == "week" else "month"
    n_periods = int(c.get("retention_periods", 6))
    basis = "signup_date" if ctx.has_clients else "first_activity_date"
    diff = "datediff('month', cohort, period)" if grain == "month" else "datediff('week', cohort, period)"
    table = rows(con, f"""
        SELECT date_trunc('{grain}', {basis})::DATE AS cohort, count(*) AS players,
               count(*) FILTER (WHERE first_deposit_date IS NOT NULL
                                AND (signup_date IS NULL OR first_deposit_date >= signup_date)) AS ftd,
               median(days_to_ftd) FILTER (WHERE days_to_ftd >= 0) AS median_days_to_ftd,
               count(*) FILTER (WHERE active_days > 0) AS active_in_period,
               coalesce(sum(lifetime_deposits), 0) AS lifetime_deposits,
               coalesce(sum(lifetime_deposits - lifetime_withdrawals), 0) AS lifetime_net
        FROM player_profile WHERE {basis} IS NOT NULL
        GROUP BY 1 ORDER BY 1 DESC LIMIT 12
    """)
    for r in table:
        r["ftd_rate"] = ratio(r["ftd"], r["players"])
        r["active_rate"] = ratio(r["active_in_period"], r["players"])
        r["net_per_player"] = ratio(r["lifetime_net"], r["players"])
    table.sort(key=lambda r: r["cohort"])
    ret = rows(con, f"""
        WITH coh AS (SELECT player_id, date_trunc('{grain}', {basis})::DATE AS cohort FROM player_profile WHERE {basis} IS NOT NULL),
        act_p AS (SELECT DISTINCT player_id, date_trunc('{grain}', dia)::DATE AS period FROM b_act_all)
        SELECT cohort, {diff} AS k, count(DISTINCT player_id) AS players
        FROM coh JOIN act_p USING (player_id)
        WHERE period >= cohort AND {diff} < {n_periods}
        GROUP BY 1, 2
    """)
    sizes = {r["cohort"]: r["players"] for r in table}
    matrix = []
    for r in table:
        line = {"cohort": r["cohort"], "players": r["players"]}
        for k in range(n_periods):
            n = next((x["players"] for x in ret if x["cohort"] == r["cohort"] and x["k"] == k), None)
            line[f"p{k}"] = ratio(n, sizes[r["cohort"]]) if n is not None else None
        matrix.append(line)
    return {"grain": grain, "basis": basis, "table": table, "retention": matrix, "periods": n_periods}


def _rhythm(ctx: Ctx, cfg: dict[str, Any]) -> dict[str, Any]:
    con = ctx.con
    out: dict[str, Any] = {}
    if ctx.has_payments:
        s, e = _date(ctx.start), _date(ctx.end)
        dom = rows(con, f"""
            SELECT day(paid_at) AS day, count(*) AS deposits_n, sum(amount) AS deposits
            FROM b_pay_all WHERE type = 'deposit' AND paid_at BETWEEN {s} AND {e} GROUP BY 1 ORDER BY 1
        """)
        dow = rows(con, f"""
            SELECT isodow(paid_at) AS dow, count(*) AS deposits_n, sum(amount) AS deposits
            FROM b_pay_all WHERE type = 'deposit' AND paid_at BETWEEN {s} AND {e} GROUP BY 1 ORDER BY 1
        """)
        names = {1: "seg", 2: "ter", 3: "qua", 4: "qui", 5: "sex", 6: "sáb", 7: "dom"}
        for r in dow:
            r["name"] = names[r["dow"]]
        payday = _payday_sql(cfg.get("payday_windows") or [])
        p = one(con, f"""
            SELECT coalesce(sum(amount) FILTER (WHERE {payday}), 0) AS payday, coalesce(sum(amount), 0) AS total,
                   count(DISTINCT day(paid_at)) FILTER (WHERE {payday}) AS payday_days_present,
                   count(DISTINCT day(paid_at)) AS days_present
            FROM b_pay_all WHERE type = 'deposit' AND paid_at BETWEEN {s} AND {e}
        """)
        windows = cfg.get("payday_windows") or []
        n_days = (ctx.end - ctx.start).days + 1
        days_of_month = [(ctx.start + timedelta(days=i)).day for i in range(n_days)]
        cal = sum(1 for dm in days_of_month if any(int(lo) <= dm <= int(hi) for lo, hi in windows))
        calendar_share = ratio(cal, n_days)
        payday_share = ratio(p["payday"], p["total"])
        out.update(day_of_month=dom, weekday=dow, payday_windows=windows,
                   payday_share=payday_share, payday_calendar_share=calendar_share,
                   payday_lift=ratio(payday_share, calendar_share) if payday_share is not None and calendar_share else None)
    if ctx.has_clients and ctx.has_payments:
        edges = [int(x) for x in (cfg.get("ftd_buckets") or [0, 1, 3, 7, 30])]
        cases, lo = [], None
        for hi in edges:
            label = "mesmo dia" if hi == 0 else (f"{(lo or 0) + 1}–{hi} dias" if (lo or 0) + 1 != hi else f"{hi} dia")
            cases.append((f"days_to_ftd <= {hi}", label))
            lo = hi
        case_sql = " ".join(f"WHEN {c} THEN '{lbl}'" for c, lbl in cases)
        b = rows(con, f"""
            SELECT bucket, count(*) AS players FROM (
              SELECT CASE WHEN first_deposit_date IS NULL OR days_to_ftd < 0 THEN 'sem FTD'
                          {case_sql} ELSE '> {edges[-1]} dias' END AS bucket
              FROM player_profile WHERE signed_up_in_period) GROUP BY 1
        """)
        order = [lbl for _, lbl in cases] + [f"> {edges[-1]} dias", "sem FTD"]
        b.sort(key=lambda r: order.index(r["bucket"]))
        total = sum(r["players"] for r in b)
        for r in b:
            r["share"] = ratio(r["players"], total)
        out["time_to_ftd"] = b
    return out


def profile_rows(ctx: Ctx) -> list[dict[str, Any]]:
    cols = list(FEATURES) + ["value_tier", "lifecycle", "suppressed"]
    return rows(ctx.con, f"SELECT {', '.join(cols)} FROM player_profile ORDER BY lifetime_deposits DESC, player_id")


def validate_config(cfg: dict[str, Any]) -> list[str]:
    """Compile every rule without data; return human-readable errors (empty list = valid)."""
    errors: list[str] = []
    feats = set(FEATURES)
    for st in cfg.get("lifecycle") or []:
        try:
            compile_rule(st.get("when"), feats | {"value_tier"}, f"lifecycle.{st.get('id')}")
        except RuleError as exc:
            errors.append(str(exc))
    if not cfg.get("lifecycle"):
        errors.append("lifecycle: defina ao menos uma regra (a última normalmente é when: \"true\").")
    allowed = feats | set(DERIVED)
    sup = (cfg.get("suppression") or {}).get("when")
    if sup:
        try:
            compile_rule(sup, allowed, "suppression")
        except RuleError as exc:
            errors.append(str(exc))
    seen = set()
    for sg in cfg.get("segments") or []:
        sid = str(sg.get("id", ""))
        if not re.fullmatch(r"[a-z][a-z0-9_]*", sid):
            errors.append(f"segmento com id inválido: {sid!r}")
        if sid in seen:
            errors.append(f"segmento duplicado: {sid}")
        seen.add(sid)
        try:
            compile_rule(sg.get("when"), allowed, f"segments.{sid}")
        except RuleError as exc:
            errors.append(str(exc))
        pct = sg.get("control_group_pct")
        if pct is not None and not (0 <= float(pct) <= 50):
            errors.append(f"segments.{sid}: control_group_pct deve estar entre 0 e 50.")
    vt = cfg.get("value_tiers") or {}
    for key in ("metric", "fallback_metric"):
        if vt.get(key) and vt[key] not in FEATURES:
            errors.append(f"value_tiers.{key}: feature desconhecida '{vt[key]}'.")
    return errors
