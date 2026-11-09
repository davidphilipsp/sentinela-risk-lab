"""Player risk scoring: transparent, rule-based, statistically grounded.

Each flag is a boolean rule whose parameters come from rules.yaml; the
population statistics it used (medians, MADs, quantiles) are returned so that
the evidence JSON lets anyone recompute every flag by hand.
"""
from __future__ import annotations

import math
from typing import Any

from sentinela.engine import Ctx, D, one, ratio, rows

FLAG_ORDER = [
    "HIGH_EXPOSURE", "HOLD_OUTLIER_LOW", "BET_SIZE_OUTLIER", "BONUS_ABUSE_PATTERN",
    "MULTI_PROVIDER_BURST", "WITHDRAWAL_GT_DEPOSIT", "LOW_WAGER_CASHOUT", "FAST_CASHOUT",
]
PAYMENT_FLAGS = {"WITHDRAWAL_GT_DEPOSIT", "LOW_WAGER_CASHOUT", "FAST_CASHOUT"}


def _num(value: Any) -> str:
    """Render a numeric parameter as a SQL literal (or NULL)."""
    if value is None:
        return "NULL"
    v = float(value)
    if math.isnan(v) or math.isinf(v):
        return "NULL"
    return repr(v)


def score_players(ctx: Ctx) -> dict[str, Any]:
    con = ctx.con
    r = ctx.rules
    rs = r["robust_statistics"]
    pf = r["player_flags"]
    tiers = r["risk_tiers"]

    con.execute("""
        CREATE OR REPLACE TEMP TABLE player_features AS
        WITH a AS (
            SELECT player_id, count(DISTINCT dia) AS active_days, count(DISTINCT provider_name) AS providers_used,
                   sum(turnover) AS turnover, sum(ggr) AS ggr, sum(total_apostas) AS bets,
                   min(dia) AS first_day, max(dia) AS last_day
            FROM act GROUP BY player_id),
        p AS (
            SELECT player_id,
                   sum(amount) FILTER (WHERE type='deposit') AS deposits,
                   sum(amount) FILTER (WHERE type='withdrawal') AS withdrawals,
                   min(paid_at) FILTER (WHERE type='deposit') AS first_deposit,
                   min(paid_at) FILTER (WHERE type='withdrawal') AS first_withdrawal
            FROM pay WHERE status='approved' GROUP BY player_id)
        SELECT coalesce(a.player_id, p.player_id) AS player_id,
               coalesce(a.active_days, 0) AS active_days,
               coalesce(a.providers_used, 0) AS providers_used,
               coalesce(a.turnover, 0) AS turnover,
               coalesce(a.ggr, 0) AS ggr,
               -coalesce(a.ggr, 0) AS player_net,
               coalesce(a.bets, 0) AS bets,
               a.first_day, a.last_day,
               coalesce(p.deposits, 0) AS deposits,
               coalesce(p.withdrawals, 0) AS withdrawals,
               p.first_deposit, p.first_withdrawal,
               CASE WHEN coalesce(a.bets,0) > 0 THEN a.turnover::DOUBLE / a.bets END AS avg_bet,
               CASE WHEN coalesce(a.turnover,0) > 0 THEN a.ggr::DOUBLE / a.turnover END AS hold
        FROM a FULL OUTER JOIN p USING (player_id)
    """)

    min_t, min_b = rs["min_turnover_for_hold"], rs["min_bets_for_hold"]
    eligible = f"turnover >= {_num(min_t)} AND bets >= {_num(min_b)}"

    stats = one(con, f"""
        SELECT
          median(hold) FILTER (WHERE {eligible}) AS hold_median,
          median(ln(avg_bet)) FILTER (WHERE avg_bet > 0) AS logbet_median,
          quantile_cont(player_net::DOUBLE, {pf['HIGH_EXPOSURE']['quantile']}) FILTER (WHERE turnover > 0) AS q_player_net,
          quantile_cont(turnover::DOUBLE, {pf['BONUS_ABUSE_PATTERN']['turnover_quantile']}) FILTER (WHERE turnover > 0) AS q_turnover,
          quantile_cont(providers_used::DOUBLE, {pf['MULTI_PROVIDER_BURST']['providers_quantile']}) FILTER (WHERE turnover > 0) AS q_providers,
          count(*) FILTER (WHERE {eligible}) AS hold_eligible_players,
          count(*) FILTER (WHERE turnover > 0) AS active_players,
          count(*) AS universe
        FROM player_features
    """)
    # Size-adjusted hold deviation: (hold - median) * sqrt(bets). Hold of a player with few bets
    # varies much more than one with many (standard error ~ 1/sqrt(n)); scaling by sqrt(bets) puts
    # every player on the same footing before the robust z-score is taken.
    mads = one(con, f"""
        SELECT
          median(abs((hold - {_num(stats['hold_median'])}) * sqrt(bets))) FILTER (WHERE {eligible}) AS hold_mad,
          median(abs(ln(avg_bet) - {_num(stats['logbet_median'])})) FILTER (WHERE avg_bet > 0) AS logbet_mad
        FROM player_features
    """)
    stats.update(mads)
    cut = rs["z_cutoff"]

    def z(expr: str, med: Any, mad: Any) -> str:
        if med is None or not mad:
            return "NULL::DOUBLE"
        return f"(0.6745 * (({expr}) - {_num(med)}) / {_num(mad)})"

    if stats["hold_median"] is None or not stats["hold_mad"]:
        hold_z_sql = "NULL::DOUBLE"
    else:
        hold_z_sql = (f"(0.6745 * (hold - {_num(stats['hold_median'])}) * sqrt(bets) "
                      f"/ {_num(stats['hold_mad'])})")

    he, ba, mp = pf["HIGH_EXPOSURE"], pf["BONUS_ABUSE_PATTERN"], pf["MULTI_PROVIDER_BURST"]
    wg, lw, fc = pf["WITHDRAWAL_GT_DEPOSIT"], pf["LOW_WAGER_CASHOUT"], pf["FAST_CASHOUT"]
    pay_on = "true" if ctx.has_payments else "false"
    q_net = stats["q_player_net"]
    exposure_floor = max(float(he["min_player_net"]), float(q_net) if q_net is not None else 0.0)

    flag_sql = {
        "HIGH_EXPOSURE": f"player_net::DOUBLE >= {_num(exposure_floor)} AND player_net > 0",
        "HOLD_OUTLIER_LOW": f"({eligible}) AND hold_z <= -{_num(cut)}",
        "BET_SIZE_OUTLIER": f"bet_z >= {_num(cut)}",
        "BONUS_ABUSE_PATTERN": (f"turnover > 0 AND (turnover::DOUBLE >= {_num(stats['q_turnover'])} "
                                f"OR ({pay_on} AND deposits > 0 AND turnover >= {_num(ba.get('min_wager_multiple'))} * deposits)) "
                                f"AND abs(hold) <= {_num(ba['max_abs_hold'])} AND active_days <= {int(ba['max_active_days'])}"),
        "MULTI_PROVIDER_BURST": (f"providers_used >= greatest({_num(stats['q_providers'])}, {int(mp['min_providers'])}) "
                                 f"AND active_days <= {int(mp['max_active_days'])}"),
        "WITHDRAWAL_GT_DEPOSIT": (f"{pay_on} AND withdrawals >= {_num(wg['min_withdrawals'])} "
                                  f"AND withdrawals > {_num(wg['ratio'])} * deposits"),
        "LOW_WAGER_CASHOUT": (f"{pay_on} AND deposits >= {_num(lw['min_deposits'])} AND withdrawals > 0 "
                              f"AND turnover < {_num(lw['max_turnover_to_deposit'])} * deposits"),
        "FAST_CASHOUT": (f"{pay_on} AND first_withdrawal IS NOT NULL AND first_deposit IS NOT NULL "
                         f"AND (first_withdrawal - first_deposit) BETWEEN 0 AND {int(fc['max_days'])}"),
    }
    flag_cols = ", ".join(f"coalesce({sql}, false) AS {name.lower()}" for name, sql in flag_sql.items())
    score = " + ".join(f"(CASE WHEN {n.lower()} THEN {int(pf[n]['weight'])} ELSE 0 END)" for n in FLAG_ORDER)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE player_risk AS
        WITH zz AS (
            SELECT *,
                   CASE WHEN {eligible} THEN {hold_z_sql} END AS hold_z,
                   CASE WHEN avg_bet > 0 THEN {z('ln(avg_bet)', stats['logbet_median'], stats['logbet_mad'])} END AS bet_z
            FROM player_features),
        ff AS (SELECT *, {flag_cols} FROM zz)
        SELECT *, ({score}) AS risk_score,
               CASE WHEN ({score}) >= {int(tiers['alto'])} THEN 'alto'
                    WHEN ({score}) >= {int(tiers['medio'])} THEN 'medio'
                    WHEN ({score}) >= {int(tiers['baixo'])} THEN 'baixo'
                    ELSE 'nenhum' END AS risk_tier
        FROM ff
    """)

    flag_counts = []
    for name in FLAG_ORDER:
        if name in PAYMENT_FLAGS and not ctx.has_payments:
            continue
        n = one(con, f"SELECT count(*) AS n, coalesce(sum(turnover),0) AS turnover, coalesce(sum(player_net),0) AS player_net "
                     f"FROM player_risk WHERE {name.lower()}")
        flag_counts.append({"flag": name, "players": n["n"], "turnover": n["turnover"], "player_net": n["player_net"],
                            "weight": pf[name]["weight"], "description": pf[name]["description"]})

    tier_counts = rows(con, """
        SELECT risk_tier, count(*) AS players, coalesce(sum(turnover),0) AS turnover, coalesce(sum(ggr),0) AS ggr
        FROM player_risk GROUP BY risk_tier
        ORDER BY CASE risk_tier WHEN 'alto' THEN 1 WHEN 'medio' THEN 2 WHEN 'baixo' THEN 3 ELSE 4 END
    """)

    # concat_ws skips NULLs -> comma-separated list of raised flags (no lambdas: version-agnostic)
    flags_expr = "concat_ws(', ', " + ", ".join(f"CASE WHEN {n.lower()} THEN '{n}' END" for n in FLAG_ORDER) + ")"
    detail_cols = f"""player_id, risk_score, risk_tier, {flags_expr} AS flags,
        active_days, providers_used, turnover, ggr, player_net, bets, avg_bet, hold,
        round(hold_z, 3) AS hold_z, round(bet_z, 3) AS bet_z, deposits, withdrawals, first_day, last_day"""
    flagged = rows(con, f"""
        SELECT {detail_cols} FROM player_risk WHERE risk_score >= {int(tiers['medio'])}
        ORDER BY risk_score DESC, player_net DESC, turnover DESC, player_id
    """)
    all_scored = rows(con, f"SELECT {detail_cols} FROM player_risk WHERE risk_score > 0 "
                           f"ORDER BY risk_score DESC, player_net DESC, turnover DESC, player_id")
    exposure = rows(con, f"""
        SELECT {detail_cols} FROM player_risk WHERE player_net > 0
        ORDER BY player_net DESC, player_id LIMIT 20
    """)

    conc = one(con, """
        WITH s AS (SELECT turnover::DOUBLE AS x, row_number() OVER (ORDER BY turnover DESC, player_id) AS rk_desc,
                          row_number() OVER (ORDER BY turnover ASC, player_id) AS rk_asc,
                          count(*) OVER () AS n
                   FROM player_risk WHERE turnover > 0)
        SELECT sum(x) AS total,
               sum(x) FILTER (WHERE rk_desc <= 10) AS top10,
               sum(x) FILTER (WHERE rk_desc <= greatest(1, ceil(n * 0.01))) AS top1pct,
               max(n) AS n,
               (2.0 * sum(rk_asc * x)) / (max(n) * sum(x)) - (max(n) + 1.0) / max(n) AS gini
        FROM s
    """)
    concentration = {
        "players_with_turnover": conc.get("n"),
        "top10_turnover_share": ratio(conc.get("top10"), conc.get("total")) if conc.get("total") else None,
        "top1pct_turnover_share": ratio(conc.get("top1pct"), conc.get("total")) if conc.get("total") else None,
        "gini_turnover": round(conc["gini"], 4) if conc.get("gini") is not None else None,
    }

    params = {
        **{k: (round(v, 6) if isinstance(v, float) else v) for k, v in stats.items()},
        "exposure_floor": exposure_floor,
        "z_cutoff": cut,
        "min_turnover_for_hold": min_t,
        "min_bets_for_hold": min_b,
        "flag_sql": flag_sql,
    }
    return {
        "params": params,
        "flag_counts": flag_counts,
        "tiers": tier_counts,
        "flagged": flagged,
        "all_scored": all_scored,
        "exposure_top": exposure,
        "concentration": concentration,
        "flagged_threshold": int(tiers["medio"]),
        "payments_used": ctx.has_payments,
        "total_player_net_flagged": sum((D(p["player_net"]) for p in flagged), D(0)),
    }
