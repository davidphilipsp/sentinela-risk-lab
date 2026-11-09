"""Deterministic metrics engine (DuckDB, exact DECIMAL arithmetic).

Money is summed as DECIMAL(38,6) in DuckDB and ratios are computed with Python
``Decimal``; floats are used only for statistical descriptors (z-scores, slopes)
and are labelled as such.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal, getcontext
from typing import Any

import duckdb

getcontext().prec = 40
Q = Decimal("1e-10")


@dataclass
class Ctx:
    con: duckdb.DuckDBPyConnection
    start: date
    end: date
    rules: dict[str, Any]
    datasets: set[str]
    notes: list[str] = field(default_factory=list)

    @property
    def has_payments(self) -> bool:
        return "payments" in self.datasets

    @property
    def has_clients(self) -> bool:
        return "clients" in self.datasets

    @property
    def has_games(self) -> bool:
        return "games" in self.datasets


# --------------------------------------------------------------------------- helpers

def rows(con: duckdb.DuckDBPyConnection, sql: str, params: list | None = None) -> list[dict[str, Any]]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def one(con: duckdb.DuckDBPyConnection, sql: str, params: list | None = None) -> dict[str, Any]:
    out = rows(con, sql, params)
    return out[0] if out else {}


def D(value: Any) -> Decimal:
    if value is None:
        return Decimal(0)
    return value if isinstance(value, Decimal) else Decimal(str(value))


def ratio(num: Any, den: Any) -> Decimal | None:
    if num is None or den is None:
        return None
    den = D(den)
    if den == 0:
        return None
    return (D(num) / den).quantize(Q)


def robust_z(values: list[float]) -> tuple[float | None, float | None]:
    """Return (median, MAD) for robust z-scores."""
    clean = [v for v in values if v is not None]
    if len(clean) < 3:
        return None, None
    med = statistics.median(clean)
    mad = statistics.median([abs(v - med) for v in clean])
    return med, mad


def zscore(x: float | None, med: float | None, mad: float | None) -> float | None:
    if x is None or med is None or not mad:
        return None
    return round(0.6745 * (x - med) / mad, 4)


def prepare_views(ctx: Ctx) -> None:
    s, e = ctx.start.isoformat(), ctx.end.isoformat()
    con = ctx.con
    con.execute(f"CREATE OR REPLACE TEMP VIEW act AS SELECT * FROM activity WHERE dia BETWEEN DATE '{s}' AND DATE '{e}'")
    if ctx.has_payments:
        con.execute(f"CREATE OR REPLACE TEMP VIEW pay AS SELECT * FROM payments WHERE paid_at BETWEEN DATE '{s}' AND DATE '{e}'")
    else:
        con.execute(
            "CREATE OR REPLACE TEMP TABLE pay (transaction_id VARCHAR, paid_at DATE, player_id VARCHAR, "
            "type VARCHAR, amount DECIMAL(38,6), status VARCHAR)"
        )
    if ctx.has_games:
        con.execute(f"CREATE OR REPLACE TEMP VIEW gam AS SELECT * FROM games WHERE dia BETWEEN DATE '{s}' AND DATE '{e}'")


# --------------------------------------------------------------------------- executive

def executive(ctx: Ctx) -> dict[str, Any]:
    con = ctx.con
    t = one(con, """
        SELECT count(*) AS rows,
               coalesce(sum(turnover), 0) AS turnover,
               coalesce(sum(ggr), 0) AS ggr,
               coalesce(sum(total_apostas), 0) AS bets,
               count(DISTINCT player_id) AS players,
               count(DISTINCT provider_name) AS providers,
               count(DISTINCT btag) AS btags,
               count(DISTINCT dia) AS active_days,
               min(dia) AS first_day, max(dia) AS last_day
        FROM act
    """)
    period_days = (ctx.end - ctx.start).days + 1
    metrics = {
        **t,
        "period_days": period_days,
        "hold": ratio(t["ggr"], t["turnover"]),
        "avg_bet": ratio(t["turnover"], t["bets"]),
        "turnover_per_player": ratio(t["turnover"], t["players"]),
        "ggr_per_player": ratio(t["ggr"], t["players"]),
        "ggr_per_day": ratio(t["ggr"], period_days),
        "player_net": -D(t["ggr"]),
    }

    daily = rows(con, """
        SELECT dia, sum(turnover) AS turnover, sum(ggr) AS ggr, sum(total_apostas) AS bets,
               count(DISTINCT player_id) AS players
        FROM act GROUP BY dia ORDER BY dia
    """)
    for d in daily:
        d["hold"] = ratio(d["ggr"], d["turnover"])
    holds = [float(d["hold"]) if d["hold"] is not None else None for d in daily]
    med, mad = robust_z(holds)
    for d, h in zip(daily, holds, strict=True):
        d["hold_z"] = zscore(h, med, mad)

    present = {d["dia"] for d in daily}
    missing_days = [ctx.start + timedelta(days=i) for i in range(period_days)
                    if ctx.start + timedelta(days=i) not in present]

    trend = one(con, """
        SELECT regr_slope(g, x) AS slope, regr_r2(g, x) AS r2 FROM (
            SELECT sum(ggr)::DOUBLE AS g, (dia - DATE '1970-01-01')::DOUBLE AS x FROM act GROUP BY dia)
    """)
    return {
        "metrics": metrics,
        "daily": daily,
        "missing_days": missing_days,
        "daily_hold_stats": {"median": med, "mad": mad},
        "ggr_trend": {
            "slope_per_day": round(trend["slope"], 2) if trend.get("slope") is not None else None,
            "r2": round(trend["r2"], 4) if trend.get("r2") is not None else None,
            "note": "estatística descritiva (regressão linear do GGR diário); não é previsão",
        },
    }


# --------------------------------------------------------------------------- providers

def providers(ctx: Ctx, exec_metrics: dict[str, Any]) -> dict[str, Any]:
    data = rows(ctx.con, """
        SELECT provider_name, count(DISTINCT player_id) AS players,
               sum(turnover) AS turnover, sum(ggr) AS ggr, sum(total_apostas) AS bets
        FROM act GROUP BY provider_name ORDER BY turnover DESC, provider_name
    """)
    total_t, total_g = exec_metrics["turnover"], exec_metrics["ggr"]
    overall_hold = exec_metrics["hold"]
    rules = ctx.rules["insights"]
    hhi = Decimal(0)
    for r in data:
        r["hold"] = ratio(r["ggr"], r["turnover"])
        r["turnover_share"] = ratio(r["turnover"], total_t)
        r["ggr_share"] = ratio(r["ggr"], total_g)
        r["avg_bet"] = ratio(r["turnover"], r["bets"])
        share = r["turnover_share"] or Decimal(0)
        hhi += (share * 100) ** 2
        dev = (r["hold"] - overall_hold) if (r["hold"] is not None and overall_hold is not None) else None
        r["hold_deviation"] = dev
        r["hold_flag"] = bool(
            dev is not None
            and share >= Decimal(str(rules["provider_min_share_for_hold_check"]))
            and abs(dev) >= Decimal(str(rules["provider_hold_deviation_pp"]))
        )
    return {
        "providers": data,
        "hhi": hhi.quantize(Decimal("0.01")),
        "top_share": data[0]["turnover_share"] if data else None,
        "top_provider": data[0]["provider_name"] if data else None,
    }


# --------------------------------------------------------------------------- affiliates

def affiliates(ctx: Ctx, exec_metrics: dict[str, Any], flagged_threshold: int) -> dict[str, Any]:
    data = rows(ctx.con, f"""
        WITH b AS (
            SELECT btag, count(DISTINCT player_id) AS players, sum(turnover) AS turnover,
                   sum(ggr) AS ggr, sum(total_apostas) AS bets
            FROM act GROUP BY btag),
        f AS (
            SELECT a.btag, count(DISTINCT a.player_id) AS flagged_players
            FROM act a JOIN player_risk r USING (player_id)
            WHERE r.risk_score >= {int(flagged_threshold)} GROUP BY a.btag)
        SELECT b.*, coalesce(f.flagged_players, 0) AS flagged_players
        FROM b LEFT JOIN f USING (btag) ORDER BY turnover DESC, btag
    """)
    total_flagged = one(ctx.con, f"""
        SELECT count(DISTINCT a.player_id) AS n FROM act a JOIN player_risk r USING (player_id)
        WHERE r.risk_score >= {int(flagged_threshold)}
    """)["n"]
    overall_rate = ratio(total_flagged, exec_metrics["players"])
    rules = ctx.rules["insights"]
    for r in data:
        r["hold"] = ratio(r["ggr"], r["turnover"])
        r["turnover_share"] = ratio(r["turnover"], exec_metrics["turnover"])
        r["turnover_per_player"] = ratio(r["turnover"], r["players"])
        r["flagged_rate"] = ratio(r["flagged_players"], r["players"])
        r["risk_multiplier"] = ratio(r["flagged_rate"], overall_rate) if overall_rate else None
        enough = r["players"] >= rules["affiliate_min_players"]
        r["risk_flag"] = bool(enough and r["risk_multiplier"] is not None
                              and r["risk_multiplier"] >= Decimal(str(rules["affiliate_risk_multiplier_alert"])))
        r["low_hold_flag"] = bool(enough and r["hold"] is not None
                                  and r["hold"] < Decimal(str(rules["affiliate_low_hold"])))
    return {"affiliates": data, "overall_flagged_rate": overall_rate, "flagged_players": total_flagged}


# --------------------------------------------------------------------------- games

GAME_METRIC_KEYS = {
    "turnover": ["turnover", "wager", "apostado", "valor_apostado", "stake"],
    "ggr": ["ggr", "receita_bruta", "resultado_casa"],
    "bets": ["total_apostas", "bets", "apostas", "rounds", "giros"],
}


def games(ctx: Ctx, exec_metrics: dict[str, Any]) -> dict[str, Any]:
    con = ctx.con
    if ctx.has_games:
        source = "games.csv"
        mode = "metrics"
        con.execute("""
            CREATE OR REPLACE TEMP VIEW game_rows AS
            SELECT dia, game_name, provider_name, player_id, turnover, ggr, total_apostas AS bets FROM gam
        """)
    else:
        has_col = one(con, "SELECT count(*) FILTER (WHERE top_jogos IS NOT NULL) AS n FROM act")["n"]
        if not has_col:
            return {"available": False, "reason": "Sem games.csv e sem coluna top_jogos na atividade."}
        source = "activity.top_jogos"

        def pick(keys: list[str]) -> str:
            return "coalesce(" + ", ".join(f"v->>'{k}'" for k in keys) + ")"

        # Accept JSON object {game: {...}} or array [{game_name:..., ...}]. Per-game metrics
        # come from INSIDE the JSON; the row-level turnover is never repeated per game
        # (that was the double-count of the original get_game_performance).
        con.execute("""
            CREATE OR REPLACE TEMP VIEW tj AS
            SELECT dia, player_id, provider_name, top_jogos::JSON AS j FROM act
            WHERE top_jogos IS NOT NULL AND json_valid(top_jogos)
        """)
        con.execute("""
            CREATE OR REPLACE TEMP TABLE game_json AS
            SELECT dia, player_id, provider_name, e.key AS k, e.value AS v
            FROM tj, unnest(map_entries(j::MAP(VARCHAR, JSON))) AS t(e)
            WHERE json_type(j) = 'OBJECT'
            UNION ALL
            SELECT dia, player_id, provider_name, NULL AS k, v
            FROM tj, unnest(j::JSON[]) AS t(v)
            WHERE json_type(j) = 'ARRAY'
        """)
        con.execute(f"""
            CREATE OR REPLACE TEMP VIEW game_rows AS
            SELECT dia, coalesce(v->>'game_name', v->>'name', v->>'jogo', k) AS game_name,
                   provider_name, player_id,
                   TRY_CAST({pick(GAME_METRIC_KEYS['turnover'])} AS DECIMAL(38,6)) AS turnover,
                   TRY_CAST({pick(GAME_METRIC_KEYS['ggr'])} AS DECIMAL(38,6)) AS ggr,
                   TRY_CAST({pick(GAME_METRIC_KEYS['bets'])} AS BIGINT) AS bets
            FROM game_json
        """)
        with_metrics = one(con, "SELECT count(*) FILTER (WHERE turnover IS NOT NULL) AS n FROM game_rows")["n"]
        mode = "metrics" if with_metrics else "appearances"

    data = rows(con, """
        SELECT game_name, string_agg(DISTINCT provider_name, ', ' ORDER BY provider_name) AS providers,
               count(DISTINCT player_id) FILTER (WHERE player_id <> '(agregado)') AS players,
               count(*) AS appearances,
               sum(turnover) AS turnover, sum(ggr) AS ggr, sum(bets) AS bets
        FROM game_rows WHERE game_name IS NOT NULL
        GROUP BY game_name ORDER BY turnover DESC NULLS LAST, appearances DESC, game_name
    """)
    totals = one(con, "SELECT coalesce(sum(turnover),0) AS turnover, coalesce(sum(ggr),0) AS ggr FROM game_rows")
    rules = ctx.rules
    min_t = Decimal(str(rules["insights"]["game_min_turnover_for_hold_check"]))
    for r in data:
        r["hold"] = ratio(r["ggr"], r["turnover"])
        r["turnover_share"] = ratio(r["turnover"], totals["turnover"])
    # Statistical test per game (ratio estimator, standard error clustered by player):
    #   SE(hold) = sqrt( n/(n-1) * sum_i (ggr_i - hold * turnover_i)^2 ) / sum_i turnover_i
    # Robust to whales/big winners (stake heterogeneity), unlike sqrt(bets) scaling.
    # A game is flagged only if its hold is SIGNIFICANTLY outside the plausible band
    # [median game hold +- tolerance] (honest slots differ by a few p.p. of RTP).
    se_rows = rows(con, """
        WITH c AS (
            SELECT game_name,
                   CASE WHEN player_id IS NULL OR player_id = '(agregado)' THEN 'd:' || dia::VARCHAR ELSE player_id END AS cl,
                   sum(turnover)::DOUBLE AS t, sum(ggr)::DOUBLE AS g
            FROM game_rows WHERE turnover IS NOT NULL AND ggr IS NOT NULL AND game_name IS NOT NULL
            GROUP BY 1, 2),
        h AS (SELECT game_name, sum(g) / sum(t) AS hold, sum(t) AS tt, count(*) AS n
              FROM c GROUP BY 1 HAVING sum(t) > 0)
        SELECT c.game_name, h.n AS clusters,
               sqrt(sum(power(c.g - h.hold * c.t, 2)) * h.n / greatest(h.n - 1, 1)) / h.tt AS se
        FROM c JOIN h USING (game_name) GROUP BY c.game_name, h.tt, h.n
    """)
    se_map = {x["game_name"]: x for x in se_rows}
    th = rules["insights"]
    min_clusters = int(th.get("game_min_clusters", 30))
    tol = float(th.get("game_hold_tolerance_pp", 0.03))
    cut = rules["robust_statistics"]["z_cutoff"]
    watch = float(th.get("game_watch_z", 2.0))
    for r in data:
        s_ = se_map.get(r["game_name"], {})
        r["clusters"] = s_.get("clusters")
        r["hold_se"] = round(s_["se"], 6) if s_.get("se") else None
    elig = [r for r in data if r["hold"] is not None and D(r["turnover"]) >= min_t
            and (r["clusters"] or 0) >= min_clusters and r["hold_se"]]
    ref, _ = robust_z([float(r["hold"]) for r in elig])
    for r in data:
        r["hold_z"] = r["band_z"] = None
        r["hold_flag"] = r["hold_watch"] = False
        if ref is None or r not in elig:
            continue
        h, se = float(r["hold"]), r["hold_se"]
        r["hold_z"] = round((h - ref) / se, 3)
        if h < ref - tol:
            r["band_z"] = round((h - (ref - tol)) / se, 3)
        elif h > ref + tol:
            r["band_z"] = round((h - (ref + tol)) / se, 3)
        r["hold_flag"] = bool(r["band_z"] is not None and abs(r["band_z"]) >= cut)
        r["hold_watch"] = bool(r["band_z"] is not None and watch <= abs(r["band_z"]) < cut)
    return {
        "available": True,
        "source": source,
        "mode": mode,
        "games": data,
        "total_turnover": totals["turnover"],
        "total_ggr": totals["ggr"],
        "coverage_vs_activity": ratio(totals["turnover"], exec_metrics["turnover"]) if mode == "metrics" else None,
        "hold_stats": {
            "reference_median": ref, "tolerance": tol, "min_clusters": min_clusters,
            "method": "ratio-estimator SE clustered by player", "alert_z": cut, "watch_z": watch,
        },
    }


# --------------------------------------------------------------------------- payments

def payments(ctx: Ctx) -> dict[str, Any]:
    con = ctx.con
    t = one(con, """
        SELECT
          coalesce(sum(amount) FILTER (WHERE type='deposit' AND status='approved'), 0) AS deposits,
          count(*) FILTER (WHERE type='deposit' AND status='approved') AS deposit_count,
          count(DISTINCT player_id) FILTER (WHERE type='deposit' AND status='approved') AS depositors,
          coalesce(sum(amount) FILTER (WHERE type='withdrawal' AND status='approved'), 0) AS withdrawals,
          count(*) FILTER (WHERE type='withdrawal' AND status='approved') AS withdrawal_count,
          count(DISTINCT player_id) FILTER (WHERE type='withdrawal' AND status='approved') AS withdrawers,
          count(*) FILTER (WHERE type='deposit' AND status IN ('approved','rejected')) AS deposit_decided,
          count(*) FILTER (WHERE type='withdrawal' AND status IN ('approved','rejected')) AS withdrawal_decided,
          count(*) FILTER (WHERE status='pending') AS pending
        FROM pay
    """)
    ftd = one(con, f"""
        SELECT count(*) AS ftd_players, coalesce(sum(first_amount), 0) AS ftd_amount FROM (
            SELECT player_id, arg_min(amount, paid_at) AS first_amount, min(paid_at) AS first_paid
            FROM payments WHERE type='deposit' AND status='approved' GROUP BY player_id)
        WHERE first_paid BETWEEN DATE '{ctx.start}' AND DATE '{ctx.end}'
    """)
    no_activity = one(con, """
        SELECT count(DISTINCT player_id) AS n FROM pay
        WHERE status='approved' AND player_id NOT IN (SELECT DISTINCT player_id FROM act)
    """)["n"]
    daily = rows(con, """
        SELECT paid_at AS dia,
               coalesce(sum(amount) FILTER (WHERE type='deposit' AND status='approved'), 0) AS deposits,
               coalesce(sum(amount) FILTER (WHERE type='withdrawal' AND status='approved'), 0) AS withdrawals
        FROM pay GROUP BY paid_at ORDER BY paid_at
    """)
    for d in daily:
        d["net"] = D(d["deposits"]) - D(d["withdrawals"])
    metrics = {
        **t, **ftd,
        "net_deposits": D(t["deposits"]) - D(t["withdrawals"]),
        "withdrawal_to_deposit": ratio(t["withdrawals"], t["deposits"]),
        "avg_deposit": ratio(t["deposits"], t["deposit_count"]),
        "deposit_approval_rate": ratio(t["deposit_count"], t["deposit_decided"]),
        "withdrawal_approval_rate": ratio(t["withdrawal_count"], t["withdrawal_decided"]),
        "players_paying_without_activity": no_activity,
    }
    ctx.notes.append("FTD = primeiro depósito aprovado presente no arquivo de pagamentos; "
                     "depende do histórico exportado.")
    return {"metrics": metrics, "daily": daily}


# --------------------------------------------------------------------------- clients

def clients(ctx: Ctx) -> dict[str, Any]:
    con = ctx.con
    s, e = ctx.start.isoformat(), ctx.end.isoformat()
    con.execute(f"CREATE OR REPLACE TEMP VIEW signups AS SELECT * FROM clients WHERE created_at BETWEEN DATE '{s}' AND DATE '{e}'")
    pay_join = (
        "LEFT JOIN (SELECT player_id, min(paid_at) AS first_dep FROM payments "
        "WHERE type='deposit' AND status='approved' GROUP BY player_id) p USING (player_id)"
        if ctx.has_payments else "LEFT JOIN (SELECT NULL::VARCHAR AS player_id, NULL::DATE AS first_dep) p USING (player_id)"
    )
    base = f"""
        SELECT s.player_id, s.btag, s.kyc_status,
               (p.first_dep IS NOT NULL AND p.first_dep >= s.created_at) AS converted_ftd,
               (s.player_id IN (SELECT DISTINCT player_id FROM act)) AS active
        FROM signups s {pay_join}
    """
    t = one(con, f"""
        SELECT count(*) AS signups,
               count(*) FILTER (WHERE converted_ftd) AS ftd,
               count(*) FILTER (WHERE active) AS active
        FROM ({base})
    """)
    total_clients = one(con, "SELECT count(*) AS n FROM clients")["n"]
    kyc = rows(con, "SELECT kyc_status, count(*) AS players FROM signups GROUP BY kyc_status ORDER BY players DESC, kyc_status")
    for k in kyc:
        k["share"] = ratio(k["players"], t["signups"])
    by_btag = rows(con, f"""
        SELECT btag, count(*) AS signups, count(*) FILTER (WHERE converted_ftd) AS ftd,
               count(*) FILTER (WHERE active) AS active
        FROM ({base}) GROUP BY btag ORDER BY signups DESC, btag
    """)
    for b in by_btag:
        b["ftd_rate"] = ratio(b["ftd"], b["signups"])
        b["active_rate"] = ratio(b["active"], b["signups"])
    return {
        "metrics": {
            **t,
            "total_clients_in_file": total_clients,
            "ftd_rate": ratio(t["ftd"], t["signups"]) if ctx.has_payments else None,
            "active_rate": ratio(t["active"], t["signups"]),
        },
        "kyc": kyc,
        "by_btag": by_btag,
    }
