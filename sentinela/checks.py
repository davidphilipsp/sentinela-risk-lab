"""Reconciliation checks: the numbers must close before anyone reads them."""
from __future__ import annotations

from decimal import Decimal
from typing import Any

from sentinela.engine import Ctx, D, one


def _check(cid: str, description: str, status: str, expected: Any = None, actual: Any = None,
           detail: str = "", section: str = "data_quality") -> dict[str, Any]:
    diff = None
    if expected is not None and actual is not None:
        try:
            diff = D(actual) - D(expected)
        except Exception:  # noqa: BLE001
            diff = None
    return {"id": cid, "section": section, "description": description, "status": status,
            "expected": expected, "actual": actual, "diff": diff, "detail": detail}


def _equal(cid: str, description: str, expected: Any, actual: Any, section: str) -> dict[str, Any]:
    status = "PASS" if D(expected) == D(actual) else "FALHA"
    return _check(cid, description, status, expected, actual, section=section)


def reconcile(ctx: Ctx, results: dict[str, Any], dataset_reports: dict[str, Any]) -> list[dict[str, Any]]:
    con = ctx.con
    tol = Decimal(str(ctx.rules["insights"]["coverage_tolerance"]))
    ex = results["executive"]["metrics"]
    out: list[dict[str, Any]] = []

    for metric in ("turnover", "ggr"):
        if "providers" in results:
            total = sum((D(p[metric]) for p in results["providers"]["providers"]), D(0))
            out.append(_equal(f"R1.{metric}", f"Σ providers = total executivo ({metric})", ex[metric], total, "providers"))
        if "affiliates" in results:
            total = sum((D(a[metric]) for a in results["affiliates"]["affiliates"]), D(0))
            out.append(_equal(f"R3.{metric}", f"Σ btags = total executivo ({metric})", ex[metric], total, "affiliates"))
        total = sum((D(d[metric]) for d in results["executive"]["daily"]), D(0))
        out.append(_equal(f"R4.{metric}", f"Σ dias = total executivo ({metric})", ex[metric], total, "executive"))

    pl = one(con, "SELECT coalesce(sum(turnover),0) AS turnover, coalesce(sum(ggr),0) AS ggr FROM player_features")
    out.append(_equal("R2.turnover", "Σ players = total executivo (turnover)", ex["turnover"], pl["turnover"], "players"))
    out.append(_equal("R2.ggr", "Σ players = total executivo (ggr)", ex["ggr"], pl["ggr"], "players"))

    bh = results.get("behavior")
    if bh:
        lc_players = sum(r["players"] for r in bh["lifecycle"])
        out.append(_equal("R11.players", "Σ estágios de ciclo de vida = universo de players", bh["universe"], lc_players, "behavior"))
        lc_turn = sum((D(r["turnover"]) for r in bh["lifecycle"]), D(0))
        out.append(_equal("R11.turnover", "Σ estágios (turnover) = total executivo", ex["turnover"], lc_turn, "behavior"))
        tier_players = sum(r["players"] for r in bh["value_tiers"]["tiers"])
        out.append(_equal("R11.tiers", "Σ faixas de valor = universo de players", bh["universe"], tier_players, "behavior"))
        if "payments" in results:
            lc_dep = sum((D(r["deposits"]) for r in bh["lifecycle"]), D(0))
            out.append(_equal("R12.deposits", "Σ estágios (depósitos) = depósitos aprovados do período",
                              results["payments"]["metrics"]["deposits"], lc_dep, "behavior"))

    g = results.get("games")
    if g and g.get("available") and g.get("mode") == "metrics":
        cov = g["coverage_vs_activity"]
        if cov is None:
            status, detail = "ALERTA", "sem turnover de atividade para comparar"
        elif cov > 1 + tol:
            status, detail = "FALHA", "jogos somam MAIS turnover que a atividade: possível dupla contagem ou bases desalinhadas"
        elif g["source"] == "games.csv" and cov < 1 - tol:
            status, detail = "ALERTA", "games.csv cobre menos turnover que a atividade (jogos ausentes)"
        elif cov < 1 - tol:
            status, detail = "INFO", "top_jogos cobre apenas os principais jogos (cobertura parcial esperada)"
        else:
            status, detail = "PASS", ""
        out.append(_check("R5.games", "Turnover de jogos vs. atividade", status,
                          ex["turnover"], g["total_turnover"], f"cobertura {cov}. {detail}".strip(), "games"))
    elif g and g.get("available"):
        out.append(_check("R5.games", "Jogos sem métricas por jogo", "INFO",
                          detail="top_jogos não contém turnover/ggr por jogo: seção mostra apenas aparições", section="games"))

    missing = results["executive"]["missing_days"]
    out.append(_check("R6.coverage", "Dias do período com dados", "PASS" if not missing else "ALERTA",
                      ex["period_days"], ex["period_days"] - len(missing),
                      ("dias sem dados: " + ", ".join(d.isoformat() for d in missing[:15])
                       + (" …" if len(missing) > 15 else "")) if missing else "", "executive"))

    outside = one(con, f"""
        SELECT count(*) AS n FROM activity WHERE dia NOT BETWEEN DATE '{ctx.start}' AND DATE '{ctx.end}'
    """)["n"]
    out.append(_check("R7.outside", "Linhas de atividade fora do período (ignoradas)", "INFO", actual=outside))

    if ctx.has_payments and "payments" in results:
        n = results["payments"]["metrics"]["players_paying_without_activity"]
        out.append(_check("R8.pay_no_activity", "Players com pagamento aprovado e sem atividade de cassino",
                          "INFO" if not n else "ALERTA", actual=n, section="payments",
                          detail="pode indicar atividade em sportsbook (fora da base) ou ciclo depósito→saque sem jogo"))

    for name, rep in dataset_reports.items():
        if rep.rows_dropped:
            out.append(_check(f"R9.{name}", f"Linhas removidas pelo contrato ({name})", "ALERTA",
                              rep.rows_raw, rep.rows_loaded,
                              "números calculados SEM essas linhas; veja a seção de contratos"))
        if rep.rows_with_warnings:
            out.append(_check(f"R10.{name}", f"Linhas com alertas de regra ({name})", "ALERTA",
                              actual=rep.rows_with_warnings, detail="mantidas no cálculo; ver detalhes do contrato"))
    return out
