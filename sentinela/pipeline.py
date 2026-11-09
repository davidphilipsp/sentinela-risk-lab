"""End-to-end deterministic pipeline: contracts -> metrics -> risk -> checks -> insights."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from sentinela import __version__
from sentinela.behavior import analyze_behavior, profile_rows
from sentinela.checks import reconcile
from sentinela.contracts import ContractError, DatasetReport, load_dataset
from sentinela.engine import Ctx, affiliates, clients, executive, games, payments, prepare_views, providers
from sentinela.insights import build_insights
from sentinela.risk import score_players
from sentinela.security import Vault, Workspace, unlock
from sentinela.study import DATASETS, Study, load_config


class Session:
    """Unlocked keyring + RAM workspace + decrypted inputs for ONE run. Always use as a context manager."""

    def __init__(self, study: Study) -> None:
        self.study = study
        self.keys = unlock(study.home)
        self.vault = Vault(study.home, self.keys)
        self.ws = Workspace("sentinela-run")
        try:
            self.inputs = self._materialize()
        except Exception:
            self.ws.wipe()
            raise

    def _materialize(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for name, cfg in self.study.inputs.items():
            cfg = dict(cfg)
            if "vault" in cfg:
                entry = self.vault.resolve(cfg["vault"], name)
                cfg["path"] = str(self.vault.materialize(entry, self.ws))
                cfg["delimiter"] = ","          # vault content is always normalized UTF-8, comma-separated
                cfg.pop("encoding", None)
                cfg["display"] = f"vault:{entry['label']}"
            else:
                cfg["display"] = Path(cfg["path"]).name
            out[name] = cfg
        return out

    def close(self) -> None:
        self.ws.wipe()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def connect(ws: Workspace | None = None) -> duckdb.DuckDBPyConnection:
    config = {"temp_directory": str(ws.path)} if ws else {}
    con = duckdb.connect(database=":memory:", config=config)  # spills (if any) stay in the RAM workspace
    # Air-gap guarantee: DuckDB must never try to download extensions.
    con.execute("SET autoinstall_known_extensions = false")
    con.execute("SET autoload_known_extensions = false")
    return con


def load_inputs(study: Study, con: duckdb.DuckDBPyConnection, session: Session) -> tuple[dict[str, DatasetReport], dict[str, Any], str]:
    contracts, contracts_hash = load_config("contracts.yaml", study.contracts_path)
    secret = session.keys.pseudo_secret
    reports: dict[str, DatasetReport] = {}
    for name in DATASETS:
        if name in session.inputs:
            cfg = session.inputs[name]
            rep = load_dataset(con, name, contracts["datasets"][name], cfg, secret, study.on_contract_error)
            rep.path = cfg["display"]  # never expose RAM paths or original file names
            reports[name] = rep
    return reports, contracts, contracts_hash


def analyze(study: Study, session: Session | None = None) -> dict[str, Any]:
    if session is None:
        with Session(study) as own:
            return analyze(study, own)
    con = connect(session.ws)
    try:
        return _analyze(study, session, con)
    finally:
        con.close()


def _analyze(study: Study, session: Session, con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    reports, contracts, contracts_hash = load_inputs(study, con, session)
    rules, rules_hash = load_config("rules.yaml", study.rules_path)
    behavior_cfg, behavior_hash = load_config("behavior.yaml", study.behavior_path)
    sections_cfg, _ = load_config("sections.yaml")

    ctx = Ctx(con=con, start=study.start, end=study.end, rules=rules, datasets=set(reports))
    prepare_views(ctx)

    n_rows = con.execute("SELECT count(*) FROM act").fetchone()[0]
    if n_rows == 0:
        raise ContractError(
            f"Nenhuma linha de atividade dentro do período {study.start} a {study.end}. "
            "Confira study.period e a coluna de data do CSV."
        )

    wanted = set(study.sections)
    skipped: dict[str, str] = {}
    results: dict[str, Any] = {}

    ex = executive(ctx)
    results["executive"] = ex
    risk = score_players(ctx)  # always computed: feeds affiliates and checks
    if "players" in wanted:
        results["players"] = risk
    bulk: dict[str, Any] = {}
    if "behavior" in wanted:
        results["behavior"] = analyze_behavior(ctx, behavior_cfg)
        bulk = results["behavior"].pop("_bulk")
        bulk["profile"] = profile_rows(ctx)
    if "providers" in wanted:
        results["providers"] = providers(ctx, ex["metrics"])
    if "affiliates" in wanted:
        results["affiliates"] = affiliates(ctx, ex["metrics"], risk["flagged_threshold"])
    if "games" in wanted:
        g = games(ctx, ex["metrics"])
        if g.get("available"):
            results["games"] = g
        else:
            skipped["games"] = g["reason"]
    if "payments" in wanted:
        if ctx.has_payments:
            results["payments"] = payments(ctx)
        else:
            skipped["payments"] = "payments.csv não informado no estudo."
    if "clients" in wanted:
        if ctx.has_clients:
            results["clients"] = clients(ctx)
        else:
            skipped["clients"] = "clients.csv não informado no estudo."

    checks = reconcile(ctx, results, reports)
    insights = build_insights(results, checks, rules)

    input_hashes = {name: rep.sha256 for name, rep in reports.items()}
    fingerprint = json.dumps({
        "version": __version__,
        "study": study.sha256(),
        "contracts": contracts_hash,
        "rules": rules_hash,
        "behavior": behavior_hash,
        "inputs": input_hashes,
    }, sort_keys=True)
    run_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    return {
        "meta": {
            "tool": "Sentinela Risk Lab",
            "version": __version__,
            "run_id": run_id,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "title": study.title,
            "subtitle": study.subtitle,
            "author": study.author,
            "currency": study.currency,
            "period": {"start": study.start, "end": study.end, "days": study.days},
            "sections": [s for s in study.sections if s in results or s == "data_quality"],
            "skipped_sections": skipped,
            "study_file": str(study.path.name),
            "study_sha256": study.sha256(),
            "contracts_version": contracts.get("version"),
            "contracts_sha256": contracts_hash,
            "rules_version": rules.get("version"),
            "rules_sha256": rules_hash,
            "behavior_version": behavior_cfg.get("version"),
            "behavior_sha256": behavior_hash,
            "input_sha256": input_hashes,
            "ai_used": False,
            "pseudonymization": "sha256(chave_local | player_id)[:16] aplicado na carga; IDs brutos nunca entram nos resultados",
            "encryption": {
                "inputs": "plaintext (modo de teste)" if study.plaintext_inputs else "cofre AES-256-GCM",
                "outputs": "plaintext (modo de teste)" if study.plaintext_outputs else "cofre AES-256-GCM",
                "workspace": "RAM (tmpfs)" if session.ws.is_ram else "disco temporário (fora do Linux)",
            },
        },
        "datasets": {name: rep.as_dict() for name, rep in reports.items()},
        "results": results,
        "checks": checks,
        "insights": insights,
        "notes": ctx.notes,
        "rules": rules,
        "sections_cfg": sections_cfg["sections"],
        "behavior_cfg": behavior_cfg,
        "_bulk": bulk,  # per-player lists: exported as CSV, never serialized into evidence.json
    }
