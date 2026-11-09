"""Study file (study.yaml): the declarative contract of one analysis request.

It replaces the LLM orchestrator of the original squad: title, period, inputs,
sections and privacy are explicit, versionable and reproducible.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

ALL_SECTIONS = ["executive", "behavior", "providers", "players", "affiliates", "games", "payments", "clients", "data_quality"]
DATASETS = ["activity", "games", "payments", "clients"]
FORMATS = {"html", "pdf", "json", "csv"}


class StudyError(Exception):
    pass


@dataclass
class Study:
    path: Path
    title: str
    subtitle: str
    author: str
    start: date
    end: date
    currency: str
    inputs: dict[str, dict[str, Any]]
    sections: list[str]
    on_contract_error: str
    output_dir: Path
    formats: set[str]
    home: Path
    plaintext_inputs: bool = False
    plaintext_outputs: bool = False
    contracts_path: Path | None = None
    rules_path: Path | None = None
    behavior_path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def days(self) -> int:
        return (self.end - self.start).days + 1

    def sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


def _as_date(value: Any, label: str) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise StudyError(f"{label} deve estar no formato AAAA-MM-DD (recebido: {value!r}).") from exc


def load_study(path: str | Path) -> Study:
    path = Path(path).resolve()
    if not path.exists():
        raise StudyError(f"Arquivo de estudo não encontrado: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    base = path.parent

    meta = data.get("study") or {}
    title = str(meta.get("title") or "").strip()
    if not title:
        raise StudyError("study.title é obrigatório (nomeia o relatório e a pasta de saída).")
    period = meta.get("period") or {}
    if "start" not in period or "end" not in period:
        raise StudyError("study.period.start e study.period.end são obrigatórios (reprodutibilidade).")
    start = _as_date(period["start"], "study.period.start")
    end = _as_date(period["end"], "study.period.end")
    if start > end:
        raise StudyError("study.period.start deve ser anterior ou igual a study.period.end.")

    inputs_raw = data.get("inputs") or {}
    unknown = set(inputs_raw) - set(DATASETS)
    if unknown:
        raise StudyError(f"inputs desconhecidos: {', '.join(sorted(unknown))}. Válidos: {', '.join(DATASETS)}")
    if "activity" not in inputs_raw:
        raise StudyError("inputs.activity é obrigatório (CSV de atividade de cassino).")
    security = data.get("security") or {}
    plaintext_inputs = bool(security.get("plaintext_inputs", False))
    plaintext_outputs = bool(security.get("plaintext_outputs", False))
    inputs: dict[str, dict[str, Any]] = {}
    for name, cfg in inputs_raw.items():
        if cfg is None:
            continue
        if isinstance(cfg, str):
            cfg = {"vault": cfg[6:]} if cfg.startswith("vault:") else {"path": cfg}
        cfg = dict(cfg)
        if "vault" in cfg:
            cfg["vault"] = str(cfg["vault"])
        elif "path" in cfg:
            if not plaintext_inputs:
                raise StudyError(
                    f"inputs.{name}: arquivos em texto puro não são aceitos (regra de segurança). "
                    f"Ingira no cofre: sentinela ingest {cfg['path']} --dataset {name} "
                    f"e use  {name}: {{vault: latest}}  no estudo."
                )
            cfg["path"] = str((base / cfg["path"]).resolve())
        else:
            raise StudyError(f"inputs.{name}: informe vault: <rótulo|latest>.")
        inputs[name] = cfg

    sections = data.get("sections") or ALL_SECTIONS
    bad = [s for s in sections if s not in ALL_SECTIONS]
    if bad:
        raise StudyError(f"seções desconhecidas: {', '.join(bad)}. Válidas: {', '.join(ALL_SECTIONS)}")
    if "data_quality" not in sections:
        sections = list(sections) + ["data_quality"]  # never optional

    on_error = data.get("on_contract_error", "fail")
    if on_error not in ("fail", "drop"):
        raise StudyError("on_contract_error deve ser 'fail' ou 'drop'.")

    output = data.get("output") or {}
    formats = set(output.get("formats") or ["html", "pdf", "json", "csv"])
    if formats - FORMATS:
        raise StudyError(f"output.formats inválidos: {', '.join(sorted(formats - FORMATS))}")

    def opt_path(value: Any) -> Path | None:
        return (base / value).resolve() if value else None

    return Study(
        path=path,
        title=title,
        subtitle=str(meta.get("subtitle") or "Inteligência de risco · cálculo determinístico local").strip(),
        author=str(meta.get("author") or "").strip(),
        start=start,
        end=end,
        currency=str(meta.get("currency") or "BRL"),
        inputs=inputs,
        sections=list(sections),
        on_contract_error=on_error,
        output_dir=(base / output.get("dir", "../outputs")).resolve(),
        formats=formats,
        home=(base / security.get("home", "..")).resolve(),
        plaintext_inputs=plaintext_inputs,
        plaintext_outputs=plaintext_outputs,
        contracts_path=opt_path(data.get("contracts")),
        rules_path=opt_path(data.get("rules")),
        behavior_path=opt_path(data.get("behavior")),
        raw=data,
    )


def load_secret(study: "Study") -> str:
    """Pseudonymization key: lives inside the encrypted keyring, never in plaintext."""
    from sentinela.security import unlock

    return unlock(study.home).pseudo_secret


def load_config(name: str, override: Path | None = None) -> tuple[dict[str, Any], str]:
    """Load a packaged YAML config (or an override) and return (data, sha256)."""
    if override:
        text = Path(override).read_text(encoding="utf-8")
    else:
        text = resources.files("sentinela.config").joinpath(name).read_text(encoding="utf-8")
    return yaml.safe_load(text), hashlib.sha256(text.encode("utf-8")).hexdigest()


STUDY_TEMPLATE = """\
# =============================================================================
# Sentinela Risk Lab — STUDY FILE
# One file = one analysis. Paths are relative to THIS file.
# =============================================================================
study:
  title: "{title}"
  subtitle: "Inteligência de risco · cálculo determinístico local"
  author: ""
  period:
    start: {start}       # AAAA-MM-DD (obrigatório)
    end: {end}         # AAAA-MM-DD (obrigatório)
  currency: BRL

inputs:                             # SOMENTE dados do cofre (regra de segurança)
  activity:                         # OBRIGATÓRIO
    vault: latest                   # latest = última ingestão desse dataset, ou um rótulo
    decimal_separator: auto         # auto | "." | ","
    # date_formats: ["%d/%m/%Y"]
    # column_map:                   # seu cabeçalho -> coluna do contrato
    #   "Data da Aposta": dia
    #   "ID Usuario": player_id
  # games:
  #   vault: latest
  # payments:
  #   vault: latest
  # clients:
  #   vault: latest
  # Antes:  sentinela ingest ~/Downloads/arquivo.csv --dataset activity

sections: [executive, behavior, providers, players, affiliates, games, payments, clients, data_quality]

on_contract_error: fail             # fail = aborta | drop = remove linhas inválidas (registrado)

security:
  home: ..                          # raiz do projeto: keyring (.sentinela/) e cofre (vault/)
  # plaintext_inputs: false         # NUNCA ative em produção
  # plaintext_outputs: false        # relatórios ficam cifrados no cofre (sentinela view / export)

output:
  formats: [html, pdf, json, csv]

# rules: ../my-rules.yaml           # sobrescreve limiares de risco (opcional)
# contracts: ../my-contracts.yaml   # sobrescreve contratos (opcional)
# behavior: ../my-behavior.yaml     # suas definições de ciclo de vida, faixas e segmentos (opcional)
"""
