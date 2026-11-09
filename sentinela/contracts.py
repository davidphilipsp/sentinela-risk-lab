"""CSV data contracts: header mapping, typing, validation and pseudonymization.

Every CSV goes through this module before any metric is computed. The output is
a typed DuckDB table (one per dataset) plus a ``DatasetReport`` that records
exactly what was accepted, what was rejected and why.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb

DEFAULT_DATE_FORMATS = [
    "%Y-%m-%d",
    "%d/%m/%Y",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
]

NUMERIC_TYPES = {"decimal", "integer"}

# Headers that carry direct personal data. They are never loaded into analysis tables;
# the report lists them as "PII descartada" so the discard is explicit and auditable.
PII_HEADER_PATTERN = re.compile(
    r"(^|_)(e_?mail|mail|phone|telefone|tel|celular|cel|whatsapp|mobile|cpf|cnpj|rg|documento|document|doc|"
    r"sobrenome|surname|endereco|address|rua|cep|zip|postal|ip|ip_address|"
    r"nascimento|birth|birthdate|data_nascimento|dob|senha|password|cartao|card|pan|iban|chave_pix|pix_key)($|_)"
)
# Person names only: "provider_name" / "game_name" are NOT personal data.
PERSON_NAME_PATTERN = re.compile(
    r"^(nome|name|full_name|first_name|last_name|given_name|family_name|"
    r"(user|player|customer|client|cliente|jogador|usuario)_(name|nome)|nome_(completo|cliente|jogador|usuario|social|mae|pai))$"
)


def is_pii_header(header: str) -> bool:
    norm = normalize_header(header)
    return bool(PII_HEADER_PATTERN.search(norm) or PERSON_NAME_PATTERN.match(norm))
PSEUDONYM_PREFIX = "P-"


class ContractError(Exception):
    """Raised when a dataset cannot be loaded under its contract."""

    def __init__(self, message: str, report: "DatasetReport | None" = None):
        super().__init__(message)
        self.report = report


@dataclass
class Issue:
    check_id: str
    severity: str  # error | warning | info
    count: int
    description: str
    column: str | None = None
    examples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "count": self.count,
            "column": self.column,
            "description": self.description,
            "examples": self.examples,
        }


@dataclass
class DatasetReport:
    name: str
    path: str
    sha256: str
    rows_raw: int = 0
    rows_loaded: int = 0
    rows_dropped: int = 0
    rows_with_errors: int = 0
    rows_with_warnings: int = 0
    delimiter: str | None = None
    decimal_separator: str | None = None
    column_mapping: dict[str, str] = field(default_factory=dict)
    ignored_columns: list[str] = field(default_factory=list)
    pii_discarded: list[str] = field(default_factory=list)
    defaulted_columns: list[str] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(i.count for i in self.issues if i.severity == "error")

    @property
    def status(self) -> str:
        if any(i.severity == "error" for i in self.issues):
            return "FALHA" if self.rows_dropped == 0 else "CORRIGIDO (linhas removidas)"
        if any(i.severity == "warning" for i in self.issues):
            return "ALERTA"
        return "OK"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "rows_raw": self.rows_raw,
            "rows_loaded": self.rows_loaded,
            "rows_dropped": self.rows_dropped,
            "rows_with_errors": self.rows_with_errors,
            "rows_with_warnings": self.rows_with_warnings,
            "delimiter": self.delimiter,
            "decimal_separator": self.decimal_separator,
            "column_mapping": self.column_mapping,
            "ignored_columns": self.ignored_columns,
            "pii_discarded": self.pii_discarded,
            "defaulted_columns": self.defaulted_columns,
            "status": self.status,
            "issues": [i.as_dict() for i in self.issues],
        }


# --------------------------------------------------------------------------- utils

def normalize_header(value: str) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def normalize_value_token(value: str) -> str:
    return normalize_header(value)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pseudonymize(raw_id: str, secret: str) -> str:
    """Python twin of the SQL pseudonymization (used by `sentinela lookup`)."""
    token = hashlib.sha256(f"{secret}|{raw_id.strip()}".encode("utf-8")).hexdigest()[:16]
    return f"{PSEUDONYM_PREFIX}{token}"


def qident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def qlit(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


# --------------------------------------------------------------------------- mapping

def map_columns(
    headers: list[str], spec: dict[str, Any], column_map: dict[str, str] | None = None
) -> tuple[dict[str, str], list[str]]:
    """Return ({canonical: source_header}, ignored_headers)."""
    column_map = column_map or {}
    columns: dict[str, Any] = spec["columns"]
    by_norm = {normalize_header(h): h for h in headers}
    mapping: dict[str, str] = {}

    # 1) explicit mapping from the study file wins
    for source, canonical in column_map.items():
        if canonical not in columns:
            raise ContractError(
                f"column_map aponta para coluna desconhecida '{canonical}'. "
                f"Colunas válidas: {', '.join(columns)}"
            )
        src = by_norm.get(normalize_header(source))
        if src is None:
            raise ContractError(f"column_map: cabeçalho '{source}' não existe no CSV.")
        mapping[canonical] = src

    used = set(mapping.values())
    # 2) canonical name, 3) aliases
    for canonical, col_spec in columns.items():
        if canonical in mapping:
            continue
        candidates = [canonical] + list(col_spec.get("aliases", []))
        for candidate in candidates:
            src = by_norm.get(normalize_header(candidate))
            if src is not None and src not in used:
                mapping[canonical] = src
                used.add(src)
                break

    ignored = [h for h in headers if h not in used]
    return mapping, ignored


# --------------------------------------------------------------------------- numbers

_NUM_CLEAN = "regexp_replace(regexp_replace(trim({c}), '^R\\$\\s*', ''), '\\s+', '', 'g')"


def _clean_num_sql(col_sql: str) -> str:
    cleaned = _NUM_CLEAN.format(c=col_sql)
    # accounting negatives: (123,45) -> -123,45
    return (
        f"(CASE WHEN regexp_full_match({cleaned}, '^\\(.*\\)$') "
        f"THEN '-' || substr({cleaned}, 2, length({cleaned}) - 2) ELSE {cleaned} END)"
    )


def _decimal_sql(col_sql: str, sep: str) -> str:
    x = _clean_num_sql(col_sql)
    if sep == ",":
        pattern = r"^-?(\d{1,3}(\.\d{3})+|\d+)(,\d+)?$"
        converted = f"replace(replace({x}, '.', ''), ',', '.')"
    else:
        pattern = r"^-?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?$"
        converted = f"replace({x}, ',', '')"
    return (
        f"(CASE WHEN regexp_full_match({x}, '{pattern}') "
        f"THEN TRY_CAST({converted} AS DECIMAL(38,6)) END)"
    )


def detect_decimal_separator(
    con: duckdb.DuckDBPyConnection, raw_table: str, numeric_sources: list[str]
) -> str:
    """Decide '.' or ',' from the data itself; refuse to guess when ambiguous."""
    if not numeric_sources:
        return "."
    parts = []
    for src in numeric_sources:
        c = _NUM_CLEAN.format(c=qident(src))
        parts.append(f"SELECT {c} AS v FROM {raw_table} WHERE {qident(src)} IS NOT NULL")
    union = " UNION ALL ".join(parts)
    row = con.execute(
        f"""
        SELECT
          count(*) FILTER (WHERE regexp_full_match(v, '^-?\\d+,(\\d{{1,2}}|\\d{{4,}})$')
                              OR regexp_full_match(v, '^-?\\d{{1,3}}(\\.\\d{{3}})+,\\d+$')) AS comma_dec,
          count(*) FILTER (WHERE regexp_full_match(v, '^-?\\d+\\.(\\d{{1,2}}|\\d{{4,}})$')
                              OR regexp_full_match(v, '^-?\\d{{1,3}}(,\\d{{3}})+\\.\\d+$')) AS dot_dec,
          count(*) FILTER (WHERE regexp_full_match(v, '^-?\\d{{1,3}}(,\\d{{3}})+$')) AS comma_three,
          count(*) FILTER (WHERE regexp_full_match(v, '^-?\\d{{1,3}}(\\.\\d{{3}})+$')) AS dot_three
        FROM ({union})
        """
    ).fetchone()
    comma_dec, dot_dec, comma_three, dot_three = row
    if comma_dec and dot_dec:
        raise ContractError(
            "Separador decimal misto no mesmo arquivo (valores '1,5' e '1.5'). "
            "Corrija o CSV ou defina decimal_separator no estudo."
        )
    if comma_dec:
        return ","
    if dot_dec:
        return "."
    if comma_three or dot_three:
        raise ContractError(
            "Separador decimal ambíguo (ex.: '1,234' ou '1.234' podem ser milhar ou decimal). "
            "Defina decimal_separator: \".\" ou \",\" no estudo para este arquivo."
        )
    return "."


# --------------------------------------------------------------------------- loader

def load_dataset(
    con: duckdb.DuckDBPyConnection,
    name: str,
    spec: dict[str, Any],
    input_cfg: dict[str, Any],
    secret: str,
    on_error: str = "fail",
) -> DatasetReport:
    """Load, type and validate one CSV into DuckDB table ``name``."""
    path = Path(input_cfg["path"])
    if not path.exists():
        raise ContractError(f"[{name}] arquivo não encontrado: {path}")

    report = DatasetReport(name=name, path=str(path), sha256=file_sha256(path))
    raw = f"raw_{name}"

    read_opts = ["header=true", "all_varchar=true", "sample_size=-1"]
    delimiter = input_cfg.get("delimiter", "auto")
    if delimiter and delimiter != "auto":
        read_opts.append(f"delim={qlit(delimiter)}")
    if input_cfg.get("encoding"):
        read_opts.append(f"encoding={qlit(input_cfg['encoding'])}")
    try:
        con.execute(
            f"CREATE OR REPLACE TEMP TABLE {raw} AS "
            f"SELECT *, row_number() OVER () + 1 AS _line FROM read_csv({qlit(str(path))}, {', '.join(read_opts)})"
        )
    except duckdb.Error as exc:
        raise ContractError(f"[{name}] não foi possível ler o CSV: {exc}") from exc

    report.delimiter = delimiter if delimiter != "auto" else _sniff_delimiter(con, path)
    headers = [r[0] for r in con.execute(f"DESCRIBE {raw}").fetchall() if r[0] != "_line"]
    report.rows_raw = con.execute(f"SELECT count(*) FROM {raw}").fetchone()[0]

    mapping, ignored = map_columns(headers, spec, input_cfg.get("column_map"))
    report.column_mapping = dict(mapping)
    report.pii_discarded = [h for h in ignored if is_pii_header(h)]
    report.ignored_columns = [h for h in ignored if h not in report.pii_discarded]

    columns: dict[str, Any] = spec["columns"]
    missing = [c for c, s in columns.items() if s.get("required") and c not in mapping]
    if missing:
        raise ContractError(
            f"[{name}] colunas obrigatórias ausentes: {', '.join(missing)}. "
            f"Cabeçalhos encontrados: {', '.join(headers)}. "
            "Use column_map no estudo para mapear seus cabeçalhos.",
            report,
        )

    numeric_sources = [mapping[c] for c, s in columns.items() if s["type"] in NUMERIC_TYPES and c in mapping]
    sep = input_cfg.get("decimal_separator", "auto")
    if sep in (None, "auto"):
        try:
            sep = detect_decimal_separator(con, raw, numeric_sources)
        except ContractError as exc:
            raise ContractError(f"[{name}] {exc}", report) from exc
    if sep not in (".", ","):
        raise ContractError(f"[{name}] decimal_separator deve ser '.', ',' ou 'auto'.", report)
    report.decimal_separator = sep
    date_formats = input_cfg.get("date_formats") or DEFAULT_DATE_FORMATS
    date_list = "[" + ", ".join(qlit(f) for f in date_formats) + "]"

    # ---- build typed projection + per-column violation flags
    select_parts: list[str] = ["_line"]
    checks: list[tuple[str, str, str, str, str | None]] = []  # (check_id, severity, flag_sql, description, column)

    for canonical, col_spec in columns.items():
        ctype = col_spec["type"]
        if canonical not in mapping:
            default = col_spec.get("default")
            report.defaulted_columns.append(canonical)
            if default is None:
                select_parts.append(f"NULL::{_sql_type(ctype)} AS {qident(canonical)}")
            else:
                select_parts.append(f"{qlit(default)}::{_sql_type(ctype)} AS {qident(canonical)}")
            continue

        src = qident(mapping[canonical])
        raw_present = f"(nullif(trim({src}), '') IS NOT NULL)"
        select_parts.append(f"{raw_present} AS {qident('_has_' + canonical)}")

        if ctype == "string":
            expr = f"nullif(trim({src}), '')"
            allowed = col_spec.get("allowed_values")
            if allowed:
                whens = []
                for canon_value, value_aliases in allowed.items():
                    tokens = sorted({normalize_value_token(canon_value), *(normalize_value_token(a) for a in value_aliases)})
                    token_list = ", ".join(qlit(t) for t in tokens)
                    whens.append(f"WHEN {_sql_token(expr)} IN ({token_list}) THEN {qlit(canon_value)}")
                expr = f"(CASE {' '.join(whens)} ELSE NULL END)"
            if col_spec.get("pii"):
                expr = f"(CASE WHEN {expr} IS NULL THEN NULL ELSE {qlit(PSEUDONYM_PREFIX)} || sha256({qlit(secret)} || '|' || {expr})[:16] END)"
        elif ctype == "date":
            expr = f"TRY_CAST(try_strptime(trim({src}), {date_list}) AS DATE)"
        elif ctype == "decimal":
            expr = _decimal_sql(src, sep)
        elif ctype == "integer":
            dec = _decimal_sql(src, sep)
            expr = f"(CASE WHEN {dec} = floor({dec}) THEN TRY_CAST({dec} AS BIGINT) END)"
        else:
            raise ContractError(f"[{name}] tipo desconhecido no contrato: {ctype}")

        default = col_spec.get("default")
        if default is not None and not col_spec.get("required"):
            # default applies only when the raw cell is empty, never to invalid values
            expr = f"(CASE WHEN {raw_present} THEN {expr} ELSE {qlit(default)}::{_sql_type(ctype)} END)"
        select_parts.append(f"{expr} AS {qident(canonical)}")

    typed = f"typed_{name}"
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE {typed} AS SELECT {', '.join(select_parts)} FROM {raw}"
    )

    for canonical, col_spec in columns.items():
        if canonical not in mapping:
            continue
        col = qident(canonical)
        has = qident("_has_" + canonical)
        ctype = col_spec["type"]
        if col_spec.get("required"):
            checks.append((f"{canonical}.obrigatorio", "error", f"NOT {has}",
                           f"'{canonical}' vazio (coluna obrigatória)", canonical))
        label = "valor fora da lista permitida" if col_spec.get("allowed_values") else f"valor inválido para tipo {ctype}"
        checks.append((f"{canonical}.tipo", "error", f"{has} AND {col} IS NULL",
                       f"'{canonical}': {label}", canonical))
        if "min" in col_spec:
            checks.append((f"{canonical}.min", "error", f"{col} < {col_spec['min']}",
                           f"'{canonical}' abaixo do mínimo {col_spec['min']}", canonical))
        if "max" in col_spec:
            checks.append((f"{canonical}.max", "error", f"{col} > {col_spec['max']}",
                           f"'{canonical}' acima do máximo {col_spec['max']}", canonical))

    for rule in spec.get("row_rules", []) or []:
        checks.append((f"regra.{rule['id']}", rule.get("severity", "error"),
                       f"NOT coalesce(({rule['expr']}), true)", rule.get("description", rule["expr"]), None))

    key = spec.get("key") or []
    if key and all(k in mapping for k in key):
        key_sql = ", ".join(qident(k) for k in key)
        not_null = " AND ".join(f"{qident(k)} IS NOT NULL" for k in key)
        checks.append(("chave.duplicada", spec.get("key_severity", "error"),
                       f"({not_null}) AND row_number() OVER (PARTITION BY {key_sql} ORDER BY _line) > 1",
                       f"chave duplicada ({', '.join(key)})", None))

    # materialize flags
    flag_cols = [f"({flag}) AS {qident('_chk_' + str(i))}" for i, (_, _, flag, _, _) in enumerate(checks)]
    flagged = f"flagged_{name}"
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE {flagged} AS SELECT *{', ' if flag_cols else ''}{', '.join(flag_cols)} FROM {typed}"
    )

    error_terms, warning_terms = [], []
    for i, (check_id, severity, _flag, description, column) in enumerate(checks):
        chk = qident(f"_chk_{i}")
        count = con.execute(f"SELECT count(*) FROM {flagged} WHERE coalesce({chk}, false)").fetchone()[0]
        (error_terms if severity == "error" else warning_terms).append(f"coalesce({chk}, false)")
        if not count:
            continue
        examples = _examples(con, flagged, raw, chk, mapping.get(column) if column else None,
                             bool(column and columns[column].get("pii")))
        report.issues.append(Issue(check_id, severity, int(count), description, column, examples))

    err_expr = " OR ".join(error_terms) or "false"
    warn_expr = " OR ".join(warning_terms) or "false"
    report.rows_with_errors = con.execute(f"SELECT count(*) FROM {flagged} WHERE {err_expr}").fetchone()[0]
    report.rows_with_warnings = con.execute(f"SELECT count(*) FROM {flagged} WHERE {warn_expr}").fetchone()[0]

    if report.rows_with_errors and on_error != "drop":
        raise ContractError(
            f"[{name}] {report.rows_with_errors} linha(s) violam o contrato. "
            "Corrija o CSV ou use on_contract_error: drop no estudo.",
            report,
        )

    keep = [qident(c) for c in columns]
    con.execute(
        f"CREATE OR REPLACE TABLE {name} AS SELECT _line, {', '.join(keep)} FROM {flagged} "
        f"WHERE NOT ({err_expr})"
    )
    report.rows_loaded = con.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
    report.rows_dropped = report.rows_raw - report.rows_loaded
    if report.rows_dropped:
        report.issues.append(Issue("linhas.removidas", "warning", report.rows_dropped,
                                   "linhas removidas por violar o contrato (on_contract_error: drop)"))
    for tbl in (raw, typed, flagged):
        con.execute(f"DROP TABLE IF EXISTS {tbl}")
    return report


def _examples(con, flagged: str, raw: str, chk: str, source_col: str | None, pii: bool) -> list[str]:
    lines = [r[0] for r in con.execute(
        f"SELECT _line FROM {flagged} WHERE coalesce({chk}, false) ORDER BY _line LIMIT 3"
    ).fetchall()]
    if source_col is None or pii:
        return [f"linha {ln}" for ln in lines]
    out = []
    for ln in lines:
        value = con.execute(f"SELECT {qident(source_col)} FROM {raw} WHERE _line = ?", [ln]).fetchone()[0]
        out.append(f"linha {ln}: {value!r}")
    return out


def _sniff_delimiter(con, path: Path) -> str | None:
    try:
        row = con.execute(f"SELECT Delimiter FROM sniff_csv({qlit(str(path))})").fetchone()
        return row[0] if row else None
    except duckdb.Error:
        return None


def _sql_type(ctype: str) -> str:
    return {"string": "VARCHAR", "date": "DATE", "decimal": "DECIMAL(38,6)", "integer": "BIGINT"}[ctype]


def _sql_token(expr: str) -> str:
    # same normalization as normalize_value_token(), in SQL
    return f"trim(regexp_replace(lower(strip_accents({expr})), '[^a-z0-9]+', '_', 'g'), '_')"
