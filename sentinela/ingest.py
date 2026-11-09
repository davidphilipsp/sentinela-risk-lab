"""Sanitizing ingestion: every file enters the system ONLY through here.

  source CSV ─► read in RAM ─► drop personal-data columns (by header AND by content)
             ─► re-encode as clean UTF-8 CSV (no BOM, no original name, no file metadata)
             ─► AES-256-GCM into the vault ─► verify by decrypting ─► wipe RAM copies
             ─► clean desktop traces of the source (recent files, thumbnails)
             ─► securely delete the source (unless --keep-source)
"""
from __future__ import annotations

import hashlib
import re
from datetime import date
from pathlib import Path
from typing import Any

import duckdb

from sentinela.contracts import is_pii_header, map_columns, qident, qlit
from sentinela.security import Vault, VaultError, Workspace, encrypt_file, decrypt_file, secure_delete, sha256_file
from sentinela.traces import clean_desktop_traces_for

# Content patterns for personal data hidden under neutral headers ("contato", "info", ...).
CONTENT_PATTERNS = {
    "e-mail": r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$",
    "CPF": r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$",
    "telefone": r"^\+?(55)?[\s.-]?\(?\d{2}\)?[\s.-]?9?\d{4}[\s.-]?\d{4}$",
    "cartão": r"^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$",
}
CONTENT_THRESHOLD = 0.30  # share of non-empty sampled values matching a pattern


def _read_options(delimiter: str | None, encoding: str | None) -> str:
    opts = ["header=true", "all_varchar=true", "sample_size=-1"]
    if delimiter and delimiter != "auto":
        opts.append(f"delim={qlit(delimiter)}")
    if encoding:
        opts.append(f"encoding={qlit(encoding)}")
    return ", ".join(opts)


def ingest_file(vault: Vault, source: Path, dataset: str, contracts: dict[str, Any], *,
                label: str | None = None, delimiter: str | None = None, encoding: str | None = None,
                column_map: dict[str, str] | None = None, only_contract: bool = False,
                keep_source: bool = False) -> dict[str, Any]:
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise VaultError(f"arquivo não encontrado: {source}")
    if dataset not in contracts["datasets"]:
        raise VaultError(f"dataset desconhecido '{dataset}'. Válidos: {', '.join(contracts['datasets'])}")
    spec = contracts["datasets"][dataset]
    label = label or f"{dataset}-{date.today().strftime('%Y%m%d')}-{len(vault.entries(dataset)) + 1}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label):
        raise VaultError("rótulo inválido (use letras, números, _ . -; até 64 caracteres).")
    source_sha = sha256_file(source)

    with Workspace("sentinela-ingest") as ws:
        con = duckdb.connect(config={"temp_directory": str(ws.path)})
        con.execute("SET autoinstall_known_extensions = false")
        con.execute("SET autoload_known_extensions = false")
        try:
            con.execute(f"CREATE TABLE raw AS SELECT * FROM read_csv({qlit(str(source))}, "
                        f"{_read_options(delimiter, encoding)})")
        except duckdb.Error as exc:
            raise VaultError(f"não foi possível ler o CSV: {exc}") from exc
        headers = [r[0] for r in con.execute("DESCRIBE raw").fetchall()]
        rows = con.execute("SELECT count(*) FROM raw").fetchone()[0]
        mapping, _ = map_columns(headers, spec, column_map)
        protected = set(mapping.values())  # contract columns (e.g. player_id that holds e-mails) are kept

        pii_header = [h for h in headers if is_pii_header(h) and h not in protected]
        pii_content: list[str] = []
        for h in headers:
            if h in protected or h in pii_header:
                continue
            col = qident(h)
            checks = ", ".join(
                f"count(*) FILTER (WHERE regexp_full_match(trim(v), {qlit(rx)})) AS {qident(name)}"
                for name, rx in CONTENT_PATTERNS.items())
            res = con.execute(f"SELECT count(*) AS n, {checks} FROM (SELECT {col} AS v FROM raw "
                              f"WHERE nullif(trim({col}), '') IS NOT NULL LIMIT 5000)").fetchone()
            n = res[0]
            if n and any(c / n >= CONTENT_THRESHOLD for c in res[1:]):
                pii_content.append(h)
        dropped = set(pii_header) | set(pii_content)
        keep = [h for h in headers if h not in dropped and (not only_contract or h in protected)]
        missing = [c for c, s_ in spec["columns"].items() if s_.get("required") and c not in mapping]
        if not keep:
            raise VaultError("nenhuma coluna restou após remover dados pessoais.")

        clean = ws.file("clean.csv")
        cols = ", ".join(qident(h) for h in keep)
        con.execute(f"COPY (SELECT {cols} FROM raw) TO {qlit(str(clean))} (HEADER, DELIMITER ',', QUOTE '\"')")
        con.close()
        clean_sha = sha256_file(clean)

        eid, target = vault.new_entry_path()
        encrypt_file(vault.keys, clean, target)
        verify = ws.file("verify.csv")
        decrypt_file(vault.keys, target, verify)
        if sha256_file(verify) != clean_sha:
            secure_delete(target)
            raise VaultError("verificação falhou: o arquivo cifrado não confere. Nada foi alterado.")

    entry = {
        "id": eid, "label": label, "dataset": dataset, "file": target.name, "rows": rows,
        "columns": keep, "pii_removed_by_header": pii_header, "pii_removed_by_content": pii_content,
        "required_missing": missing, "sha256": clean_sha, "source_sha256": source_sha,
        "source_name_sha256": hashlib.sha256(source.name.encode()).hexdigest(),
        "ingested": date.today().isoformat(),
    }
    vault.add_entry(entry)
    traces = clean_desktop_traces_for(source)
    if not keep_source:
        secure_delete(source)
    entry["_traces_cleaned"] = traces
    entry["_source_deleted"] = not keep_source
    return entry
