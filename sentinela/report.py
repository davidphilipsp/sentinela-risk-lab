"""Output writers: evidence JSON, CSV tables, HTML report and PDF export."""
from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
import unicodedata
from datetime import date, datetime
from decimal import Decimal
from importlib import resources
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape
from markupsafe import Markup

from sentinela import charts
from sentinela.formatting import money, number, percent, pp
from sentinela.study import Study


def slugify(value: str, max_length: int = 60) -> str:
    text = unicodedata.normalize("NFKD", value or "").encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return (slug[:max_length].rstrip("-")) or "estudo"


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"not serializable: {type(value)}")


def to_json(evidence: dict[str, Any]) -> str:
    public = {k: v for k, v in evidence.items() if not k.startswith("_")}
    return json.dumps(public, default=_json_default, ensure_ascii=False, indent=2, sort_keys=False)


def _csv_value(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, float):
        return repr(round(value, 10))
    return value


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _csv_value(v) for k, v in r.items()})


def table_exports(evidence: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    res = evidence["results"]
    out: dict[str, list[dict[str, Any]]] = {"daily": res["executive"]["daily"]}
    if "behavior" in res:
        b = res["behavior"]
        out["behavior_lifecycle"] = b["lifecycle"]
        out["behavior_value_tiers"] = b["value_tiers"]["tiers"]
        out["behavior_matrix"] = b["matrix"]
        out["behavior_segments"] = b["segments"]
        out["behavior_cohorts"] = b["cohorts"]["table"]
        out["behavior_retention"] = b["cohorts"]["retention"]
        for key in ("day_of_month", "weekday", "time_to_ftd"):
            if key in b["rhythm"]:
                out[f"behavior_{key}"] = b["rhythm"][key]
        bulk = evidence.get("_bulk") or {}
        if bulk.get("profile"):
            out["player_profile"] = bulk["profile"]
        for seg_id, members in (bulk.get("members") or {}).items():
            out[f"segments/{seg_id}"] = members
    if "providers" in res:
        out["providers"] = res["providers"]["providers"]
    if "players" in res:
        out["players_flagged"] = res["players"]["flagged"]
        out["players_scored"] = res["players"]["all_scored"]
        out["players_exposure_top20"] = res["players"]["exposure_top"]
        out["risk_flags"] = res["players"]["flag_counts"]
    if "affiliates" in res:
        out["affiliates"] = res["affiliates"]["affiliates"]
    if "games" in res:
        out["games"] = res["games"]["games"]
    if "payments" in res:
        out["payments_daily"] = res["payments"]["daily"]
    if "clients" in res:
        out["clients_by_btag"] = res["clients"]["by_btag"]
        out["clients_kyc"] = res["clients"]["kyc"]
    out["checks"] = evidence["checks"]
    out["insights"] = evidence["insights"]
    issues = []
    for name, ds in evidence["datasets"].items():
        for i in ds["issues"]:
            issues.append({"dataset": name, **{k: (", ".join(v) if isinstance(v, list) else v) for k, v in i.items()}})
    out["contract_issues"] = issues
    return out


def render_html(evidence: dict[str, Any]) -> str:
    env = Environment(autoescape=select_autoescape(["html", "xml", "j2"]))
    env.filters.update(money=money, number=number, percent=percent, pp=pp)
    template_text = resources.files("sentinela.templates").joinpath("report.html.j2").read_text(encoding="utf-8")
    template = env.from_string(template_text)
    res = evidence["results"]
    chart = {"daily_ggr": Markup(charts.daily_bars(res["executive"]["daily"], "ggr"))}
    if "behavior" in res:
        bh = res["behavior"]
        chart["lifecycle"] = Markup(charts.hbars([(x["label"][:30], float(x["players"]), number(x["players"])) for x in bh["lifecycle"]],
                                                 label_w=240))
        if bh["rhythm"].get("day_of_month"):
            dom = [{"dia": f"dia {d['day']}", "deposits": d["deposits"]} for d in bh["rhythm"]["day_of_month"]]
            chart["deposit_dom"] = Markup(charts.daily_bars(dom, "deposits", height=160))
    if "providers" in res:
        items = [(p["provider_name"], float(p["turnover_share"] or 0), percent(p["turnover_share"]))
                 for p in res["providers"]["providers"][:12]]
        chart["providers"] = Markup(charts.hbars(items))
    if "players" in res:
        labels = {"alto": "alto", "medio": "médio", "baixo": "baixo", "nenhum": "nenhum"}
        items = [(labels.get(t["risk_tier"], t["risk_tier"]), float(t["players"]), number(t["players"])) for t in res["players"]["tiers"]]
        chart["tiers"] = Markup(charts.hbars(items, label_w=120))
    if "payments" in res:
        chart["payments_net"] = Markup(charts.daily_bars(res["payments"]["daily"], "net"))
    return template.render(e=evidence, r=res, m=evidence["meta"], chart=chart, cfg=evidence["sections_cfg"])


def export_pdf(html_path: Path, pdf_path: Path) -> str:
    """Try WeasyPrint, then a local Chromium/Chrome. Returns the engine used or raises."""
    errors: list[str] = []
    try:
        from weasyprint import HTML  # type: ignore  # raises OSError if Pango libs are missing
    except Exception as exc:  # noqa: BLE001
        HTML = None
        errors.append(f"weasyprint indisponível ({type(exc).__name__}: {exc})")
    if HTML is not None:
        try:
            doc = HTML(filename=str(html_path)).render()
            md = doc.metadata  # strip document metadata (title, authors, dates, generator)
            md.title, md.authors, md.description, md.keywords = None, [], None, []
            md.created = md.modified = None
            md.generator = "Sentinela"
            doc.write_pdf(str(pdf_path))
            return "weasyprint"
        except Exception as exc:  # noqa: BLE001
            errors.append(f"weasyprint falhou ({exc})")
    for binary in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge"):
        exe = shutil.which(binary)
        if not exe:
            continue
        cmd = [exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
               f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{binary} falhou ({exc})")
            continue
        if proc.returncode == 0 and pdf_path.exists():
            return binary
        errors.append(f"{binary} retornou {proc.returncode}")
    raise RuntimeError(
        "; ".join(errors) + ". Para PDF no Ubuntu: sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 "
        "libharfbuzz0b (WeasyPrint) — ou instale o Chromium. O HTML foi gerado normalmente."
    )


def _render_all(evidence: dict[str, Any], out_dir: Path, slug: str, formats: set[str]) -> dict[str, Any]:
    written: dict[str, Any] = {}
    ev_path = out_dir / f"{slug}.evidence.json"  # evidence is always written: it is the audit trail
    ev_path.write_text(to_json(evidence), encoding="utf-8")
    written["evidence"] = ev_path
    if "csv" in formats:
        tdir = out_dir / "tables"
        tdir.mkdir(exist_ok=True)
        for name, rows in table_exports(evidence).items():
            (tdir / name).parent.mkdir(parents=True, exist_ok=True)
            write_csv(tdir / f"{name}.csv", rows)
        written["tables"] = tdir
    html_path = None
    if formats & {"html", "pdf"}:
        html_path = out_dir / f"{slug}.html"
        html_path.write_text(render_html(evidence), encoding="utf-8")
        written["html"] = html_path
    if "pdf" in formats and html_path is not None:
        pdf_path = out_dir / f"{slug}.pdf"
        try:
            written["pdf_engine"] = export_pdf(html_path, pdf_path)
            written["pdf"] = pdf_path
        except Exception as exc:  # noqa: BLE001
            written["pdf_error"] = str(exc)
    return written


def write_outputs(study: Study, evidence: dict[str, Any], formats: set[str] | None = None,
                  session: Any = None) -> dict[str, Any]:
    formats = formats or study.formats
    slug = slugify(study.title)
    if study.plaintext_outputs:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = study.output_dir / f"{slug}-{stamp}"
        out_dir.mkdir(parents=True, exist_ok=True)
        written = _render_all(evidence, out_dir, slug, formats)
        return {"mode": "plaintext", "output_dir": str(out_dir),
                **{k: str(v) for k, v in written.items()}}

    if session is None:
        raise ValueError("saída cifrada exige uma sessão aberta (Session).")
    from sentinela.security import Workspace

    with Workspace("sentinela-out") as ws:  # plaintext only in RAM, sealed into the vault, then wiped
        written = _render_all(evidence, ws.path, "relatorio", formats)
        files = {str(p.relative_to(ws.path)): p for p in ws.path.rglob("*") if p.is_file()}
        meta = evidence["meta"]
        run = session.vault.add_run(files, {
            "title": meta["title"], "run_id": meta["run_id"],
            "period": {"start": str(meta["period"]["start"]), "end": str(meta["period"]["end"])},
            "sections": meta["sections"],
        })
    out = {"mode": "vault", "run": run["id"], "bundle": str(session.vault.runs_dir / run["file"]),
           "files": run["files"]}
    if "pdf_error" in written:
        out["pdf_error"] = written["pdf_error"]
    return out
