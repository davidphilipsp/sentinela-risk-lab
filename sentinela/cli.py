"""Command-line interface: `sentinela <command>`."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

from sentinela import __version__
from sentinela.behavior import RuleError
from sentinela.contracts import ContractError, map_columns, pseudonymize
from sentinela.security import VaultError, harden_process
from sentinela.study import STUDY_TEMPLATE, StudyError, load_config, load_study

GREEN, RED, YELLOW, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = BOLD = RESET = ""


def _status_color(status: str) -> str:
    return {"OK": GREEN, "PASS": GREEN, "FALHA": RED, "ALERTA": YELLOW}.get(status.split(" ")[0], DIM)


def print_dataset_report(rep) -> None:
    c = _status_color(rep.status)
    print(f"\n{BOLD}[{rep.name}]{RESET} {Path(rep.path).name}  {c}{rep.status}{RESET}")
    print(f"  linhas: {rep.rows_raw} lidas · {rep.rows_loaded} carregadas · {rep.rows_dropped} removidas")
    print(f"  delimitador: {rep.delimiter!r} · decimal: {rep.decimal_separator!r} · sha256: {rep.sha256[:16]}…")
    print("  mapeamento: " + ", ".join(f"{k}←'{v}'" for k, v in rep.column_mapping.items()))
    if rep.defaulted_columns:
        print(f"  {DIM}colunas ausentes (default aplicado): {', '.join(rep.defaulted_columns)}{RESET}")
    if rep.pii_discarded:
        print(f"  {GREEN}PII descartada na carga (nunca analisada): {', '.join(rep.pii_discarded)}{RESET}")
    if rep.ignored_columns:
        print(f"  {DIM}colunas ignoradas: {', '.join(rep.ignored_columns)}{RESET}")
    for i in rep.issues:
        color = RED if i.severity == "error" else YELLOW
        ex = f"  ex.: {'; '.join(i.examples)}" if i.examples else ""
        print(f"  {color}{i.severity:7}{RESET} {i.check_id}: {i.count} linha(s) — {i.description}{DIM}{ex}{RESET}")


def cmd_validate(args) -> int:
    from sentinela.behavior import validate_config
    from sentinela.contracts import load_dataset
    from sentinela.pipeline import Session, connect
    from sentinela.study import DATASETS

    study = load_study(args.study)
    contracts, _ = load_config("contracts.yaml", study.contracts_path)
    ok = True
    with Session(study) as sess:
        con = connect(sess.ws)
        for name in DATASETS:
            if name not in sess.inputs:
                continue
            cfg = sess.inputs[name]
            try:
                rep = load_dataset(con, name, contracts["datasets"][name], cfg, sess.keys.pseudo_secret, "drop")
                rep.path = cfg["display"]
                print_dataset_report(rep)
                if rep.rows_with_errors and study.on_contract_error == "fail":
                    ok = False
            except ContractError as exc:
                ok = False
                if exc.report:
                    exc.report.path = cfg["display"]
                    print_dataset_report(exc.report)
                print(f"  {RED}ERRO:{RESET} {exc}")
        con.close()
    behavior_cfg, _ = load_config("behavior.yaml", study.behavior_path)
    errors = validate_config(behavior_cfg)
    src = study.behavior_path.name if study.behavior_path else "behavior.yaml (padrão)"
    if errors:
        ok = False
        print(f"\n{BOLD}[behavior]{RESET} {src}  {RED}FALHA{RESET}")
        for err in errors:
            print(f"  {RED}error{RESET}   {err}")
    else:
        n_seg = len(behavior_cfg.get("segments") or [])
        print(f"\n{BOLD}[behavior]{RESET} {src}  {GREEN}OK{RESET} ({len(behavior_cfg.get('lifecycle') or [])} estágios, {n_seg} segmentos)")
    print()
    if ok:
        print(f"{GREEN}Contratos e regras OK — pronto para `sentinela run {args.study}`{RESET}")
        return 0
    print(f"{RED}Há erros acima. Corrija antes de rodar (contratos com on_contract_error: fail abortam o run).{RESET}")
    return 2

def cmd_run(args) -> int:
    from sentinela.pipeline import Session, analyze
    from sentinela.report import write_outputs

    study = load_study(args.study)
    formats = set(args.formats.split(",")) if args.formats else None
    print(f"{BOLD}Sentinela Risk Lab v{__version__}{RESET} — {study.title}")
    print(f"{DIM}período {study.start} a {study.end} · seções: {', '.join(study.sections)}{RESET}")
    with Session(study) as sess:
        try:
            evidence = analyze(study, sess)
        except ContractError as exc:
            if exc.report:
                print_dataset_report(exc.report)
            print(f"\n{RED}ABORTADO:{RESET} {exc}")
            return 2
        for rep in evidence["datasets"].values():
            c = _status_color(rep["status"])
            print(f"  contrato {rep['name']:9} {c}{rep['status']}{RESET} ({rep['rows_loaded']}/{rep['rows_raw']} linhas) {DIM}{rep['path']}{RESET}")
        failed = [c for c in evidence["checks"] if c["status"] == "FALHA"]
        print(f"  reconciliação: {len(evidence['checks']) - len(failed)} ok / {RED if failed else GREEN}{len(failed)} falha(s){RESET}")
        written = write_outputs(study, evidence, formats, sess)
        ram = sess.ws.is_ram
    print(f"\n{BOLD}Leituras:{RESET}")
    for i in evidence["insights"][:12]:
        color = {"alerta": RED, "atencao": YELLOW}.get(i["severity"], DIM)
        print(f"  {color}{i['severity']:8}{RESET} {i['text']}")
    if written["mode"] == "vault":
        print(f"\n{BOLD}Relatório cifrado no cofre:{RESET} run {GREEN}{written['run']}{RESET} ({len(written['files'])} arquivos)")
        print(f"  ver:      sentinela view {written['run']} --open")
        print(f"  exportar: sentinela export {written['run']} --to <pasta>   {DIM}(cópia em texto puro: só quando necessário){RESET}")
        print(f"  {DIM}dados decifrados apenas em {'RAM (tmpfs)' if ram else 'temporário local (fora do Linux)'} e apagados ao final{RESET}")
    else:
        print(f"\n{YELLOW}MODO TEXTO PURO (teste):{RESET} {written['output_dir']}")
        for key in ("html", "pdf", "evidence", "tables"):
            if key in written:
                print(f"  {key:9} {written[key]}")
    if "pdf_error" in written:
        print(f"  {YELLOW}pdf não gerado:{RESET} {written['pdf_error']}")
    print(f"  {DIM}run_id {evidence['meta']['run_id']}{RESET}")
    return 1 if failed and args.strict else 0

def cmd_demo(args) -> int:
    import secrets as _secrets

    from sentinela.ingest import ingest_file
    from sentinela.security import Vault, Workspace, unlock
    from sentinela.synthetic import demo_study_text, generate

    root = Path(args.root).resolve()
    keys = unlock(root, create_if_missing=True)
    vault = Vault(root, keys)
    contracts, _ = load_config("contracts.yaml")
    suffix = _secrets.token_hex(3)
    labels = {}
    with Workspace("sentinela-demo") as ws:  # synthetic CSVs exist only in RAM, then go through ingestion
        planted = generate(ws.path, seed=args.seed, players=args.players, history_days=args.history_days,
                           non_depositors=max(0, args.players // 10) if args.history_days else 0)
        for ds in ("activity", "games", "payments", "clients"):
            entry = ingest_file(vault, ws.path / f"{ds}.csv", ds, contracts, label=f"demo-{ds}-{suffix}",
                                delimiter=";" if ds == "payments" else None)
            labels[ds] = entry["label"]
    study_path = root / "studies" / "demo-study.yaml"
    study_path.parent.mkdir(parents=True, exist_ok=True)
    study_path.write_text(demo_study_text(labels=labels), encoding="utf-8")
    print(f"Dados sintéticos gerados em RAM e ingeridos no cofre: {', '.join(labels.values())}")
    print(f"  anomalias plantadas: {len(planted.bonus_abusers)} bonus abusers, {len(planted.big_winners)} grandes ganhadores, "
          f"{len(planted.cashout_no_play)} saque-sem-jogo, {len(planted.whales)} whales, jogo quebrado '{planted.broken_game}', "
          f"btag problemática '{planted.abuse_btag}'")
    print(f"Estudo: {study_path}\n")
    if args.no_run:
        return 0
    return cmd_run(argparse.Namespace(study=str(study_path), formats=args.formats, strict=False))

def cmd_new_study(args) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{RED}{path} já existe (use --force para sobrescrever).{RESET}")
        return 1
    end = date.today().replace(day=1) - timedelta(days=1)
    start = end.replace(day=1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(STUDY_TEMPLATE.format(title=args.title, start=start, end=end), encoding="utf-8")
    print(f"Estudo criado: {path}\nEdite título, período e caminhos; depois: sentinela validate {path}")
    return 0


def cmd_inspect(args) -> int:
    import duckdb

    contracts, _ = load_config("contracts.yaml")
    spec = contracts["datasets"][args.dataset]
    con = duckdb.connect()
    opts = "header=true, all_varchar=true, sample_size=-1"
    if args.delimiter:
        opts += f", delim='{args.delimiter}'"
    cur = con.execute(f"SELECT * FROM read_csv(?, {opts}) LIMIT 3", [args.csv])
    headers = [d[0] for d in cur.description]
    sample = cur.fetchall()
    mapping, ignored = map_columns(headers, spec)
    print(f"{BOLD}{args.csv}{RESET} como dataset '{args.dataset}'\n")
    for canonical, col in spec["columns"].items():
        src = mapping.get(canonical)
        req = "obrigatória" if col.get("required") else "opcional"
        if src:
            idx = headers.index(src)
            ex = ", ".join(repr(r[idx]) for r in sample) if not col.get("pii") else "(oculto: PII)"
            print(f"  {GREEN}✓{RESET} {canonical:15} ← '{src}'  {DIM}{col['type']}, {req}; ex.: {ex}{RESET}")
        else:
            color = RED if col.get("required") else DIM
            print(f"  {color}✗ {canonical:15} não encontrada ({col['type']}, {req}){RESET}")
    if ignored:
        print(f"\n  {DIM}ignoradas: {', '.join(ignored)}{RESET}")
    missing = [c for c, s in spec["columns"].items() if s.get("required") and c not in mapping]
    if missing:
        print(f"\n{YELLOW}Adicione ao estudo, em inputs.{args.dataset}.column_map:{RESET}")
        for c in missing:
            print(f'    "<seu cabeçalho>": {c}')
        return 2
    return 0


def reverse_map(study, targets: set[str], session=None) -> dict[str, str]:
    """Map pseudonyms back to raw IDs LOCALLY by re-hashing raw IDs from the (decrypted) inputs."""
    import duckdb

    from sentinela.pipeline import Session

    if session is None:
        with Session(study) as own:
            return reverse_map(study, targets, own)
    contracts, _ = load_config("contracts.yaml", study.contracts_path)
    secret = session.keys.pseudo_secret
    found: dict[str, str] = {}
    con = duckdb.connect(config={"temp_directory": str(session.ws.path)})
    for name, cfg in session.inputs.items():
        spec = contracts["datasets"][name]
        opts = "header=true, all_varchar=true, sample_size=-1"
        if cfg.get("delimiter") and cfg["delimiter"] != "auto":
            opts += f", delim='{cfg['delimiter']}'"
        cur = con.execute(f"SELECT * FROM read_csv(?, {opts}) LIMIT 0", [cfg["path"]])
        headers = [d[0] for d in cur.description]
        mapping, _ = map_columns(headers, spec, cfg.get("column_map"))
        src = mapping.get("player_id")
        if not src:
            continue
        col = '"' + src.replace('"', '""') + '"'
        for (raw,) in con.execute(f"SELECT DISTINCT trim({col}) FROM read_csv(?, {opts}) WHERE {col} IS NOT NULL",
                                  [cfg["path"]]).fetchall():
            p = pseudonymize(raw, secret)
            if p in targets:
                found[p] = raw
    con.close()
    return found

def cmd_lookup(args) -> int:
    study = load_study(args.study)  # decrypts inputs into RAM for the duration of the lookup
    targets = set(args.pseudonyms)
    found = reverse_map(study, targets)
    for p in args.pseudonyms:
        print(f"{p} -> {found.get(p, '(não encontrado nos CSVs do estudo)')}")
    return 0 if len(found) == len(targets) else 1


def cmd_features(args) -> int:
    from sentinela.behavior import DERIVED, FEATURES

    print(f"{BOLD}Features por player{RESET} (use em behavior.yaml: lifecycle / segments / suppression)\n")
    for name, desc in {**FEATURES, **DERIVED}.items():
        print(f"  {name:26} {DIM}{desc}{RESET}")
    print(f"\n{DIM}Operadores: AND OR NOT IN IS NULL BETWEEN LIKE = <> != < <= > >= + - * / · "
          f"funções: coalesce abs least greatest round lower upper{RESET}")
    return 0


def cmd_export_segment(args) -> int:
    import csv
    import os
    from datetime import datetime

    from sentinela.pipeline import Session, analyze
    from sentinela.security import view_dir

    study = load_study(args.study)
    if "behavior" not in study.sections:
        study.sections.insert(1, "behavior")
    with Session(study) as sess:
        evidence = analyze(study, sess)
        members = (evidence.get("_bulk") or {}).get("members") or {}
        if args.segment not in members:
            print(f"{RED}Segmento '{args.segment}' não existe.{RESET} Disponíveis: {', '.join(members) or '(nenhum)'}")
            return 2
        rows_ = members[args.segment]
        if args.group != "all":
            rows_ = [r for r in rows_ if r["grupo"] == args.group]
        real = reverse_map(study, {r["player_id"] for r in rows_}, sess) if args.reveal else {}
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.out:
        path = Path(args.out)
    elif study.plaintext_outputs:
        out_dir = study.output_dir / ("private" if args.reveal else "segments")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{args.segment}-{args.group}-{stamp}.csv"
    else:
        out_dir = view_dir() / "segments"  # RAM: disappears with `sentinela clean` or reboot
        out_dir.mkdir(exist_ok=True)
        path = out_dir / f"{args.segment}-{args.group}-{stamp}.csv"
    fields = (["player_id_real"] if args.reveal else []) + ["player_id", "grupo", "lifecycle", "value_tier", "risk_tier",
                                                           "days_since_last_activity", "deposits", "lifetime_deposits", "btag"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows_:
            w.writerow({**r, "player_id_real": real.get(r["player_id"], "")} if args.reveal else r)
    os.chmod(path, 0o600)
    if args.reveal:
        missing = sum(1 for r in rows_ if r["player_id"] not in real)
        print(f"{YELLOW}ATENÇÃO: arquivo com IDs REAIS (modo 600). Envie ao CRM pelo canal aprovado e apague: "
              f"sentinela clean{RESET}")
        if missing:
            print(f"{YELLOW}{missing} pseudônimo(s) não encontrados nos dados do estudo.{RESET}")
    groups: dict[str, int] = {}
    for r in rows_:
        groups[r["grupo"]] = groups.get(r["grupo"], 0) + 1
    print(f"Segmento {args.segment}: {len(rows_)} players {groups} → {path}")
    print(f"{DIM}run_id {evidence['meta']['run_id']}{RESET}")
    return 0

def _home(args) -> Path:
    return Path(getattr(args, "home", ".") or ".").resolve()


def cmd_init(args) -> int:
    from sentinela.security import get_passphrase, init_keyring, keyring_path

    home = _home(args)
    if keyring_path(home).exists():
        print(f"{YELLOW}Keyring já existe em {keyring_path(home)}.{RESET}")
        return 1
    pw = get_passphrase(confirm=True, purpose="criar o keyring")
    init_keyring(home, pw)
    print(f"{GREEN}Keyring criado{RESET} em {keyring_path(home)} (modo 600).")
    print(f"{YELLOW}Guarde a frase-senha: sem ela, o cofre NÃO pode ser aberto (não há recuperação).{RESET}")
    return 0


def cmd_passwd(args) -> int:
    import getpass

    from sentinela.security import change_passphrase, check_passphrase

    home = _home(args)
    old = getpass.getpass("Frase-senha atual: ")
    new = getpass.getpass("Nova frase-senha: ")
    check_passphrase(new)
    if getpass.getpass("Repita a nova: ") != new:
        print(f"{RED}As frases-senha não conferem.{RESET}")
        return 2
    change_passphrase(home, old, new)
    print(f"{GREEN}Frase-senha alterada.{RESET} Os dados do cofre não precisaram ser recifrados.")
    return 0


def cmd_ingest(args) -> int:
    from sentinela.ingest import ingest_file
    from sentinela.security import Vault, unlock

    home = _home(args)
    src = Path(args.file).expanduser()
    if not src.is_file():
        print(f"{RED}Arquivo não encontrado: {src}{RESET}")
        return 2
    keep = args.keep_source
    if not keep and not args.yes:
        if not sys.stdin.isatty():
            print(f"{RED}O original será apagado com segurança; confirme com --yes (ou use --keep-source).{RESET}")
            return 2
        ans = input(f"Após cifrar e verificar, o arquivo original será SOBRESCRITO e APAGADO:\n  {src}\nContinuar? [s/N] ")
        if ans.strip().lower() not in ("s", "sim", "y", "yes"):
            print("Cancelado. Nada foi alterado.")
            return 1
    column_map = {}
    for item in args.map or []:
        if ":" not in item:
            print(f"{RED}--map espera 'Cabeçalho:coluna' (recebido {item!r}).{RESET}")
            return 2
        k, v = item.rsplit(":", 1)
        column_map[k] = v
    keys = unlock(home)
    vault = Vault(home, keys)
    contracts, _ = load_config("contracts.yaml")
    e = ingest_file(vault, src, args.dataset, contracts, label=args.label, delimiter=args.delimiter,
                    encoding=args.encoding, column_map=column_map or None, only_contract=args.only_contract,
                    keep_source=keep)
    print(f"{GREEN}Ingerido no cofre{RESET}: {BOLD}{e['label']}{RESET} ({e['dataset']}, {e['rows']} linhas, {len(e['columns'])} colunas)")
    removed = e["pii_removed_by_header"] + e["pii_removed_by_content"]
    if removed:
        print(f"  {GREEN}dados pessoais removidos antes de cifrar:{RESET} {', '.join(removed)}")
        if e["pii_removed_by_content"]:
            print(f"  {DIM}(detectados pelo conteúdo: {', '.join(e['pii_removed_by_content'])}){RESET}")
    if e["required_missing"]:
        print(f"  {YELLOW}colunas obrigatórias não reconhecidas: {', '.join(e['required_missing'])} — use column_map no estudo{RESET}")
    t = e["_traces_cleaned"]
    print(f"  rastros da área de trabalho removidos: {t['recent_files']} recente(s), {t['thumbnails']} miniatura(s)")
    print(f"  original: {'APAGADO com sobrescrita' if e['_source_deleted'] else 'mantido (--keep-source)'}")
    print(f"  {DIM}no estudo:  {e['dataset']}: {{vault: {e['label']}}}{RESET}")
    if not keep:
        print(f"  {DIM}dica: o nome do arquivo ficou no histórico do shell — sentinela clean --traces --apply{RESET}")
    return 0


def cmd_vault(args) -> int:
    from sentinela.security import Vault, unlock

    vault = Vault(_home(args), unlock(_home(args)))
    if args.action == "rm":
        if not args.ref:
            print(f"{RED}informe o rótulo: sentinela vault rm <rótulo>{RESET}")
            return 2
        e = vault.remove_entry(args.ref)
        print(f"Removido com sobrescrita: {e['label']}")
        return 0
    es = vault.entries()
    if not es:
        print("Cofre vazio. Use: sentinela ingest <arquivo.csv> --dataset activity")
        return 0
    print(f"{BOLD}{'RÓTULO':34} {'DATASET':9} {'LINHAS':>9}  INGERIDO    PII REMOVIDA{RESET}")
    for e in es:
        pii = len(e["pii_removed_by_header"]) + len(e["pii_removed_by_content"])
        print(f"{e['label']:34} {e['dataset']:9} {e['rows']:>9}  {e['ingested']}  {pii} coluna(s)")
    return 0


def cmd_runs(args) -> int:
    from sentinela.security import Vault, unlock

    vault = Vault(_home(args), unlock(_home(args)))
    if args.action == "rm":
        r = vault.remove_run(args.ref)
        print(f"Relatório removido com sobrescrita: {r['id']} — {r['title']}")
        return 0
    rs = vault.runs()
    if not rs:
        print("Nenhum relatório no cofre.")
        return 0
    print(f"{BOLD}{'ID':9} {'CRIADO':11} {'PERÍODO':24} TÍTULO{RESET}")
    for r in rs:
        print(f"{r['id']:9} {r['created']:11} {r['period']['start']} a {r['period']['end']}  {r['title']}")
    return 0


def cmd_view(args) -> int:
    import subprocess

    from sentinela.security import Vault, unlock, view_dir, workspace_base

    vault = Vault(_home(args), unlock(_home(args)))
    run = vault.resolve_run(args.run)
    dest = view_dir() / f"run-{run['id']}"
    _, files = vault.extract_run(run["id"], dest)
    html = next((f for f in files if f.suffix == ".html"), None)
    _, is_ram = workspace_base()
    print(f"Relatório {run['id']} decifrado em {'RAM' if is_ram else 'temporário local'}: {dest}")
    if html:
        print(f"  html: {html}")
    print(f"  {DIM}feche e apague com: sentinela clean{RESET}")
    if args.open and html:
        opener = "xdg-open" if sys.platform.startswith("linux") else "open"
        subprocess.Popen([opener, str(html)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  {YELLOW}o navegador pode guardar cache/histórico desta página: use uma janela anônima.{RESET}")
    return 0


def cmd_export(args) -> int:
    from sentinela.security import Vault, unlock

    vault = Vault(_home(args), unlock(_home(args)))
    dest = Path(args.to).expanduser().resolve()
    only = {"." + x.strip(".") if x not in ("tables",) else "tables/" for x in args.only.split(",")} if args.only else None
    run, files = vault.extract_run(args.run, dest, only)
    print(f"{YELLOW}CÓPIA EM TEXTO PURO{RESET} do relatório {run['id']} em {dest} ({len(files)} arquivos, carimbos de data neutralizados).")
    print(f"  {DIM}PDF sem metadados; o conteúdo traz agregados e pseudônimos. Apague após o uso: shred -u <arquivo>{RESET}")
    return 0


def cmd_doctor(args) -> int:
    from sentinela.traces import doctor

    res = doctor(_home(args))
    worst = 0
    for r in res:
        color = _status_color(r["status"])
        print(f"  {color}{r['status']:6}{RESET} {r['check']}: {r['detail']}")
        if r["fix"]:
            print(f"         {DIM}→ {r['fix']}{RESET}")
        worst = max(worst, {"OK": 0, "ALERTA": 1, "FALHA": 2}.get(r["status"], 0))
    print()
    print({0: f"{GREEN}Ambiente pronto.{RESET}", 1: f"{YELLOW}Ambiente com alertas.{RESET}",
           2: f"{RED}Ambiente com falhas de segurança.{RESET}"}[worst])
    return 0 if worst < 2 else 2


def cmd_clean(args) -> int:
    from sentinela.security import iter_user_workspaces, secure_delete, wipe_tree
    from sentinela.traces import clean_desktop, clean_history, plaintext_files, scan_desktop, scan_history

    home = _home(args)
    n = 0
    for ws in iter_user_workspaces():
        wipe_tree(ws)
        n += 1
    print(f"  áreas temporárias em RAM apagadas: {n}")
    plain = plaintext_files([home])
    if plain:
        if args.apply:
            for p in plain:
                secure_delete(p)
            print(f"  {GREEN}arquivos em texto puro apagados com sobrescrita: {len(plain)}{RESET}")
        else:
            print(f"  {YELLOW}arquivos em texto puro no projeto: {len(plain)}{RESET} (use --apply para apagar)")
            for p in plain[:10]:
                print(f"    {p.relative_to(home)}")
    if args.traces:
        hist, desk = scan_history(home), scan_desktop(home)
        if args.apply:
            ch, cd = clean_history(home), clean_desktop(home)
            print(f"  histórico do shell: {sum(ch.values())} linha(s) removida(s)")
            print(f"  arquivos recentes: {cd['recent_files']} · miniaturas: {cd['thumbnails']}")
            print(f"  {DIM}o shell aberto regrava o histórico ao sair: rode 'history -c' nesta sessão "
                  f"(ou comece comandos com espaço){RESET}")
        else:
            print(f"  histórico do shell: {sum(hist.values())} linha(s) · arquivos recentes: {len(desk)}  (use --apply)")
    return 0


def cmd_contracts(args) -> int:
    contracts, digest = load_config("contracts.yaml")
    if args.json:
        print(json.dumps(contracts, indent=2, ensure_ascii=False, default=str))
        return 0
    print(f"{BOLD}Contratos v{contracts['version']}{RESET} {DIM}sha256 {digest[:16]}…{RESET}")
    for name, spec in contracts["datasets"].items():
        req = "OBRIGATÓRIO" if spec.get("required_dataset") else "opcional"
        print(f"\n{BOLD}{name}{RESET} ({req}) — {spec['description'].strip()}")
        print(f"  chave única: {', '.join(spec.get('key') or []) or '-'}")
        for col, c in spec["columns"].items():
            flag = "*" if c.get("required") else " "
            extra = []
            if "min" in c:
                extra.append(f"min {c['min']}")
            if c.get("allowed_values"):
                extra.append("valores: " + "/".join(c["allowed_values"]))
            if c.get("pii"):
                extra.append("PII→pseudonimizado")
            aliases = ", ".join(c.get("aliases", [])[:6])
            print(f"  {flag} {col:15} {c['type']:8} {DIM}{'; '.join(extra)}{' · aliases: ' + aliases if aliases else ''}{RESET}")
    print(f"\n{DIM}* = obrigatória{RESET}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinela", description="Sentinela Risk Lab — análise de risco determinística a partir de CSVs.")
    p.add_argument("--version", action="version", version=f"sentinela {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("demo", help="gera dados sintéticos com anomalias plantadas e roda o estudo demo")
    s.add_argument("--root", default=".", help="raiz do projeto (default: .)")
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--players", type=int, default=2500)
    s.add_argument("--formats", default=None, help="ex.: html,json,csv,pdf")
    s.add_argument("--history-days", type=int, default=120,
                   help="dias de histórico antes do período (ciclo de vida/coortes); 0 = só o período")
    s.add_argument("--no-run", action="store_true")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("new-study", help="cria um arquivo de estudo a partir do modelo")
    s.add_argument("path")
    s.add_argument("--title", default="Novo Estudo de Risco")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_new_study)

    s = sub.add_parser("inspect", help="mostra como os cabeçalhos de um CSV mapeiam para o contrato")
    s.add_argument("csv")
    s.add_argument("--dataset", default="activity", choices=["activity", "games", "payments", "clients"])
    s.add_argument("--delimiter", default=None)
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("validate", help="valida os CSVs do estudo contra os contratos (sem calcular)")
    s.add_argument("study")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("run", help="executa o estudo completo e gera HTML/PDF/JSON/CSV")
    s.add_argument("study")
    s.add_argument("--formats", default=None, help="sobrescreve output.formats (ex.: html,json)")
    s.add_argument("--strict", action="store_true", help="exit code 1 se alguma reconciliação falhar")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("lookup", help="reverte pseudônimos para IDs reais (somente local, usa a chave)")
    s.add_argument("study")
    s.add_argument("pseudonyms", nargs="+")
    s.set_defaults(func=cmd_lookup)

    s = sub.add_parser("init", help="cria o keyring cifrado (frase-senha) — uma vez por projeto")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("passwd", help="troca a frase-senha do keyring")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_passwd)

    s = sub.add_parser("ingest", help="ÚNICA porta de entrada: limpa, cifra no cofre e apaga o original")
    s.add_argument("file")
    s.add_argument("--dataset", required=True, choices=["activity", "games", "payments", "clients"])
    s.add_argument("--label", default=None)
    s.add_argument("--delimiter", default=None)
    s.add_argument("--encoding", default=None)
    s.add_argument("--map", action="append", help="'Cabeçalho:coluna' (repita); protege colunas do contrato")
    s.add_argument("--only-contract", action="store_true", help="guarda só as colunas reconhecidas pelo contrato")
    s.add_argument("--keep-source", action="store_true", help="não apaga o arquivo original")
    s.add_argument("--yes", action="store_true", help="confirma a exclusão segura do original")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("vault", help="lista as entradas do cofre (ou: vault rm <rótulo>)")
    s.add_argument("action", nargs="?", default="list", choices=["list", "rm"])
    s.add_argument("ref", nargs="?")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_vault)

    s = sub.add_parser("runs", help="lista os relatórios cifrados (ou: runs rm <id>)")
    s.add_argument("action", nargs="?", default="list", choices=["list", "rm"])
    s.add_argument("ref", nargs="?")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_runs)

    s = sub.add_parser("view", help="decifra um relatório em RAM para leitura")
    s.add_argument("run", nargs="?", default="latest")
    s.add_argument("--open", action="store_true")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_view)

    s = sub.add_parser("export", help="cópia EM TEXTO PURO de um relatório (para compartilhar)")
    s.add_argument("run")
    s.add_argument("--to", required=True)
    s.add_argument("--only", default=None, help="ex.: html,pdf,json,tables")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("doctor", help="verifica a segurança do ambiente Linux")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("clean", help="apaga áreas em RAM e texto puro; --traces limpa histórico e recentes")
    s.add_argument("--traces", action="store_true")
    s.add_argument("--apply", action="store_true")
    s.add_argument("--home", default=".")
    s.set_defaults(func=cmd_clean)

    s = sub.add_parser("features", help="lista as features por player usadas nas regras de comportamento")
    s.set_defaults(func=cmd_features)

    s = sub.add_parser("export-segment", help="exporta a lista de um segmento (CRM); --reveal inclui IDs reais (local)")
    s.add_argument("study")
    s.add_argument("segment")
    s.add_argument("--group", default="all", choices=["all", "tratamento", "controle", "lista", "monitoramento"])
    s.add_argument("--reveal", action="store_true", help="inclui a coluna player_id_real (somente nesta máquina)")
    s.add_argument("--out", default=None)
    s.set_defaults(func=cmd_export_segment)

    s = sub.add_parser("contracts", help="mostra os contratos de CSV")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_contracts)
    return p


def main(argv: list[str] | None = None) -> int:
    harden_process()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (StudyError, ContractError, RuleError, VaultError) as exc:
        print(f"{RED}ERRO:{RESET} {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
