"""Trace hygiene on Linux desktops + environment checks (`sentinela doctor` / `sentinela clean`).

Traces a data file usually leaves behind:
  * GNOME/GTK "recent files"   ~/.local/share/recently-used.xbel
  * thumbnails                 ~/.cache/thumbnails/*/<md5(file-uri)>.png
  * shell history              ~/.bash_history, ~/.zsh_history (commands mention file names)
  * leftover plaintext         CSV/XLSX exports in Downloads or in the project folder
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

DATA_EXTS = {".csv", ".tsv", ".xlsx", ".xls", ".json", ".parquet", ".pdf", ".html"}
SKIP_DIRS = {".venv", "wheelhouse", "vault", ".sentinela", "__pycache__", ".git", "node_modules"}


def _home() -> Path:
    return Path(os.environ.get("HOME", str(Path.home())))


def file_uri(path: Path) -> str:
    return "file://" + quote(str(Path(path).resolve()))


# ------------------------------------------------------------------------------ desktop

def _thumbnail_paths(uri: str) -> list[Path]:
    digest = hashlib.md5(uri.encode()).hexdigest()  # noqa: S324 - freedesktop thumbnail spec mandates MD5
    root = _home() / ".cache" / "thumbnails"
    return [p for p in root.glob(f"**/{digest}.png")] if root.exists() else []


def _xbel_path() -> Path:
    return _home() / ".local" / "share" / "recently-used.xbel"


def _xbel_remove(predicate) -> list[str]:
    """Remove <bookmark> elements whose href matches predicate. Returns removed URIs."""
    path = _xbel_path()
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    removed: list[str] = []

    def repl(m: re.Match) -> str:
        href = m.group(1)
        if predicate(href):
            removed.append(href)
            return ""
        return m.group(0)

    new = re.sub(r'\s*<bookmark\s+href="([^"]+)".*?</bookmark>', repl, text, flags=re.S)
    if removed:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(new, encoding="utf-8")
        os.replace(tmp, path)
    return removed


def clean_desktop_traces_for(path: Path) -> dict[str, int]:
    """Remove recent-files entries and thumbnails that point to one file."""
    uri = file_uri(path)
    removed = _xbel_remove(lambda href: href == uri)
    thumbs = 0
    for t in _thumbnail_paths(uri):
        try:
            t.unlink()
            thumbs += 1
        except OSError:
            pass
    return {"recent_files": len(removed), "thumbnails": thumbs}


def _uri_to_path(href: str) -> Path | None:
    u = urlparse(href)
    return Path(unquote(u.path)) if u.scheme == "file" else None


def scan_desktop(project: Path) -> list[str]:
    path = _xbel_path()
    if not path.exists():
        return []
    hrefs = re.findall(r'<bookmark\s+href="([^"]+)"', path.read_text(encoding="utf-8", errors="replace"))
    return [h for h in hrefs if _desktop_match(h, project)]


def _desktop_match(href: str, project: Path) -> bool:
    p = _uri_to_path(href)
    if p is None:
        return False
    in_project = str(p).startswith(str(project.resolve()))
    vanished_data = p.suffix.lower() in DATA_EXTS and not p.exists()
    return in_project or vanished_data


def clean_desktop(project: Path) -> dict[str, int]:
    removed = _xbel_remove(lambda h: _desktop_match(h, project))
    thumbs = 0
    for href in removed:
        for t in _thumbnail_paths(href):
            try:
                t.unlink()
                thumbs += 1
            except OSError:
                pass
    return {"recent_files": len(removed), "thumbnails": thumbs}


# ------------------------------------------------------------------------------ shell history

def history_files() -> list[Path]:
    h = _home()
    cands = [h / ".bash_history", h / ".zsh_history", h / ".local" / "share" / "fish" / "fish_history",
             h / ".python_history"]
    env = os.environ.get("HISTFILE")
    if env:
        cands.insert(0, Path(env))
    seen, out = set(), []
    for c in cands:
        if c.exists() and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _history_match(line: str, project: Path) -> bool:
    return bool(re.search(r"\bsentinela\b", line)) or str(project.resolve()) in line


def scan_history(project: Path) -> dict[str, int]:
    out = {}
    for f in history_files():
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        n = sum(1 for ln in lines if _history_match(ln, project))
        if n:
            out[str(f)] = n
    return out


def clean_history(project: Path) -> dict[str, int]:
    out = {}
    for f in history_files():
        raw = f.read_bytes()
        text = raw.decode("utf-8", errors="surrogateescape")
        lines = text.splitlines(keepends=True)
        keep = [ln for ln in lines if not _history_match(ln, project)]
        if len(keep) != len(lines):
            mode = f.stat().st_mode & 0o777
            tmp = f.with_name(f.name + ".sentinela-tmp")
            tmp.write_bytes("".join(keep).encode("utf-8", errors="surrogateescape"))
            os.chmod(tmp, mode)
            os.replace(tmp, f)
            out[str(f)] = len(lines) - len(keep)
    return out


# ------------------------------------------------------------------------------ plaintext files

def plaintext_files(roots: list[Path]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() in {".csv", ".tsv", ".xlsx", ".xls", ".parquet"}:
                    found.append(p)
    return sorted(found)


# ------------------------------------------------------------------------------ doctor

def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _is_encrypted_device(source: str) -> bool | None:
    if not source:
        return None
    types = _run(["lsblk", "-s", "-n", "-o", "TYPE", source])
    if not types:
        return None
    return "crypt" in types.split()


def _fs_source(path: str) -> str:
    return _run(["findmnt", "-n", "-o", "SOURCE", "-T", path]).split("[")[0]


def doctor(project: Path) -> list[dict[str, Any]]:
    from sentinela.security import keyring_path, ram_root

    res: list[dict[str, Any]] = []

    def add(check: str, status: str, detail: str, fix: str = "") -> None:
        res.append({"check": check, "status": status, "detail": detail, "fix": fix})

    linux = sys.platform.startswith("linux")
    add("Sistema operacional", "OK" if linux else "ALERTA", sys.platform,
        "" if linux else "o ambiente-alvo é Ubuntu/Linux; verificações de sistema puladas")
    if linux:
        enc = _is_encrypted_device(_fs_source(str(project)))
        add("Disco do projeto cifrado (LUKS)", {True: "OK", False: "FALHA", None: "ALERTA"}[enc],
            "dm-crypt detectado" if enc else ("sem dm-crypt" if enc is False else "não foi possível verificar"),
            "" if enc else "reinstale o Ubuntu com 'criptografar o disco' (LUKS)")
        swaps = []
        try:
            swaps = [ln.split()[0] for ln in Path("/proc/swaps").read_text().splitlines()[1:] if ln.strip()]
        except OSError:
            pass
        if not swaps:
            add("Swap", "OK", "sem swap ativo (a memória nunca vai para o disco)")
        else:
            bad = []
            for sw in swaps:
                src = sw if sw.startswith("/dev/") else _fs_source(sw)
                if not _is_encrypted_device(src):
                    bad.append(sw)
            add("Swap cifrado", "OK" if not bad else "FALHA",
                "todos em dispositivo cifrado" if not bad else f"swap sem cifra: {', '.join(bad)}",
                "" if not bad else "use swap dentro do LUKS ou desative: sudo swapoff -a")
        rr = ram_root()
        add("Área de trabalho em RAM (tmpfs)", "OK" if rr else "FALHA", str(rr) if rr else "tmpfs indisponível",
            "" if rr else "monte /dev/shm como tmpfs (padrão do Ubuntu)")
        up = []
        for iface in Path("/sys/class/net").glob("*"):
            if iface.name == "lo":
                continue
            try:
                if (iface / "operstate").read_text().strip() == "up":
                    up.append(iface.name)
            except OSError:
                pass
        add("Rede desligada", "OK" if not up else "ALERTA", "nenhuma interface ativa" if not up else f"ativas: {', '.join(up)}",
            "" if not up else "desligue Wi-Fi/cabo durante a análise ou bloqueie saída: sudo ufw default deny outgoing")
        apport = _run(["systemctl", "is-enabled", "apport"])
        add("Relatórios de falha (apport)", "OK" if apport in ("", "disabled", "masked") else "ALERTA",
            apport or "não instalado", "" if apport in ("", "disabled", "masked") else "sudo systemctl disable --now apport")

    kr = keyring_path(project)
    if kr.exists():
        mode = kr.stat().st_mode & 0o777
        add("Keyring", "OK" if mode == 0o600 else "FALHA", f"{kr} (modo {oct(mode)})",
            "" if mode == 0o600 else f"chmod 600 {kr}")
    else:
        add("Keyring", "ALERTA", "não inicializado", "sentinela init")
    vdir = project / "vault"
    if vdir.exists():
        mode = vdir.stat().st_mode & 0o777
        add("Permissões do cofre", "OK" if mode == 0o700 else "FALHA", f"modo {oct(mode)}", "" if mode == 0o700 else f"chmod 700 {vdir}")

    plain = plaintext_files([project])
    add("Arquivos em texto puro no projeto", "OK" if not plain else "FALHA",
        "nenhum" if not plain else f"{len(plain)}: " + ", ".join(str(p.relative_to(project)) for p in plain[:5]),
        "" if not plain else "sentinela ingest <arquivo> --dataset ... (ou sentinela clean --apply)")
    downloads = _home() / "Downloads"
    dl = plaintext_files([downloads]) if downloads.exists() else []
    add("Planilhas/CSVs em ~/Downloads", "OK" if not dl else "ALERTA",
        "nenhum" if not dl else f"{len(dl)} arquivo(s)", "" if not dl else "ingira no cofre ou apague com segurança: shred -u <arquivo>")
    hist = scan_history(project)
    add("Histórico do shell", "OK" if not hist else "ALERTA",
        "limpo" if not hist else "; ".join(f"{Path(k).name}: {v} linha(s)" for k, v in hist.items()),
        "" if not hist else "sentinela clean --traces --apply  (e comece comandos com espaço: HISTCONTROL=ignorespace)")
    desk = scan_desktop(project)
    add("Arquivos recentes da área de trabalho", "OK" if not desk else "ALERTA",
        "limpo" if not desk else f"{len(desk)} entrada(s)", "" if not desk else "sentinela clean --traces --apply")
    return res
