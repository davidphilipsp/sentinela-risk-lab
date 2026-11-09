"""Security core: encryption at rest, RAM-only workspaces, secure deletion, process hardening.

Design (Linux first):
  * Keyring  — a random 256-bit data key + the pseudonymization secret, wrapped with a key
               derived from the user's passphrase (scrypt). File: <home>/.sentinela/keyring.json
  * Files    — chunked AES-256-GCM; one sub-key per file (HMAC(data_key, file_id)); every chunk is
               authenticated with the header and a "final" flag -> tampering, reordering and
               truncation are all detected.
  * Vault    — <home>/vault/*.sntl (random names, normalized timestamps) + encrypted manifest.
  * Workspace— plaintext exists only in RAM (tmpfs /dev/shm on Linux) and is wiped on exit.
  * Process  — umask 077, no core dumps, not ptrace-dumpable, temp files redirected to RAM.
"""
from __future__ import annotations

import atexit
import base64
import ctypes
import getpass
import hashlib
import hmac
import io
import json
import os
import resource
import secrets
import shutil
import signal
import stat
import struct
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SNTL"
VERSION = 1
KIND_FILE, KIND_MANIFEST, KIND_BUNDLE = 0, 1, 2
CHUNK = 4 * 1024 * 1024
HEADER = struct.Struct(">4sBB16sI")  # magic, version, kind, file_id, chunk_size  (26 bytes)
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
FIXED_MTIME = 946684800  # 2000-01-01: vault files do not reveal when they were written
PASS_ENV = "SENTINELA_PASSPHRASE"
MIN_PASSPHRASE = 12


class VaultError(Exception):
    pass


# =============================================================================== hardening

_HARDENED = False


def harden_process() -> dict[str, Any]:
    """Reduce the footprint of the running process. Safe to call more than once."""
    global _HARDENED
    info: dict[str, Any] = {}
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        info["core_dumps"] = "disabled"
    except (ValueError, OSError):
        info["core_dumps"] = "unchanged"
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            info["dumpable"] = False
        except OSError:
            info["dumpable"] = "unknown"
    root = ram_root()
    if root:
        os.environ["TMPDIR"] = str(root)
        tempfile.tempdir = str(root)
    info["ram_root"] = str(root) if root else None
    _HARDENED = True
    return info


def _is_tmpfs(path: str, mounts_text: str | None = None) -> bool:
    """True when `path` lives on a RAM file system, according to /proc/mounts (longest mount-point match)."""
    if mounts_text is None:
        try:
            with open("/proc/mounts", encoding="utf-8") as fh:
                mounts_text = fh.read()
        except OSError:
            return False
    path = os.path.normpath(path)
    best, fstype = "", ""
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mp = parts[1].replace("\\040", " ")
        inside = path == mp or path.startswith(mp.rstrip("/") + "/")
        if inside and len(mp) >= len(best):
            best, fstype = mp, parts[2]
    return fstype in ("tmpfs", "ramfs")


def ram_root() -> Path | None:
    """A RAM-backed directory for plaintext (Linux tmpfs). None when unavailable."""
    if not sys.platform.startswith("linux"):
        return None
    for cand in ("/dev/shm", os.environ.get("XDG_RUNTIME_DIR", "")):
        if cand and os.path.isdir(cand) and os.access(cand, os.W_OK) and _is_tmpfs(cand):
            return Path(cand)
    return None


def workspace_base() -> tuple[Path, bool]:
    """(directory, is_ram). Off Linux (development machines) falls back to the system temp dir."""
    root = ram_root()
    if root:
        return root, True
    return Path(tempfile.gettempdir()), False


_LIVE_WORKSPACES: list["Workspace"] = []


class Workspace:
    """Private plaintext scratch area in RAM; wiped on close, on exit and on SIGTERM/SIGINT."""

    def __init__(self, prefix: str = "sentinela-ws") -> None:
        base, self.is_ram = workspace_base()
        self.path = Path(tempfile.mkdtemp(prefix=f"{prefix}-", dir=base))
        os.chmod(self.path, 0o700)
        _LIVE_WORKSPACES.append(self)

    def file(self, name: str) -> Path:
        return self.path / name

    def wipe(self) -> None:
        if self.path.exists():
            wipe_tree(self.path)
        if self in _LIVE_WORKSPACES:
            _LIVE_WORKSPACES.remove(self)

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.wipe()


def _wipe_all_workspaces(*_: Any) -> None:
    for ws in list(_LIVE_WORKSPACES):
        try:
            ws.wipe()
        except OSError:
            pass


def _signal_handler(signum: int, _frame: Any) -> None:
    _wipe_all_workspaces()
    raise SystemExit(128 + signum)


atexit.register(_wipe_all_workspaces)
for _sig in (signal.SIGTERM, signal.SIGHUP):
    try:
        signal.signal(_sig, _signal_handler)
    except (ValueError, OSError):  # not in main thread
        pass


# =============================================================================== secure delete

def secure_delete(path: str | Path, passes: int = 1) -> None:
    """Overwrite with random bytes, fsync, truncate, rename to a random name, unlink.

    NOTE: on SSDs and journaling/copy-on-write file systems an overwrite cannot be guaranteed
    to reach the original blocks; full-disk encryption (LUKS) is what makes leftovers unreadable.
    """
    p = Path(path)
    if not p.exists() and not p.is_symlink():
        return
    if p.is_symlink() or not p.is_file():
        p.unlink()
        return
    size = p.stat().st_size
    with open(p, "r+b", buffering=0) as fh:
        for _ in range(max(1, passes)):
            fh.seek(0)
            remaining = size
            while remaining > 0:
                n = min(remaining, 1024 * 1024)
                fh.write(secrets.token_bytes(n))
                remaining -= n
            fh.flush()
            os.fsync(fh.fileno())
        fh.truncate(0)
        os.fsync(fh.fileno())
    tmp = p.with_name(secrets.token_hex(8))
    os.replace(p, tmp)
    tmp.unlink()


def wipe_tree(path: Path) -> None:
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            try:
                secure_delete(Path(root) / f)
            except OSError:
                pass
        for d in dirs:
            shutil.rmtree(Path(root) / d, ignore_errors=True)
    shutil.rmtree(path, ignore_errors=True)


# =============================================================================== keyring

@dataclass
class Keys:
    data_key: bytes
    pseudo_secret: str


_UNLOCKED: dict[str, Keys] = {}


def keyring_path(home: Path) -> Path:
    return Path(home) / ".sentinela" / "keyring.json"


def _kek(passphrase: str, salt: bytes, params: dict[str, int]) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=params["n"], r=params["r"], p=params["p"],
                          maxmem=128 * 1024 * 1024, dklen=32)


def _write_keyring(home: Path, keys: Keys, passphrase: str) -> None:
    salt = secrets.token_bytes(16)
    kek = _kek(passphrase, salt, SCRYPT)
    nonce = secrets.token_bytes(12)
    payload = json.dumps({"data_key": base64.b64encode(keys.data_key).decode(), "pseudo_secret": keys.pseudo_secret})
    ct = AESGCM(kek).encrypt(nonce, payload.encode(), b"sentinela-keyring-v1")
    doc = {"version": 1, "kdf": "scrypt", "params": SCRYPT, "salt": base64.b64encode(salt).decode(),
           "wrapped": base64.b64encode(nonce + ct).decode()}
    path = keyring_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise VaultError(f"A frase-senha precisa ter pelo menos {MIN_PASSPHRASE} caracteres.")


def init_keyring(home: Path, passphrase: str, pseudo_secret: str | None = None) -> Keys:
    if keyring_path(home).exists():
        raise VaultError(f"Já existe um keyring em {keyring_path(home)}.")
    check_passphrase(passphrase)
    keys = Keys(secrets.token_bytes(32), pseudo_secret or secrets.token_hex(32))
    _write_keyring(home, keys, passphrase)
    _UNLOCKED[str(Path(home).resolve())] = keys
    return keys


def unlock(home: Path, passphrase: str | None = None, *, create_if_missing: bool = False) -> Keys:
    home = Path(home).resolve()
    if str(home) in _UNLOCKED:
        return _UNLOCKED[str(home)]
    path = keyring_path(home)
    if not path.exists():
        if create_if_missing:
            pw = passphrase or get_passphrase(confirm=True, purpose="criar o keyring")
            return init_keyring(home, pw)
        raise VaultError(f"Keyring não encontrado em {path}. Rode: sentinela init")
    doc = json.loads(path.read_text(encoding="utf-8"))
    pw = passphrase if passphrase is not None else get_passphrase()
    raw = base64.b64decode(doc["wrapped"])
    try:
        kek = _kek(pw, base64.b64decode(doc["salt"]), doc["params"])
        payload = json.loads(AESGCM(kek).decrypt(raw[:12], raw[12:], b"sentinela-keyring-v1"))
    except InvalidTag as exc:
        raise VaultError("Frase-senha incorreta.") from exc
    keys = Keys(base64.b64decode(payload["data_key"]), payload["pseudo_secret"])
    _UNLOCKED[str(home)] = keys
    return keys


def change_passphrase(home: Path, old: str, new: str) -> None:
    check_passphrase(new)
    _UNLOCKED.pop(str(Path(home).resolve()), None)
    keys = unlock(home, old)
    _write_keyring(home, keys, new)


def get_passphrase(confirm: bool = False, purpose: str = "desbloquear o cofre") -> str:
    env = os.environ.get(PASS_ENV)
    if env:
        return env
    if not sys.stdin.isatty():
        raise VaultError(f"Frase-senha necessária para {purpose}: rode em um terminal ou defina {PASS_ENV}.")
    pw = getpass.getpass(f"Frase-senha para {purpose}: ")
    if confirm:
        check_passphrase(pw)
        if getpass.getpass("Repita a frase-senha: ") != pw:
            raise VaultError("As frases-senha não conferem.")
    return pw


def forget_keys() -> None:
    _UNLOCKED.clear()


# =============================================================================== file format

def _subkey(keys: Keys, file_id: bytes) -> bytes:
    return hmac.new(keys.data_key, b"sentinela-file|" + file_id, hashlib.sha256).digest()


def _nonce(index: int, final: bool) -> bytes:
    return index.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def encrypt_stream(keys: Keys, src: io.BufferedIOBase, dst: io.BufferedIOBase, kind: int = KIND_FILE) -> None:
    file_id = secrets.token_bytes(16)
    header = HEADER.pack(MAGIC, VERSION, kind, file_id, CHUNK)
    aead = AESGCM(_subkey(keys, file_id))
    dst.write(header)
    index = 0
    current = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        final = not nxt
        ct = aead.encrypt(_nonce(index, final), current, header)
        dst.write(struct.pack(">I", len(ct)))
        dst.write(ct)
        if final:
            break
        current, index = nxt, index + 1


def decrypt_stream(keys: Keys, src: io.BufferedIOBase, dst: io.BufferedIOBase, expect_kind: int | None = None) -> int:
    header = src.read(HEADER.size)
    if len(header) != HEADER.size:
        raise VaultError("arquivo cifrado inválido ou truncado (cabeçalho).")
    magic, version, kind, file_id, _chunk = HEADER.unpack(header)
    if magic != MAGIC or version != VERSION:
        raise VaultError("não é um arquivo do cofre Sentinela (assinatura inválida).")
    if expect_kind is not None and kind != expect_kind:
        raise VaultError("tipo de arquivo cifrado inesperado.")
    aead = AESGCM(_subkey(keys, file_id))
    index, total = 0, 0
    lenbuf = src.read(4)
    if len(lenbuf) != 4:
        raise VaultError("arquivo cifrado truncado.")
    while True:
        (n,) = struct.unpack(">I", lenbuf)
        ct = src.read(n)
        if len(ct) != n:
            raise VaultError("arquivo cifrado truncado.")
        lenbuf = src.read(4)
        final = len(lenbuf) == 0
        if not final and len(lenbuf) != 4:
            raise VaultError("arquivo cifrado truncado.")
        try:
            pt = aead.decrypt(_nonce(index, final), ct, header)
        except InvalidTag as exc:
            raise VaultError("falha de autenticação: arquivo adulterado, truncado ou chave errada.") from exc
        dst.write(pt)
        total += len(pt)
        if final:
            return total
        index += 1


def encrypt_file(keys: Keys, src: Path, dst: Path, kind: int = KIND_FILE) -> None:
    tmp = dst.with_name(dst.name + ".part")
    with open(src, "rb") as fi, open(tmp, "wb") as fo:
        encrypt_stream(keys, fi, fo, kind)
        fo.flush()
        os.fsync(fo.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dst)
    os.utime(dst, (FIXED_MTIME, FIXED_MTIME))


def decrypt_file(keys: Keys, src: Path, dst: Path, expect_kind: int | None = None) -> None:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        decrypt_stream(keys, fi, fo, expect_kind)
    os.chmod(dst, 0o600)


def encrypt_bytes(keys: Keys, data: bytes, dst: Path, kind: int) -> None:
    tmp = dst.with_name(dst.name + ".part")
    with open(tmp, "wb") as fo:
        encrypt_stream(keys, io.BytesIO(data), fo, kind)
        fo.flush()
        os.fsync(fo.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dst)
    os.utime(dst, (FIXED_MTIME, FIXED_MTIME))


def decrypt_bytes(keys: Keys, src: Path, expect_kind: int | None = None) -> bytes:
    out = io.BytesIO()
    with open(src, "rb") as fi:
        decrypt_stream(keys, fi, out, expect_kind)
    return out.getvalue()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================== vault

class Vault:
    """Encrypted store of ingested datasets and report bundles."""

    def __init__(self, home: Path, keys: Keys) -> None:
        self.home = Path(home).resolve()
        self.keys = keys
        self.dir = self.home / "vault"
        self.runs_dir = self.dir / "runs"
        for d in (self.dir, self.runs_dir):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        self.manifest_path = self.dir / "manifest.sntl"

    # ---- manifest
    def manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {"version": 1, "entries": [], "runs": []}
        return json.loads(decrypt_bytes(self.keys, self.manifest_path, KIND_MANIFEST))

    def save_manifest(self, doc: dict[str, Any]) -> None:
        encrypt_bytes(self.keys, json.dumps(doc, ensure_ascii=False, default=str).encode(), self.manifest_path, KIND_MANIFEST)

    # ---- entries
    def new_entry_path(self) -> tuple[str, Path]:
        eid = secrets.token_hex(8)
        return eid, self.dir / f"{eid}.sntl"

    def add_entry(self, entry: dict[str, Any]) -> None:
        doc = self.manifest()
        if any(e["label"] == entry["label"] for e in doc["entries"]):
            raise VaultError(f"já existe uma entrada com o rótulo '{entry['label']}'.")
        doc["entries"].append(entry)
        self.save_manifest(doc)

    def entries(self, dataset: str | None = None) -> list[dict[str, Any]]:
        es = self.manifest()["entries"]
        return [e for e in es if dataset is None or e["dataset"] == dataset]

    def resolve(self, ref: str, dataset: str | None = None) -> dict[str, Any]:
        es = self.entries()
        if ref == "latest":
            cands = [e for e in es if dataset is None or e["dataset"] == dataset]
            if not cands:
                raise VaultError(f"nenhuma entrada '{dataset}' no cofre. Rode: sentinela ingest <csv> --dataset {dataset}")
            return cands[-1]
        for e in es:
            if e["label"] == ref or e["id"] == ref:
                if dataset and e["dataset"] != dataset:
                    raise VaultError(f"a entrada '{ref}' é do dataset '{e['dataset']}', não '{dataset}'.")
                return e
        prefix = [e for e in es if e["id"].startswith(ref)]
        if len(prefix) == 1:
            return prefix[0]
        raise VaultError(f"entrada '{ref}' não encontrada no cofre (sentinela vault para listar).")

    def materialize(self, entry: dict[str, Any], ws: Workspace) -> Path:
        dst = ws.file(f"{entry['id']}.csv")
        decrypt_file(self.keys, self.dir / entry["file"], dst, KIND_FILE)
        if sha256_file(dst) != entry["sha256"]:
            raise VaultError(f"integridade: conteúdo de '{entry['label']}' não confere com o manifesto.")
        return dst

    def remove_entry(self, ref: str) -> dict[str, Any]:
        doc = self.manifest()
        e = self.resolve(ref)
        secure_delete(self.dir / e["file"])
        doc["entries"] = [x for x in doc["entries"] if x["id"] != e["id"]]
        self.save_manifest(doc)
        return e

    # ---- runs (report bundles)
    def add_run(self, files: dict[str, Path], meta: dict[str, Any]) -> dict[str, Any]:
        rid = secrets.token_hex(4)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, path in sorted(files.items()):
                info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))  # no timestamps in the bundle
                info.external_attr = 0o600 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, Path(path).read_bytes())
        target = self.runs_dir / f"run-{rid}.sntl"
        encrypt_bytes(self.keys, buf.getvalue(), target, KIND_BUNDLE)
        entry = {"id": rid, "file": target.name, "files": sorted(files), "created": date.today().isoformat(), **meta}
        doc = self.manifest()
        doc["runs"].append(entry)
        self.save_manifest(doc)
        return entry

    def runs(self) -> list[dict[str, Any]]:
        return self.manifest()["runs"]

    def resolve_run(self, ref: str) -> dict[str, Any]:
        rs = self.runs()
        if ref == "latest" and rs:
            return rs[-1]
        hits = [r for r in rs if r["id"] == ref or r["id"].startswith(ref)]
        if len(hits) == 1:
            return hits[0]
        raise VaultError(f"relatório '{ref}' não encontrado (sentinela runs para listar).")

    def extract_run(self, ref: str, dest: Path, only: set[str] | None = None) -> tuple[dict[str, Any], list[Path]]:
        run = self.resolve_run(ref)
        data = decrypt_bytes(self.keys, self.runs_dir / run["file"], KIND_BUNDLE)
        dest.mkdir(parents=True, exist_ok=True)
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if ".." in Path(name).parts or name.startswith("/"):
                    raise VaultError("pacote de relatório inválido.")
                if only and not any(name.endswith(ext) or name.startswith(ext) for ext in only):
                    continue
                target = dest / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(name))
                os.chmod(target, 0o600)
                os.utime(target, (FIXED_MTIME, FIXED_MTIME))
                out.append(target)
        return run, out

    def remove_run(self, ref: str) -> dict[str, Any]:
        run = self.resolve_run(ref)
        secure_delete(self.runs_dir / run["file"])
        doc = self.manifest()
        doc["runs"] = [r for r in doc["runs"] if r["id"] != run["id"]]
        self.save_manifest(doc)
        return run


def view_dir() -> Path:
    base, _ = workspace_base()
    d = base / f"sentinela-view-{os.getuid()}"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    if d.stat().st_uid != os.getuid() or stat.S_IMODE(d.stat().st_mode) != 0o700:
        raise VaultError(f"diretório de visualização inseguro: {d}")
    return d


def iter_user_workspaces() -> Iterator[Path]:
    base, _ = workspace_base()
    for p in base.glob("sentinela-*"):
        try:
            if p.is_dir() and p.stat().st_uid == os.getuid():
                yield p
        except OSError:
            continue
