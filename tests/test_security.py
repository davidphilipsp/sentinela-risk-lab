"""Security core: encryption, tamper detection, sanitizing ingestion, RAM workspaces, trace hygiene."""
import hashlib
import io
import os
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path

from sentinela import security as sec
from sentinela.ingest import ingest_file
from sentinela.pipeline import Session, analyze
from sentinela.security import CHUNK, Vault, VaultError, Workspace, decrypt_stream, encrypt_stream
from sentinela.study import StudyError, load_config, load_study
from sentinela.traces import clean_history, doctor, file_uri, scan_history


def _keys():
    return sec.Keys(os.urandom(32), "x" * 64)


def _enc(keys, data: bytes) -> bytes:
    out = io.BytesIO()
    encrypt_stream(keys, io.BytesIO(data), out)
    return out.getvalue()


def _dec(keys, blob: bytes) -> bytes:
    out = io.BytesIO()
    decrypt_stream(keys, io.BytesIO(blob), out)
    return out.getvalue()


class CryptoTests(unittest.TestCase):
    def test_roundtrip_chunk_boundaries(self):
        keys = _keys()
        for size in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK):
            data = os.urandom(size)
            self.assertEqual(_dec(keys, _enc(keys, data)), data, size)

    def test_ciphertext_reveals_nothing_and_is_randomized(self):
        keys = _keys()
        data = b"dia,player_id\n2026-05-01,joao@mail.com\n" * 100
        a, b = _enc(keys, data), _enc(keys, data)
        self.assertNotEqual(a, b)
        self.assertNotIn(b"joao", a)
        self.assertNotIn(b"player_id", a)

    def test_tamper_truncation_and_wrong_key_detected(self):
        keys = _keys()
        blob = bytearray(_enc(keys, os.urandom(CHUNK + 100)))
        flipped = bytearray(blob)
        flipped[len(flipped) // 2] ^= 1
        with self.assertRaises(VaultError):
            _dec(keys, bytes(flipped))
        first_len = int.from_bytes(blob[26:30], "big")
        with self.assertRaises(VaultError):              # cut at a chunk boundary: final flag mismatch
            _dec(keys, bytes(blob[:26 + 4 + first_len]))
        with self.assertRaises(VaultError):
            _dec(_keys(), bytes(blob))
        with self.assertRaises(VaultError):
            _dec(keys, b"not a vault file at all")


class RamDetectionTests(unittest.TestCase):
    MOUNTS = textwrap.dedent("""\
        /dev/mapper/vgubuntu-root / ext4 rw,relatime 0 0
        udev /dev devtmpfs rw,nosuid 0 0
        tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
        tmpfs /run/user/1000 tmpfs rw,nosuid,nodev 0 0
        /dev/sda1 /d ext4 rw 0 0
        """)

    def test_tmpfs_longest_mount_match(self):
        self.assertTrue(sec._is_tmpfs("/dev/shm", self.MOUNTS))
        self.assertTrue(sec._is_tmpfs("/dev/shm/sentinela-ws-abc/file.csv", self.MOUNTS))
        self.assertTrue(sec._is_tmpfs("/run/user/1000", self.MOUNTS))
        self.assertFalse(sec._is_tmpfs("/dev", self.MOUNTS))          # devtmpfs is not a RAM workspace
        self.assertFalse(sec._is_tmpfs("/home/david", self.MOUNTS))   # ext4 on LUKS = disk
        self.assertFalse(sec._is_tmpfs("/dev/shmX", self.MOUNTS))     # no false prefix match


class KeyringTests(unittest.TestCase):
    def test_passphrase_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with self.assertRaises(VaultError):
                sec.init_keyring(home, "short")
            keys = sec.init_keyring(home, "correct horse battery")
            self.assertEqual(oct(sec.keyring_path(home).stat().st_mode & 0o777), "0o600")
            self.assertNotIn(keys.pseudo_secret, sec.keyring_path(home).read_text())
            sec.forget_keys()
            with self.assertRaisesRegex(VaultError, "incorreta"):
                sec.unlock(home, "wrong passphrase!!")
            sec.change_passphrase(home, "correct horse battery", "another long passphrase")
            sec.forget_keys()
            again = sec.unlock(home, "another long passphrase")
            self.assertEqual(again.data_key, keys.data_key)   # data never needs re-encryption
            sec.forget_keys()


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fake_home = self.root / "home"
        (self.fake_home / ".local" / "share").mkdir(parents=True)
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.fake_home)
        self.keys = sec.unlock(self.root, create_if_missing=True)
        self.vault = Vault(self.root, self.keys)
        self.contracts, _ = load_config("contracts.yaml")
        self.src = self.root / "Downloads" / "Operator Export Secreto.csv"
        self.src.parent.mkdir()
        self.src.write_text(textwrap.dedent("""\
            dia,player_id,Nome,Telefone,CPF,contato,provider_name,turnover,ggr,total_apostas
            2026-05-01,joao@mail.com,Joao Silva,11900000000,123.456.789-09,joao@mail.com,ProvX,100.00,5.00,10
            2026-05-02,maria@mail.com,Maria Souza,21900000001,987.654.321-00,maria@mail.com,ProvY,200.00,-3.00,20
            """), encoding="utf-8")
        # desktop traces pointing at the source file
        uri = file_uri(self.src)
        (self.fake_home / ".local" / "share" / "recently-used.xbel").write_text(
            f'<?xml version="1.0"?>\n<xbel>\n  <bookmark href="{uri}" added="x">\n  </bookmark>\n'
            f'  <bookmark href="file:///other.txt" added="x">\n  </bookmark>\n</xbel>\n', encoding="utf-8")
        thumbs = self.fake_home / ".cache" / "thumbnails" / "normal"
        thumbs.mkdir(parents=True)
        self.thumb = thumbs / (hashlib.md5(uri.encode()).hexdigest() + ".png")
        self.thumb.write_bytes(b"png")

    def tearDown(self):
        os.environ["HOME"] = self.old_home or ""
        self.tmp.cleanup()

    def test_ingest_sanitizes_encrypts_and_erases(self):
        e = ingest_file(self.vault, self.src, "activity", self.contracts, label="act-may")
        self.assertEqual(set(e["pii_removed_by_header"]), {"Nome", "Telefone", "CPF"})
        self.assertEqual(e["pii_removed_by_content"], ["contato"])
        self.assertIn("player_id", e["columns"])               # contract column kept even with e-mails
        self.assertFalse(self.src.exists())                      # original securely deleted
        self.assertFalse(self.thumb.exists())                    # thumbnail removed
        xbel = (self.fake_home / ".local" / "share" / "recently-used.xbel").read_text()
        self.assertNotIn("Secreto", xbel)
        self.assertIn("other.txt", xbel)
        stored = (self.root / "vault" / e["file"]).read_bytes()
        manifest = (self.root / "vault" / "manifest.sntl").read_bytes()
        for needle in (b"joao", b"ProvX", b"Silva", b"act-may", b"Secreto", b"player_id"):
            self.assertNotIn(needle, stored)
            self.assertNotIn(needle, manifest)
        self.assertEqual((self.root / "vault" / e["file"]).stat().st_mtime, sec.FIXED_MTIME)
        with Workspace() as ws:
            clean = self.vault.materialize(e, ws).read_text()
        self.assertNotIn("Silva", clean)
        self.assertNotIn("contato", clean)
        self.assertIn("joao@mail.com", clean)                   # the ID itself is hashed later, at analysis

    def test_study_reads_vault_and_wipes_workspace(self):
        e = ingest_file(self.vault, self.src, "activity", self.contracts, label="act-may")
        study_path = self.root / "studies" / "s.yaml"
        study_path.parent.mkdir()
        study_path.write_text('study: {title: T, period: {start: 2026-05-01, end: 2026-05-31}}\n'
                              f'inputs: {{activity: {{vault: {e["label"]}}}}}\nsecurity: {{home: ..}}\n', encoding="utf-8")
        study = load_study(study_path)
        with Session(study) as sess:
            ws_path = sess.ws.path
            ev = analyze(study, sess)
            self.assertTrue(ws_path.exists())
        self.assertFalse(ws_path.exists())                       # plaintext gone after the run
        self.assertEqual(ev["datasets"]["activity"]["path"], "vault:act-may")
        self.assertEqual(ev["results"]["executive"]["metrics"]["players"], 2)

    def test_plaintext_inputs_refused_by_default(self):
        p = self.root / "s.yaml"
        p.write_text("study: {title: T, period: {start: 2026-05-01, end: 2026-05-31}}\n"
                     "inputs: {activity: data.csv}\n", encoding="utf-8")
        with self.assertRaisesRegex(StudyError, "sentinela ingest"):
            load_study(p)

    def test_report_bundle_has_no_timestamps(self):
        f = self.root / "x.txt"
        f.write_text("conteudo")
        run = self.vault.add_run({"relatorio.html": f}, {"title": "T", "run_id": "r", "period": {"start": "a", "end": "b"},
                                                          "sections": []})
        data = sec.decrypt_bytes(self.keys, self.vault.runs_dir / run["file"], sec.KIND_BUNDLE)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            self.assertEqual(zf.infolist()[0].date_time, (1980, 1, 1, 0, 0, 0))
        self.assertNotIn(b"conteudo", (self.vault.runs_dir / run["file"]).read_bytes())


class TraceTests(unittest.TestCase):
    def test_history_scan_and_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.environ.get("HOME")
            os.environ["HOME"] = tmp
            try:
                hist = Path(tmp) / ".bash_history"
                hist.write_text("ls\nsentinela ingest ~/Downloads/secret.csv --dataset activity\ncd /x\n")
                project = Path(tmp) / "proj"
                self.assertEqual(sum(scan_history(project).values()), 1)
                clean_history(project)
                self.assertEqual(hist.read_text(), "ls\ncd /x\n")
            finally:
                os.environ["HOME"] = old or ""

    def test_secure_delete_and_doctor(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.csv"
            f.write_text("secret")
            sec.secure_delete(f)
            self.assertFalse(f.exists())
            (Path(tmp) / "leftover.csv").write_text("x")
            checks = {c["check"]: c for c in doctor(Path(tmp))}
            self.assertEqual(checks["Arquivos em texto puro no projeto"]["status"], "FALHA")
            self.assertIn("Keyring", checks)


if __name__ == "__main__":
    unittest.main()
