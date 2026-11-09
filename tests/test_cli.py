import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from sentinela.cli import main


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_demo_validate_run_view_export_lookup(self):
        """Production path: synthetic data -> ingest -> encrypted vault -> encrypted report."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, out = run("demo", "--root", tmp, "--players", "300", "--no-run")
            self.assertEqual(code, 0, out)
            study = str(root / "studies" / "demo-study.yaml")
            code, out = run("validate", study)
            self.assertEqual(code, 0, out)
            code, out = run("run", study, "--formats", "html,json,csv", "--strict")
            self.assertEqual(code, 0, out)
            # nothing readable on disk: no CSV/HTML/JSON anywhere in the project, only .sntl files
            leaked = [p for p in root.rglob("*") if p.is_file() and p.suffix in {".csv", ".html", ".json", ".pdf"}
                      and ".sentinela" not in p.parts]
            self.assertEqual(leaked, [], leaked)
            self.assertTrue(list((root / "vault" / "runs").glob("run-*.sntl")))
            code, out = run("runs", "--home", tmp)
            self.assertIn("Estudo Hipotético", out)
            code, out = run("view", "latest", "--home", tmp)
            self.assertEqual(code, 0, out)
            self.assertIn(".html", out)
            dest = root / "export"
            code, out = run("export", "latest", "--to", str(dest), "--only", "html,tables", "--home", tmp)
            self.assertEqual(code, 0, out)
            self.assertTrue(list(dest.glob("*.html")))
            self.assertTrue(list(dest.glob("tables/players_flagged.csv")))
            self.assertFalse(list(dest.glob("*.json")))
            from sentinela.contracts import pseudonymize
            from sentinela.security import unlock
            secret = unlock(root).pseudo_secret
            code, out = run("lookup", study, pseudonymize("USR100005", secret))
            self.assertIn("USR100005", out)
            code, out = run("clean", "--home", tmp)
            self.assertEqual(code, 0, out)

    def test_inspect_suggests_column_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv = Path(tmp) / "x.csv"
            csv.write_text("quando,quem,valor\n2026-05-01,A,1\n", encoding="utf-8")
            code, out = run("inspect", str(csv), "--dataset", "activity")
            self.assertEqual(code, 2)
            self.assertIn("column_map", out)

    def test_new_study_and_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = run("new-study", str(Path(tmp) / "s.yaml"), "--title", "X")
            self.assertEqual(code, 0)
            self.assertIn('title: "X"', (Path(tmp) / "s.yaml").read_text())
        code, out = run("contracts")
        self.assertEqual(code, 0)
        self.assertIn("activity", out)

    def test_bad_study_is_friendly_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.yaml"
            p.write_text("study: {title: X}\n", encoding="utf-8")
            code, out = run("run", str(p))
            self.assertEqual(code, 2)
            self.assertIn("period", out)


if __name__ == "__main__":
    unittest.main()
