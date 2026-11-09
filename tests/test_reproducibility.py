import tempfile
import unittest
from pathlib import Path

from sentinela.pipeline import analyze
from sentinela.report import to_json
from sentinela.study import load_study
from sentinela.security import unlock
from sentinela.synthetic import demo_study_text, generate


class ReproducibilityTests(unittest.TestCase):
    def test_same_inputs_same_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unlock(root, create_if_missing=True)
            generate(root / "data" / "demo", seed=3, players=400)
            (root / "studies").mkdir()
            path = root / "studies" / "s.yaml"
            path.write_text(demo_study_text(data="../data/demo"), encoding="utf-8")
            a, b = analyze(load_study(path)), analyze(load_study(path))
            for ev in (a, b):
                ev["meta"].pop("generated_at")
            self.assertEqual(a["meta"]["run_id"], b["meta"]["run_id"])
            self.assertEqual(to_json(a), to_json(b))

    def test_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate(Path(tmp) / "x", seed=11, players=100)
            generate(Path(tmp) / "y", seed=11, players=100)
            for name in ("activity.csv", "payments.csv", "clients.csv", "games.csv"):
                self.assertEqual((Path(tmp) / "x" / name).read_bytes(), (Path(tmp) / "y" / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
