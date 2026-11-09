"""End-to-end: the engine must find the anomalies planted in synthetic data."""
import json
import tempfile
import unittest
from pathlib import Path

from sentinela.contracts import pseudonymize
from sentinela.pipeline import analyze
from sentinela.report import render_html, to_json
from sentinela.study import load_secret, load_study
from sentinela.security import unlock
from sentinela.synthetic import demo_study_text, generate


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        unlock(root, create_if_missing=True)
        cls.planted = generate(root / "data" / "demo", seed=7, players=1200)
        (root / "studies").mkdir()
        path = root / "studies" / "demo.yaml"
        path.write_text(demo_study_text(data="../data/demo"), encoding="utf-8")
        cls.study = load_study(path)
        cls.ev = analyze(cls.study)
        cls.secret = load_secret(cls.study)
        cls.scored = {p["player_id"]: p for p in cls.ev["results"]["players"]["all_scored"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def tiers(self, raw_ids):
        return [self.scored.get(pseudonymize(r, self.secret), {}).get("risk_tier", "nenhum") for r in raw_ids]

    def test_planted_risk_players_are_flagged(self):
        for group in ("bonus_abusers", "big_winners", "cashout_no_play"):
            tiers = self.tiers(getattr(self.planted, group))
            missed = [t for t in tiers if t not in ("alto", "medio")]
            self.assertEqual(missed, [], f"{group}: {tiers}")

    def test_big_winners_are_high_risk(self):
        self.assertTrue(all(t == "alto" for t in self.tiers(self.planted.big_winners)))

    def test_whales_get_bet_size_flag(self):
        for raw in self.planted.whales:
            p = self.scored[pseudonymize(raw, self.secret)]
            self.assertIn("BET_SIZE_OUTLIER", p["flags"])

    def test_precision_is_reasonable(self):
        planted = {pseudonymize(r, self.secret) for g in ("bonus_abusers", "big_winners", "cashout_no_play", "whales")
                   for r in getattr(self.planted, g)}
        flagged = self.ev["results"]["players"]["flagged"]
        extra = [p for p in flagged if p["player_id"] not in planted]
        self.assertLessEqual(len(extra) / len(flagged), 0.15, extra)

    def test_broken_game_and_bad_affiliate_detected(self):
        games = {g["game_name"]: g for g in self.ev["results"]["games"]["games"]}
        broken = games.pop(self.planted.broken_game)
        self.assertTrue(broken["hold_flag"] or broken["hold_watch"], broken)   # detected (alert or watch list)
        self.assertLess(broken["band_z"], 0)
        self.assertEqual([g for g in games.values() if g["hold_flag"]], [])  # no honest game raises an alert
        affs = {a["btag"]: a for a in self.ev["results"]["affiliates"]["affiliates"]}
        self.assertTrue(affs[self.planted.abuse_btag]["risk_flag"])

    def test_reconciliation_and_contracts_clean(self):
        self.assertEqual([c for c in self.ev["checks"] if c["status"] == "FALHA"], [])
        self.assertTrue(all(d["status"] == "OK" for d in self.ev["datasets"].values()))

    def test_no_raw_player_id_leaks(self):
        html = render_html(self.ev)
        blob = to_json(self.ev)
        some_raw = (self.planted.big_winners + self.planted.whales)[:5] + ["USR100000", "USR100001"]
        for raw in some_raw:
            self.assertNotIn(f'"{raw}"', blob)
            self.assertNotIn(raw, html)
        json.loads(blob)  # evidence is valid JSON


if __name__ == "__main__":
    unittest.main()
