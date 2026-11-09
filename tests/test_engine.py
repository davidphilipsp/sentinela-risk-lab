"""Golden tests: tiny datasets whose correct answers were computed by hand."""
import unittest
from decimal import Decimal

from sentinela.pipeline import analyze
from tests.helpers import TmpProject

ACTIVITY = """
dia,player_id,provider_name,btag,turnover,ggr,total_apostas
2026-05-01,A,ProvX,aff1,100.10,10.01,10
2026-05-01,B,ProvY,,200.20,-20.02,20
2026-05-02,A,ProvY,aff1,300.30,30.03,30
2026-05-02,C,ProvX,aff2,0.10,0.20,1
2026-05-02,D,ProvX,aff2,0.20,-0.10,1
2026-04-30,C,ProvX,aff2,999.00,99.00,9
"""


class GoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = TmpProject()
        cls.p.write("data/a.csv", ACTIVITY)
        cls.ev = analyze(cls.p.study("activity: ../data/a.csv", end="2026-05-02"))
        cls.r = cls.ev["results"]

    @classmethod
    def tearDownClass(cls):
        cls.p.cleanup()

    def test_executive_totals_are_exact(self):
        m = self.r["executive"]["metrics"]
        self.assertEqual(m["turnover"], Decimal("600.90"))   # 0.10 + 0.20 sums exactly (no float drift)
        self.assertEqual(m["ggr"], Decimal("20.12"))
        self.assertEqual(m["bets"], 62)
        self.assertEqual(m["players"], 4)
        self.assertEqual(m["providers"], 2)
        self.assertEqual(m["hold"], (Decimal("20.12") / Decimal("600.90")).quantize(Decimal("1e-10")))
        self.assertEqual(m["period_days"], 2)

    def test_out_of_period_rows_ignored_and_reported(self):
        r7 = next(c for c in self.ev["checks"] if c["id"] == "R7.outside")
        self.assertEqual(r7["actual"], 1)

    def test_providers(self):
        prov = {p["provider_name"]: p for p in self.r["providers"]["providers"]}
        self.assertEqual(prov["ProvY"]["turnover"], Decimal("500.50"))
        self.assertEqual(prov["ProvX"]["ggr"], Decimal("10.11"))
        self.assertEqual(self.r["providers"]["top_provider"], "ProvY")

    def test_missing_btag_gets_default(self):
        btags = {a["btag"] for a in self.r["affiliates"]["affiliates"]}
        self.assertIn("(sem btag)", btags)

    def test_all_reconciliations_pass(self):
        failed = [c for c in self.ev["checks"] if c["status"] == "FALHA"]
        self.assertEqual(failed, [])

    def test_no_ai_and_hashes_present(self):
        meta = self.ev["meta"]
        self.assertFalse(meta["ai_used"])
        self.assertEqual(len(meta["run_id"]), 64)
        self.assertIn("activity", meta["input_sha256"])


class TopJogosTests(unittest.TestCase):
    """Regression for the double-count bug of the original get_game_performance."""

    def setUp(self):
        self.p = TmpProject()

    def tearDown(self):
        self.p.cleanup()

    def test_per_game_metrics_not_multiplied(self):
        self.p.write("data/a.csv", '''
            dia,player_id,provider_name,turnover,ggr,total_apostas,top_jogos
            2026-05-01,A,P,100.00,10.00,30,"{""G1"": {""turnover"": 50, ""ggr"": 5, ""bets"": 10}, ""G2"": {""turnover"": 30, ""ggr"": 3, ""bets"": 10}, ""G3"": {""turnover"": 20, ""ggr"": 2, ""bets"": 10}}"
        ''')
        ev = analyze(self.p.study("activity: ../data/a.csv"))
        g = ev["results"]["games"]
        self.assertEqual(g["mode"], "metrics")
        self.assertEqual(g["total_turnover"], Decimal("100"))   # the old code would report 300
        self.assertEqual({x["game_name"]: x["turnover"] for x in g["games"]}["G1"], Decimal("50"))
        r5 = next(c for c in ev["checks"] if c["id"] == "R5.games")
        self.assertEqual(r5["status"], "PASS")

    def test_double_count_is_detected_by_reconciliation(self):
        self.p.write("data/a.csv", ACTIVITY.replace("2026-04-30,C,ProvX,aff2,999.00,99.00,9\n", ""))
        self.p.write("data/g.csv", """
            dia,player_id,provider_name,game_name,turnover,ggr,total_apostas
            2026-05-01,A,ProvX,G1,100.10,10.01,10
            2026-05-01,A,ProvX,G2,100.10,10.01,10
        """)
        ev = analyze(self.p.study("activity: ../data/a.csv\ngames: ../data/g.csv", end="2026-05-02"))
        r5 = next(c for c in ev["checks"] if c["id"] == "R5.games")
        self.assertEqual(r5["status"], "ALERTA")   # games cover less than activity
        self.p.write("data/g.csv", """
            dia,player_id,provider_name,game_name,turnover,ggr,total_apostas
            2026-05-01,A,ProvX,G1,600.90,10.01,10
            2026-05-01,A,ProvX,G2,600.90,10.01,10
        """)
        ev = analyze(self.p.study("activity: ../data/a.csv\ngames: ../data/g.csv", end="2026-05-02"))
        r5 = next(c for c in ev["checks"] if c["id"] == "R5.games")
        self.assertEqual(r5["status"], "FALHA")    # games exceed activity -> double count

    def test_names_only_json_uses_appearances(self):
        self.p.write("data/a.csv", '''
            dia,player_id,provider_name,turnover,ggr,total_apostas,top_jogos
            2026-05-01,A,P,100.00,10.00,30,"[{""name"": ""G1""}, {""name"": ""G2""}]"
        ''')
        g = analyze(self.p.study("activity: ../data/a.csv"))["results"]["games"]
        self.assertEqual(g["mode"], "appearances")
        self.assertEqual({x["game_name"] for x in g["games"]}, {"G1", "G2"})


if __name__ == "__main__":
    unittest.main()
