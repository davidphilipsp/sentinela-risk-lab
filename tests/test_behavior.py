"""Behavior module: golden lifecycle/features, configurable rules, guard, control groups, exports."""
import contextlib
import io
import os
import unittest
from decimal import Decimal

from sentinela.behavior import RuleError, compile_rule, control_group, validate_config, FEATURES
from sentinela.cli import main
from sentinela.pipeline import analyze
from sentinela.study import load_config
from tests.helpers import TmpProject

CLIENTS = """
player_id,created_at,kyc_status,btag
A,2026-01-10,aprovado,aff1
B,2026-05-28,aprovado,aff2
C,2026-03-01,aprovado,
D,2026-05-20,pendente,aff1
"""
ACTIVITY = """
dia,player_id,provider_name,turnover,ggr,total_apostas
2026-05-30,A,P1,300.00,10.00,30
2026-05-29,B,P1,40.00,-5.00,8
2026-05-10,C,P2,90.00,4.00,9
2026-02-01,E,P2,20.00,1.00,2
"""
PAYMENTS = """
id,paid_at,player_id,type,amount,status
1,2026-05-05,A,deposit,1000.00,approved
2,2026-05-25,A,deposit,500.00,approved
3,2026-05-28,B,deposit,50.00,approved
4,2026-04-01,C,deposit,100.00,approved
5,2026-05-15,F,deposit,80.00,approved
6,2026-05-16,A,deposit,999.00,rejected
"""
BEHAVIOR = """
version: "test"
payday_windows: [[1, 10]]
lifecycle:
  - {id: cadastrado_sem_ftd, when: "lifetime_deposit_count = 0 AND last_activity_date IS NULL"}
  - {id: depositou_sem_jogar, when: "lifetime_deposit_count > 0 AND last_activity_date IS NULL"}
  - {id: novo, when: "tenure_days <= 7"}
  - {id: ativo, when: "days_since_last_activity <= 7"}
  - {id: em_risco, when: "days_since_last_activity <= 30"}
  - {id: churn, when: "true"}
value_tiers:
  metric: deposits
  method: fixed
  fixed: {high: 1000, medium: 100}
  zero_label: sem_valor
suppression: {when: "kyc_status = 'pendente'"}
segments:
  - {id: payday_lovers, when: "deposit_count >= 2 AND payday_deposit_share >= 0.6", campaign: true, control_group_pct: 0}
  - {id: everyone_new, when: "lifecycle IN ('novo', 'cadastrado_sem_ftd')", campaign: true}
cohorts: {grain: month, retention_periods: 3}
"""


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class BehaviorGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = TmpProject()
        cls.p.write("data/c.csv", CLIENTS)
        cls.p.write("data/a.csv", ACTIVITY)
        cls.p.write("data/p.csv", PAYMENTS)
        cls.p.write("b.yaml", BEHAVIOR)
        cls.study = cls.p.study("activity: ../data/a.csv\npayments: ../data/p.csv\nclients: ../data/c.csv",
                                extra="behavior: ../b.yaml")
        cls.ev = analyze(cls.study)
        cls.b = cls.ev["results"]["behavior"]
        prof = cls.ev["_bulk"]["profile"]
        cls.by_raw = {}
        from sentinela.contracts import pseudonymize
        from sentinela.study import load_secret
        secret = load_secret(cls.study)
        for raw in "ABCDEF":
            cls.by_raw[raw] = next(r for r in prof if r["player_id"] == pseudonymize(raw, secret))

    @classmethod
    def tearDownClass(cls):
        cls.p.cleanup()

    def test_lifecycle_stages(self):
        got = {k: v["lifecycle"] for k, v in self.by_raw.items()}
        self.assertEqual(got, {"A": "ativo", "B": "novo", "C": "em_risco", "D": "cadastrado_sem_ftd",
                               "E": "churn", "F": "depositou_sem_jogar"})

    def test_features_exact(self):
        a = self.by_raw["A"]
        self.assertEqual(a["deposits"], Decimal("1500"))          # rejected 999 excluded
        self.assertEqual(a["deposit_count"], 2)
        self.assertAlmostEqual(a["payday_deposit_share"], 1000 / 1500)
        self.assertEqual(a["days_since_last_activity"], 1)
        self.assertEqual(a["days_since_signup"], 141)
        self.assertAlmostEqual(a["wager_multiple"], 300 / 1500)
        c = self.by_raw["C"]
        self.assertEqual(c["deposits"], Decimal("0"))              # April deposit is lifetime, not period
        self.assertEqual(c["lifetime_deposits"], Decimal("100"))
        self.assertEqual(c["days_since_last_deposit"], 60)
        self.assertEqual(self.by_raw["B"]["days_to_ftd"], 0)

    def test_value_tiers_fixed(self):
        tiers = {k: v["value_tier"] for k, v in self.by_raw.items()}
        self.assertEqual(tiers["A"], "high")
        self.assertEqual(tiers["B"], "low")
        self.assertEqual(tiers["C"], "sem_valor")
        self.assertEqual(self.b["value_tiers"]["method"], "fixed")

    def test_segments_and_suppression(self):
        seg = {s["id"]: s for s in self.b["segments"]}
        self.assertEqual(seg["payday_lovers"]["players"], 1)
        self.assertEqual(seg["everyone_new"]["players"], 2)        # B (novo) + D (sem FTD)
        self.assertEqual(seg["everyone_new"]["suppressed"], 1)     # D: KYC pendente
        self.assertEqual(seg["everyone_new"]["eligible"], 1)
        self.assertTrue(self.by_raw["D"]["suppressed"])

    def test_behavior_reconciliation(self):
        for cid in ("R11.players", "R11.turnover", "R11.tiers", "R12.deposits"):
            c = next(x for x in self.ev["checks"] if x["id"] == cid)
            self.assertEqual(c["status"], "PASS", c)

    def test_bulk_not_in_evidence_but_hash_is(self):
        from sentinela.report import to_json
        blob = to_json(self.ev)
        self.assertNotIn('"_bulk"', blob)
        self.assertIn("members_sha256", blob)

    def test_export_segment_reveal(self):
        code, out = run_cli("export-segment", str(self.study.path), "payday_lovers", "--reveal")
        self.assertEqual(code, 0, out)
        files = list((self.p.root / "outputs" / "private").glob("payday_lovers-*.csv"))
        self.assertEqual(len(files), 1)
        text = files[0].read_text()
        self.assertIn(",A,", "," + text.splitlines()[1].split(",")[0] + ",")   # first column = real id
        self.assertEqual(oct(os.stat(files[0]).st_mode & 0o777), "0o600")
        code, out = run_cli("export-segment", str(self.study.path), "payday_lovers")
        pseudo = list((self.p.root / "outputs" / "segments").glob("payday_lovers-*.csv"))[0].read_text()
        self.assertNotIn("player_id_real", pseudo)


class RuleGuardTests(unittest.TestCase):
    allowed = set(FEATURES) | {"value_tier", "lifecycle"}

    def test_valid_rules(self):
        self.assertEqual(compile_rule("deposits >= 100 AND lifecycle IN ('ativo')", self.allowed, "t"),
                         "(deposits >= 100 AND lifecycle IN ('ativo'))")
        compile_rule("coalesce(days_since_last_activity, 999) > 30", self.allowed, "t")
        compile_rule("lifecycle = 'drop table x'", self.allowed, "t")  # keywords inside text are just text
        self.assertEqual(compile_rule(True, self.allowed, "t"), "TRUE")

    def test_typo_gets_suggestion(self):
        with self.assertRaisesRegex(RuleError, "depositss.*deposits"):
            compile_rule("depositss > 10", self.allowed, "t")

    def test_injection_and_unknown_functions_rejected(self):
        for bad in ["deposits > 0; DROP TABLE activity", "deposits > 0 -- x", "read_csv('/etc/passwd') IS NULL",
                    "player_id IN (SELECT player_id FROM activity)", '"deposits" > 0', "deposits > 'x"]:
            with self.assertRaises(RuleError, msg=bad):
                compile_rule(bad, self.allowed, "t")

    def test_default_config_is_valid(self):
        cfg, _ = load_config("behavior.yaml")
        self.assertEqual(validate_config(cfg), [])

    def test_validate_reports_errors(self):
        cfg = {"lifecycle": [{"id": "x", "when": "dias_sem_jogar > 3"}],
               "segments": [{"id": "Bad-Id", "when": "true"}, {"id": "y", "when": "true", "control_group_pct": 90}]}
        errs = "\n".join(validate_config(cfg))
        self.assertIn("dias_sem_jogar", errs)
        self.assertIn("Bad-Id", errs)
        self.assertIn("control_group_pct", errs)


class ControlGroupTests(unittest.TestCase):
    def test_deterministic_and_proportional(self):
        ids = [f"P-{i:016x}" for i in range(20000)]
        groups = [control_group(i, "seg", 10) for i in ids]
        self.assertEqual(groups, [control_group(i, "seg", 10) for i in ids])
        share = groups.count("controle") / len(groups)
        self.assertTrue(0.09 < share < 0.11, share)
        other = [control_group(i, "other_seg", 10) for i in ids[:2000]]
        self.assertNotEqual(groups[:2000], other)   # independent draw per segment


if __name__ == "__main__":
    unittest.main()
