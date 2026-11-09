import unittest

from sentinela.contracts import ContractError, map_columns, normalize_header
from sentinela.pipeline import Session, analyze, connect, load_inputs
from sentinela.study import load_config
from tests.helpers import TmpProject

ACTIVITY_OK = """
dia,player_id,provider_name,btag,turnover,ggr,total_apostas
2026-05-01,A,ProvX,aff1,100.10,10.01,10
2026-05-02,B,ProvY,,200.20,-20.02,20
"""


class HeaderMappingTests(unittest.TestCase):
    def test_normalize_header_strips_accents_and_punctuation(self):
        self.assertEqual(normalize_header("  Situação do Depósito "), "situacao_do_deposito")

    def test_aliases_and_explicit_map(self):
        contracts, _ = load_config("contracts.yaml")
        spec = contracts["datasets"]["activity"]
        mapping, ignored = map_columns(
            ["Data", "ID Jogador", "Provedor", "Valor Apostado", "GGR", "Apostas", "Extra"], spec)
        self.assertEqual(mapping["dia"], "Data")
        self.assertEqual(mapping["player_id"], "ID Jogador")
        self.assertEqual(mapping["turnover"], "Valor Apostado")
        self.assertIn("Extra", ignored)
        mapping, _ = map_columns(["quando", "quem", "prov", "t", "g", "n"], spec,
                                 {"quando": "dia", "quem": "player_id", "prov": "provider_name",
                                  "t": "turnover", "g": "ggr", "n": "total_apostas"})
        self.assertEqual(mapping["turnover"], "t")


class ContractLoadTests(unittest.TestCase):
    def setUp(self):
        self.p = TmpProject()

    def tearDown(self):
        self.p.cleanup()

    def _load(self, study):
        with Session(study) as sess:
            return load_inputs(study, connect(sess.ws), sess)

    def test_brazilian_format_autodetected(self):
        self.p.write("data/a.csv", """
            data;id_jogador;provedor;valor_apostado;resultado_casa;apostas
            01/05/2026;A;ProvX;R$ 1.234,56;(12,34);10
            02/05/2026;B;ProvX;0,10;0,20;1
        """)
        study = self.p.study("activity: {path: ../data/a.csv, delimiter: ';'}")
        reports, _, _ = self._load(study)
        rep = reports["activity"]
        self.assertEqual(rep.decimal_separator, ",")
        self.assertEqual(rep.rows_loaded, 2)

    def test_ambiguous_decimal_is_refused(self):
        self.p.write("data/a.csv", """
            dia,player_id,provider_name,turnover,ggr,total_apostas
            2026-05-01,A,P,"1,234","1,000",1
        """)
        study = self.p.study("activity: ../data/a.csv")
        with self.assertRaisesRegex(ContractError, "ambíguo"):
            self._load(study)

    def test_invalid_rows_fail_or_drop(self):
        self.p.write("data/a.csv", """
            dia,player_id,provider_name,turnover,ggr,total_apostas
            2026-05-01,A,P,100.00,5.00,10
            2026-13-01,B,P,100.00,5.00,10
            2026-05-02,,P,100.00,5.00,10
            2026-05-03,C,P,-1.00,5.00,10
            2026-05-04,D,P,abc,5.00,10
            2026-05-05,E,P,10.00,5.00,1.5
        """)
        study = self.p.study("activity: ../data/a.csv")
        with self.assertRaises(ContractError) as ctx:
            self._load(study)
        rep = ctx.exception.report
        ids = {i.check_id for i in rep.issues}
        self.assertTrue({"dia.tipo", "player_id.obrigatorio", "turnover.min", "turnover.tipo",
                         "total_apostas.tipo"} <= ids, ids)
        self.assertEqual(rep.rows_with_errors, 5)

        study = self.p.study("activity: ../data/a.csv", extra="on_contract_error: drop")
        reports, _, _ = self._load(study)
        self.assertEqual(reports["activity"].rows_loaded, 1)
        self.assertEqual(reports["activity"].rows_dropped, 5)

    def test_duplicate_key_detected(self):
        self.p.write("data/a.csv", """
            dia,player_id,provider_name,turnover,ggr,total_apostas
            2026-05-01,A,P,100.00,5.00,10
            2026-05-01,A,P,50.00,1.00,5
        """)
        with self.assertRaises(ContractError) as ctx:
            self._load(self.p.study("activity: ../data/a.csv"))
        self.assertIn("chave.duplicada", {i.check_id for i in ctx.exception.report.issues})

    def test_warning_rule_keeps_row(self):
        self.p.write("data/a.csv", """
            dia,player_id,provider_name,turnover,ggr,total_apostas
            2026-05-01,A,P,100.00,150.00,10
        """)
        reports, _, _ = self._load(self.p.study("activity: ../data/a.csv"))
        rep = reports["activity"]
        self.assertEqual(rep.rows_loaded, 1)
        self.assertEqual(rep.rows_with_warnings, 1)
        self.assertEqual(rep.status, "ALERTA")

    def test_missing_required_column_message(self):
        self.p.write("data/a.csv", "dia,player_id\n2026-05-01,A\n")
        with self.assertRaisesRegex(ContractError, "colunas obrigatórias ausentes"):
            self._load(self.p.study("activity: ../data/a.csv"))

    def test_player_ids_are_pseudonymized_on_load(self):
        self.p.write("data/a.csv", ACTIVITY_OK)
        study = self.p.study("activity: ../data/a.csv")
        with Session(study) as sess:
            con = connect(sess.ws)
            load_inputs(study, con, sess)
        ids = {r[0] for r in con.execute("SELECT player_id FROM activity").fetchall()}
        self.assertFalse(ids & {"A", "B"})
        self.assertTrue(all(i.startswith("P-") and len(i) == 18 for i in ids))

    def test_payment_value_aliases(self):
        self.p.write("data/a.csv", ACTIVITY_OK)
        self.p.write("data/p.csv", """
            id,data,user_id,tipo,valor,situacao
            1,2026-05-01,A,Depósito,100.00,Aprovado
            2,2026-05-02,A,SAQUE,50.00,recusado
            3,2026-05-02,B,transfer,10.00,ok
        """)
        study = self.p.study("activity: ../data/a.csv\npayments: ../data/p.csv")
        with self.assertRaises(ContractError) as ctx:
            analyze(study)
        self.assertIn("type.tipo", {i.check_id for i in ctx.exception.report.issues})


if __name__ == "__main__":
    unittest.main()
