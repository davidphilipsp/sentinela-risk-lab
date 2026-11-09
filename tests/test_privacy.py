"""Exports with direct personal data (name, email, phone, CPF) must never leak into any output."""
import unittest

from sentinela.contracts import is_pii_header
from sentinela.pipeline import analyze
from sentinela.report import render_html, table_exports, to_json
from tests.helpers import TmpProject

PII_VALUES = ["joao@mail.com", "maria@mail.com", "Joao Silva", "Maria Souza", "90000-0000", "90000-0001",
              "123.456.789-09", "987.654.321-00", "Rua das Flores"]


class PiiTests(unittest.TestCase):
    def setUp(self):
        self.p = TmpProject()
        # player_id is itself an email (common in exports) + several direct-PII columns
        self.p.write("data/a.csv", """
            dia,player_id,Nome Completo,E-mail,Telefone Celular,CPF,Endereço,provider_name,turnover,ggr,total_apostas
            2026-05-01,joao@mail.com,Joao Silva,joao@mail.com,+55 11 90000-0000,123.456.789-09,Rua das Flores 1,ProvX,100.00,5.00,10
            2026-05-02,maria@mail.com,Maria Souza,maria@mail.com,(21) 90000-0001,987.654.321-00,Rua das Flores 2,ProvY,200.00,-3.00,20
        """)
        self.ev = analyze(self.p.study("activity: ../data/a.csv"))

    def tearDown(self):
        self.p.cleanup()

    def test_pii_headers_detected_and_discarded(self):
        ds = self.ev["datasets"]["activity"]
        self.assertEqual(set(ds["pii_discarded"]), {"Nome Completo", "E-mail", "Telefone Celular", "CPF", "Endereço"})
        self.assertNotIn("E-mail", ds["ignored_columns"])

    def test_no_pii_value_in_any_output(self):
        blobs = [to_json(self.ev), render_html(self.ev)]
        for name, rows in table_exports(self.ev).items():
            blobs.append(name + repr(rows))
        everything = "\n".join(blobs)
        for value in PII_VALUES:
            self.assertNotIn(value, everything)

    def test_header_classifier(self):
        for h in ["email", "E-mail", "telefone", "celular_whatsapp", "cpf", "nome", "Nome Completo", "first_name", "player_name", "data_nascimento", "ip_address"]:
            self.assertTrue(is_pii_header(h), h)
        for h in ["turnover", "provider_name", "dia", "ggr", "btag", "kyc_status", "total_apostas", "game_name", "tipo", "nome_jogo", "campaign_name"]:
            self.assertFalse(is_pii_header(h), h)


if __name__ == "__main__":
    unittest.main()
