"""Synthetic (hypothetical) dataset generator with PLANTED anomalies.

Used by `sentinela demo` and by the test-suite to prove the engine finds what
was hidden in the data. All names (providers, games, btags) are fictional.
Deterministic: the same seed produces byte-identical CSVs.
"""
from __future__ import annotations

import csv
import json
import math
import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

PROVIDERS = [
    ("Aurora Games", 0.34), ("Nimbus Play", 0.16), ("Vortex Studio", 0.13), ("Pixel Forge", 0.11),
    ("Lumen Slots", 0.09), ("Orbit Gaming", 0.07), ("Cascade Live", 0.06), ("Ember Interactive", 0.04),
]
GAME_WORDS = ["Fortune", "Dragon", "Neon", "Pharaoh", "Crystal", "Thunder", "Lucky", "Jungle", "Cosmic", "Golden",
              "Ocean", "Viking", "Samurai", "Candy", "Wild", "Mystic"]
GAME_NOUNS = ["Reels", "Spins", "Quest", "Rush", "Treasure", "Blitz", "Riches", "Gems"]
BTAGS = [f"aff_{i:03d}" for i in range(1, 13)]
ABUSE_BTAG = "aff_009"
BROKEN_GAME = "Mystic Gems"  # planted: misconfigured game paying above 100% RTP


@dataclass
class Planted:
    bonus_abusers: list[str] = field(default_factory=list)
    big_winners: list[str] = field(default_factory=list)
    cashout_no_play: list[str] = field(default_factory=list)
    whales: list[str] = field(default_factory=list)
    abuse_btag: str = ABUSE_BTAG
    broken_game: str = BROKEN_GAME


def _games(rng: random.Random) -> dict[str, list[tuple[str, float]]]:
    names = [f"{w} {n}" for w in GAME_WORDS for n in GAME_NOUNS]
    rng.shuffle(names)
    names.remove(BROKEN_GAME)
    out: dict[str, list[tuple[str, float]]] = {}
    i = 0
    for prov, _ in PROVIDERS:
        games = []
        for _ in range(4):
            games.append((names[i], rng.uniform(0.025, 0.06)))  # house edge
            i += 1
        out[prov] = games
    out["Lumen Slots"][0] = (BROKEN_GAME, -0.12)
    return out


def generate(out_dir: str | Path, seed: int = 42, players: int = 2500,
             start: date = date(2026, 5, 1), days: int = 31,
             history_days: int = 0, non_depositors: int = 0) -> Planted:
    """history_days > 0 simulates play BEFORE the period with churn (for lifecycle/cohorts);
    non_depositors adds signups that never deposited. Both default to 0, which keeps the
    original byte-identical dataset used by the detection tests."""
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    games = _games(rng)
    prov_names = [p for p, _ in PROVIDERS]
    prov_w = [w for _, w in PROVIDERS]
    planted = Planted()

    activity_rows: list[list] = []
    game_rows: list[list] = []
    payments: list[list] = []
    clients: list[list] = []
    tx = 0

    def add_payment(pid: str, when: date, kind: str, amount: float, status: str | None = None) -> None:
        nonlocal tx
        tx += 1
        if status is None:
            r = rng.random()
            status = "aprovado" if r < 0.93 else ("recusado" if r < 0.97 else "pendente")
        # Brazilian export: ; delimiter, dd/mm/yyyy, comma decimal
        payments.append([f"TX{tx:07d}", when.strftime("%d/%m/%Y"), pid, kind,
                         f"{amount:.2f}".replace(".", ","), status])

    def play_row(pid: str, day: date, prov: str, btag: str, n_bets: int, avg_bet: float,
                 edge_override: float | None = None, vol: float = 6.0) -> tuple[float, float]:
        """Create one activity row (+ its game rows). Returns (turnover, ggr)."""
        chosen = rng.sample(games[prov], k=rng.randint(1, 2))
        split = [rng.random() + 0.2 for _ in chosen]
        tot = sum(split)
        row_t, row_g, row_b, tj = 0.0, 0.0, 0, {}
        for (gname, edge), w in zip(chosen, split, strict=True):
            nb = max(1, int(round(n_bets * w / tot)))
            t = round(nb * avg_bet * rng.uniform(0.9, 1.1), 2)
            e = edge if edge_override is None else edge_override
            noise = rng.gauss(0, avg_bet * math.sqrt(nb) * vol)
            g = round(min(t * e + noise, t), 2)
            row_t += t
            row_g += g
            row_b += nb
            tj[gname] = {"turnover": t, "ggr": g, "bets": nb}
            game_rows.append([day.isoformat(), pid, prov, gname, f"{t:.2f}", f"{g:.2f}", nb])
        row_t, row_g = round(row_t, 2), round(row_g, 2)
        activity_rows.append([day.isoformat(), pid, prov, btag, f"{row_t:.2f}", f"{row_g:.2f}", row_b,
                              json.dumps(tj, ensure_ascii=False, sort_keys=True)])
        return row_t, row_g

    def new_player(idx: int) -> tuple[str, str, date]:
        pid = f"USR{100000 + idx}"
        btag = rng.choice(BTAGS) if rng.random() < 0.7 else ""
        signup = start + timedelta(days=rng.randint(-120, days - 1))
        clients.append([pid, signup.isoformat(), rng.choices(["aprovado", "pendente", "reprovado"], [0.8, 0.15, 0.05])[0],
                        btag])
        return pid, btag, signup

    idx = 0
    end_day = start + timedelta(days=days - 1)
    # ---------------- normal population WITH history and churn (behavior demo)
    for _ in range(players if history_days > 0 else 0):
        pid, btag, signup = new_player(idx)
        idx += 1
        first_day = max(start - timedelta(days=history_days), signup)
        avail = (end_day - first_day).days + 1
        if avail <= 0:
            continue
        active_len = min(avail, max(1, int(rng.expovariate(1 / 50))))  # days until the player churns
        n_days = min(active_len, max(1, int(rng.expovariate(1 / 6) * max(1.0, active_len / 31))))
        play_days = sorted(rng.sample(range(active_len), n_days))
        avg_bet = math.exp(rng.gauss(math.log(2.0), 0.8))
        fav = rng.choices(prov_names, prov_w, k=rng.randint(1, 3))
        total_t = total_g = 0.0
        for d in play_days:
            day = first_day + timedelta(days=d)
            for prov in sorted(set(rng.sample(fav, k=rng.randint(1, len(fav))))):
                t, g = play_row(pid, day, prov, btag, rng.randint(20, 300), avg_bet)
                total_t += t
                total_g += g
        dep_total = max(20.0, total_t * rng.uniform(0.08, 0.2))
        dep_days = sorted(rng.sample(play_days, min(len(play_days), rng.randint(1, 6))))
        for d in dep_days:
            add_payment(pid, first_day + timedelta(days=d), "deposito", round(dep_total / len(dep_days), 2))
        if total_g < 0 and rng.random() < 0.8:
            add_payment(pid, first_day + timedelta(days=play_days[-1]), "saque", round(-total_g * 0.8, 2))

    # ---------------- normal population (period only: original detection dataset)
    for _ in range(players if history_days == 0 else 0):
        pid, btag, signup = new_player(idx)
        idx += 1
        first_day = max(start, signup)
        avail = (start + timedelta(days=days - 1) - first_day).days + 1
        if avail <= 0:
            continue
        n_days = min(avail, max(1, int(rng.expovariate(1 / 6))))
        play_days = sorted(rng.sample(range(avail), n_days))
        avg_bet = math.exp(rng.gauss(math.log(2.0), 0.8))
        fav = rng.choices(prov_names, prov_w, k=rng.randint(1, 3))
        total_t = 0.0
        total_g = 0.0
        for d in play_days:
            day = first_day + timedelta(days=d)
            for prov in sorted(set(rng.sample(fav, k=rng.randint(1, len(fav))))):  # sorted: set order varies per process
                t, g = play_row(pid, day, prov, btag, rng.randint(20, 300), avg_bet)
                total_t += t
                total_g += g
        # deposits roughly fund the play
        dep_total = max(20.0, total_t * rng.uniform(0.08, 0.2))
        n_dep = rng.randint(1, 4)
        for k in range(n_dep):
            add_payment(pid, first_day + timedelta(days=play_days[min(k, len(play_days) - 1)]), "deposito",
                        round(dep_total / n_dep, 2))
        if total_g < 0 and rng.random() < 0.8:  # winners cash out (late, not fast)
            add_payment(pid, first_day + timedelta(days=play_days[-1]), "saque", round(-total_g * 0.8, 2))

    # outside-period noise (April) -> must be ignored, counted in R7
    for pid_idx in (rng.sample(range(players), 40) if history_days == 0 else []):  # distinct players -> no key collisions
        pid = f"USR{100000 + pid_idx}"
        play_row(pid, start - timedelta(days=rng.randint(1, 20)), rng.choice(prov_names), "", 50, 2.0)

    # ---------------- planted: bonus abusers (mostly from ABUSE_BTAG)
    for k in range(24):
        pid, btag, _ = new_player(idx)
        idx += 1
        btag = ABUSE_BTAG if k < 18 else rng.choice(BTAGS)
        clients[-1][3] = btag
        planted.bonus_abusers.append(pid)
        day0 = start + timedelta(days=rng.randint(0, days - 3))
        for d in range(rng.randint(1, 2)):
            for prov in rng.sample(prov_names[:4], 2):
                play_row(pid, day0 + timedelta(days=d), prov, btag, rng.randint(2500, 4000), rng.uniform(1.5, 3.0),
                         edge_override=0.002, vol=0.05)
        add_payment(pid, day0, "deposito", 200.0, "aprovado")
        add_payment(pid, day0 + timedelta(days=1), "saque", 230.0, "aprovado")

    # ---------------- planted: big winners
    for _ in range(6):
        pid, btag, _ = new_player(idx)
        idx += 1
        planted.big_winners.append(pid)
        for d in rng.sample(range(days), 6):
            play_row(pid, start + timedelta(days=d), rng.choice(prov_names), btag, rng.randint(300, 500),
                     rng.uniform(8, 15), edge_override=-0.45, vol=0.3)
        add_payment(pid, start + timedelta(days=2), "deposito", 3000.0, "aprovado")
        add_payment(pid, start + timedelta(days=days - 2), "saque", 15000.0, "aprovado")

    # ---------------- planted: deposit -> withdraw with almost no play (AML)
    for _ in range(10):
        pid, btag, _ = new_player(idx)
        idx += 1
        planted.cashout_no_play.append(pid)
        day0 = start + timedelta(days=rng.randint(0, days - 2))
        dep = round(rng.uniform(1000, 3000), 2)
        play_row(pid, day0, rng.choice(prov_names), btag, rng.randint(10, 30), rng.uniform(2, 5))
        add_payment(pid, day0, "deposito", dep, "aprovado")
        add_payment(pid, day0 + timedelta(days=1), "saque", round(dep * 0.95, 2), "aprovado")

    # ---------------- planted: whales (bet size outliers, normal hold)
    for _ in range(3):
        pid, btag, _ = new_player(idx)
        idx += 1
        planted.whales.append(pid)
        for d in rng.sample(range(days), 8):
            play_row(pid, start + timedelta(days=d), rng.choice(prov_names[:3]), btag, rng.randint(150, 250),
                     rng.uniform(400, 600), vol=0.5)
        add_payment(pid, start, "deposito", 50000.0, "aprovado")

    # ---------------- signups that never deposited (separate RNG: does not perturb the data above)
    rng2 = random.Random(seed + 1)
    for k in range(non_depositors):
        pid = f"USR{100000 + idx}"
        idx += 1
        signup = end_day - timedelta(days=rng2.randint(0, 45))
        clients.append([pid, signup.isoformat(), rng2.choices(["aprovado", "pendente"], [0.6, 0.4])[0],
                        rng2.choice(BTAGS) if rng2.random() < 0.7 else ""])
        if k % 20 == 0:  # a few deposit but never play
            tx += 1
            payments.append([f"TX{tx:07d}", signup.strftime("%d/%m/%Y"), pid, "deposito", "50,00", "aprovado"])

    _write(out / "activity.csv", ["dia", "player_id", "provider_name", "btag", "turnover", "ggr", "total_apostas", "top_jogos"],
           activity_rows, ",")
    _write(out / "games.csv", ["dia", "player_id", "provider_name", "game_name", "turnover", "ggr", "total_apostas"],
           game_rows, ",")
    _write(out / "payments.csv", ["id_transacao", "data_pagamento", "id_jogador", "tipo", "valor", "situacao"],
           payments, ";")
    _write(out / "clients.csv", ["player_id", "data_cadastro", "kyc", "afiliado"], clients, ",")
    (out / "PLANTED_ANOMALIES.json").write_text(json.dumps(planted.__dict__, indent=2), encoding="utf-8")
    return planted


def _write(path: Path, header: list[str], rows: list[list], delimiter: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        w = csv.writer(handle, delimiter=delimiter)
        w.writerow(header)
        w.writerows(rows)


_DEMO_HEADER = """\
study:
  title: "Estudo Hipotético — Operação Demo — Maio 2026"
  subtitle: "Dados sintéticos com anomalias plantadas · validação do motor"
  author: "Sentinela demo"
  period:
    start: 2026-05-01
    end: 2026-05-31
  currency: BRL

"""
_DEMO_FOOTER = """
sections: [executive, behavior, providers, players, affiliates, games, payments, clients, data_quality]
on_contract_error: fail
output:
  dir: ../outputs
  formats: [html, pdf, json, csv]
"""


def demo_study_text(labels: dict[str, str] | None = None, data: str | None = None) -> str:
    """Study for the demo. labels -> inputs from the encrypted vault (production path);
    data -> plaintext CSV paths with security.plaintext_* enabled (test-suite only)."""
    if labels:
        inputs = "inputs:\n" + "".join(f"  {ds}: {{vault: {lbl}}}\n" for ds, lbl in labels.items())
        security = "security:\n  home: ..\n"
    else:
        d = data or "../data/demo"
        inputs = (f"inputs:\n  activity:\n    path: {d}/activity.csv\n  games:\n    path: {d}/games.csv\n"
                  f"  payments:\n    path: {d}/payments.csv\n  clients:\n    path: {d}/clients.csv\n")
        security = "security:\n  home: ..\n  plaintext_inputs: true\n  plaintext_outputs: true\n"
    return _DEMO_HEADER + inputs + "\n" + security + _DEMO_FOOTER
