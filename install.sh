#!/usr/bin/env bash
# =============================================================================
# Sentinela Risk Lab — installer (Ubuntu 22.04 / 24.04 / 25.x / 26.04, x86_64)
#
#   ./install.sh              offline install from ./wheelhouse (default)
#   ./install.sh --no-pdf     skip WeasyPrint (HTML/JSON/CSV only)
#   ./install.sh --online     install from PyPI instead of ./wheelhouse
#   ./install.sh --no-tests   skip the self-test at the end
#
# Idempotent: safe to run again. Creates ./.venv and never touches system Python.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
WHEELHOUSE="${SENTINELA_WHEELHOUSE:-$ROOT/wheelhouse}"
PDF=1; ONLINE=0; TESTS=1
for arg in "$@"; do
  case "$arg" in
    --no-pdf) PDF=0 ;;
    --online) ONLINE=1 ;;
    --no-tests) TESTS=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Opção desconhecida: $arg"; exit 1 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !\033[0m %s\n' "$*"; }
die()  { printf '\033[31m  ✗ %s\033[0m\n' "$*"; exit 1; }

# ---------------------------------------------------------------- 1. Python
say "1/6 Verificando Python"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || die "python3 não encontrado. Ubuntu: sudo apt install python3"
PYVER="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python >= 3.10 necessário (encontrado $PYVER)"
ok "Python $PYVER"
ARCH="$(uname -m)"
if [[ "$ONLINE" == 0 && "$ARCH" != "x86_64" ]]; then
  warn "Arquitetura $ARCH: o wheelhouse incluso é x86_64. Use ./install.sh --online ou gere um wheelhouse (scripts/build-wheelhouse.sh)."
fi

# ---------------------------------------------------------------- 2. venv
say "2/6 Criando ambiente isolado (.venv)"
if [[ ! -x .venv/bin/python ]]; then
  if ! "$PY" -m venv .venv 2>/dev/null; then
    # Ubuntu without python3-venv (ensurepip missing): create bare venv and bootstrap pip from the wheel
    warn "python3-venv ausente; criando venv sem pip e instalando pip do wheelhouse"
    rm -rf .venv
    "$PY" -m venv --without-pip .venv || die "Não foi possível criar o venv. Instale: sudo apt install python3-venv"
    PIP_WHL="$(ls "$WHEELHOUSE"/pip-*.whl 2>/dev/null | head -1 || true)"
    [[ -n "$PIP_WHL" ]] || die "pip-*.whl não encontrado em $WHEELHOUSE"
    .venv/bin/python "$PIP_WHL/pip" install -q --no-index --find-links "$WHEELHOUSE" pip
  fi
fi
VPY="$ROOT/.venv/bin/python"
ok "$VPY"

if [[ "$ONLINE" == 1 ]]; then
  PIP_SRC=()
else
  [[ -d "$WHEELHOUSE" ]] || die "wheelhouse não encontrado ($WHEELHOUSE). Use --online."
  PIP_SRC=(--no-index --find-links "$WHEELHOUSE")
fi

# ---------------------------------------------------------------- 3. deps
say "3/6 Instalando dependências $([[ $ONLINE == 1 ]] && echo '(PyPI)' || echo '(offline, wheelhouse)')"
"$VPY" -m pip install -q "${PIP_SRC[@]}" --upgrade pip setuptools wheel
REQ=requirements.txt; [[ "$PDF" == 1 ]] && REQ=requirements-pdf.txt
"$VPY" -m pip install -q "${PIP_SRC[@]}" --only-binary=:all: -r "$REQ"
ok "dependências instaladas ($REQ)"

# ---------------------------------------------------------------- 4. package
say "4/6 Instalando o pacote sentinela (editável: edite sentinela/config/*.yaml à vontade)"
"$VPY" -m pip install -q "${PIP_SRC[@]}" --no-build-isolation --no-deps -e .
ok "$("$ROOT/.venv/bin/sentinela" --version)"

# ---------------------------------------------------------------- 5. PDF libs
say "5/6 Verificando suporte a PDF"
if [[ "$PDF" == 1 ]]; then
  if "$VPY" -c "import weasyprint" >/dev/null 2>&1; then
    ok "WeasyPrint operacional"
  else
    warn "WeasyPrint precisa das bibliotecas do sistema:"
    warn "  sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b"
    warn "Sem elas, o relatório é gerado em HTML/JSON/CSV (ou PDF via Chromium, se instalado)."
  fi
else
  warn "PDF desativado (--no-pdf). HTML/JSON/CSV continuam disponíveis."
fi

# ---------------------------------------------------------------- 6. self-test
say "6/6 Auto-teste"
if [[ "$TESTS" == 1 ]]; then
  "$VPY" -m unittest discover -s tests -t . 2>&1 | tail -3
else
  warn "auto-teste pulado"
fi
chmod 700 "$ROOT/data" "$ROOT/outputs" "$ROOT/vault" "$ROOT/.sentinela" 2>/dev/null || true

cat <<EOF

$(printf '\033[1;32m')Pronto.$(printf '\033[0m') Ative o ambiente:   source .venv/bin/activate

  sentinela init                          # cria o keyring cifrado (frase-senha; sem recuperação)
  sentinela doctor                        # verifica LUKS, swap, tmpfs, rede, rastros
  sentinela demo && sentinela view --open # prova o motor com dados sintéticos
   sentinela ingest ~/Downloads/x.csv --dataset activity   # ÚNICA entrada (espaço inicial = fora do histórico)
  sentinela new-study studies/meu.yaml    # cria um estudo (inputs: {vault: latest})
  sentinela run studies/meu.yaml          # análise em RAM → relatório cifrado no cofre

Manual: README.md · docs/
EOF
