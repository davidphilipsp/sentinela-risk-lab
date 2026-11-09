#!/usr/bin/env bash
# Rebuild ./wheelhouse on a machine WITH internet, for a target Linux platform.
# Then copy the whole project (with wheelhouse/) to the offline machine.
#
#   scripts/build-wheelhouse.sh                 # x86_64, Python 3.10 / 3.12 / 3.13 / 3.14
#   ARCH=aarch64 scripts/build-wheelhouse.sh    # ARM64 (e.g. Ubuntu on Raspberry Pi / Ampere / Apple VM)
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-x86_64}"
PYTHONS="${PYTHONS:-3.10 3.12 3.13 3.14}"
PLAT=(--platform "manylinux_2_28_$ARCH" --platform "manylinux_2_27_$ARCH" --platform "manylinux_2_17_$ARCH" --platform "manylinux2014_$ARCH")
rm -rf wheelhouse && mkdir wheelhouse
for PY in $PYTHONS; do
  # pip download evaluates environment markers against the HOST Python, so dependencies that only
  # older targets need (typing-extensions for cryptography on < 3.11) are listed explicitly.
  EXTRA=""
  if [[ "$PY" == "3.10" || "$PY" == "3.11" ]]; then DUCK="duckdb==1.5.6"; EXTRA="typing-extensions>=4.13.2"; else DUCK="duckdb==2.0.0"; fi
  python3 -m pip download -q "$DUCK" $EXTRA jinja2==3.1.6 markupsafe==3.0.4 pyyaml==6.0.3 cryptography==50.0.2 weasyprint==70.0 \
    -d wheelhouse --only-binary=:all: --python-version "$PY" --implementation cp "${PLAT[@]}"
  echo "  ✓ Python $PY ($ARCH)"
done
python3 -m pip download -q pip setuptools wheel -d wheelhouse --only-binary=:all:
echo "wheelhouse: $(ls wheelhouse | wc -l) wheels, $(du -sh wheelhouse | cut -f1)"
# verify offline resolution for every target (requires uv; skip silently if absent)
if command -v uv >/dev/null; then
  for PY in $PYTHONS; do
    uv pip compile requirements-pdf.txt --no-index --find-links wheelhouse --python-version "$PY" \
      --python-platform "${ARCH}-manylinux_2_28" --only-binary :all: -q >/dev/null && echo "  ✓ offline resolve $PY"
  done
fi
