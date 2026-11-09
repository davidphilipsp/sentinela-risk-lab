"""Shared test helpers."""
from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

from sentinela.study import load_study


class TmpProject:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "data").mkdir()
        (self.root / "studies").mkdir()
        from sentinela.security import unlock
        unlock(self.root, create_if_missing=True)

    def write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return path

    def study(self, inputs: str, start: str = "2026-05-01", end: str = "2026-05-31",
              extra: str = "", sections: str = "") -> object:
        body = f"""
study:
  title: "Teste"
  period: {{start: {start}, end: {end}}}
inputs:
{textwrap.indent(textwrap.dedent(inputs).strip(), '  ')}
{sections}
security:
  home: ..
  plaintext_inputs: true
  plaintext_outputs: true
output:
  dir: ../outputs
  formats: [html, json, csv]
{extra}
"""
        path = self.root / "studies" / "s.yaml"
        path.write_text(body, encoding="utf-8")
        return load_study(path)

    def cleanup(self) -> None:
        self._tmp.cleanup()
