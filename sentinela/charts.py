"""Tiny dependency-free SVG charts (inline in the HTML, work offline and in PDF)."""
from __future__ import annotations

from html import escape
from typing import Any

POS = "#0f766e"
NEG = "#dc2626"
MUTED = "#94a3b8"
INK = "#0f172a"


def daily_bars(daily: list[dict[str, Any]], key: str = "ggr", width: int = 760, height: int = 200) -> str:
    if not daily:
        return ""
    values = [float(d[key] or 0) for d in daily]
    vmax = max(max(values), 0.0)
    vmin = min(min(values), 0.0)
    span = (vmax - vmin) or 1.0
    pad_l, pad_b, pad_t = 8, 22, 10
    plot_h = height - pad_b - pad_t
    n = len(values)
    bw = (width - pad_l * 2) / n
    zero_y = pad_t + plot_h * (vmax / span)
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="{escape(key)} diário">']
    for i, (d, v) in enumerate(zip(daily, values, strict=True)):
        h = plot_h * abs(v) / span
        x = pad_l + i * bw + bw * 0.12
        y = zero_y - h if v >= 0 else zero_y
        color = POS if v >= 0 else NEG
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw * 0.76:.1f}" height="{max(h, 0.5):.1f}" fill="{color}">'
                     f'<title>{escape(str(d["dia"]))}: {v:,.2f}</title></rect>')
    parts.append(f'<line x1="{pad_l}" x2="{width - pad_l}" y1="{zero_y:.1f}" y2="{zero_y:.1f}" stroke="{MUTED}" stroke-width="1"/>')
    for idx in sorted({0, n // 2, n - 1}):
        x = pad_l + idx * bw + bw / 2
        anchor = "start" if idx == 0 else ("end" if idx == n - 1 and n > 1 else "middle")
        if anchor == "start":
            x = pad_l
        elif anchor == "end":
            x = width - pad_l
        parts.append(f'<text x="{x:.1f}" y="{height - 6}" font-size="10" text-anchor="{anchor}" fill="{INK}">'
                     f'{escape(str(daily[idx]["dia"]))}</text>')
    parts.append("</svg>")
    return "".join(parts)


def hbars(items: list[tuple[str, float, str]], width: int = 760, bar_h: int = 18, label_w: int = 200) -> str:
    """items = [(label, value, display_text)]"""
    if not items:
        return ""
    vmax = max((abs(v) for _, v, _ in items), default=1.0) or 1.0
    height = len(items) * (bar_h + 6) + 6
    plot_w = width - label_w - 110
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img">']
    for i, (label, value, text) in enumerate(items):
        y = 4 + i * (bar_h + 6)
        w = plot_w * abs(value) / vmax
        color = POS if value >= 0 else NEG
        parts.append(f'<text x="{label_w - 8}" y="{y + bar_h * 0.72:.1f}" font-size="11" text-anchor="end" fill="{INK}">'
                     f'{escape(label[:32])}</text>')
        parts.append(f'<rect x="{label_w}" y="{y}" width="{max(w, 0.5):.1f}" height="{bar_h}" rx="3" fill="{color}"/>')
        parts.append(f'<text x="{label_w + w + 6:.1f}" y="{y + bar_h * 0.72:.1f}" font-size="11" fill="{INK}">{escape(text)}</text>')
    parts.append("</svg>")
    return "".join(parts)
