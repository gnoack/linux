#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Render fs_bench results from bench_compare.sh into four GNUplot SVG
charts (one per directory depth) and emit an HTML snippet that lays
them out in a responsive 2x2 grid.

Inputs:
    --data-a / --data-b
        TSV files produced by bench_compare.sh (KEY\\tSYS\\tUSR per row).
        Only fs_bench rows of the form
            "fs_bench / depth=<D>, <K> domains"
        are used (baseline rows are ignored — the chart's x-axis is the
        domain count).
    --label-a / --label-b
        Legend labels (e.g. "before refactor" / "after refactor").

Output:
    HTML snippet on stdout.  Each <svg> is inlined; a single <div>
    wraps them in a CSS grid that becomes a single column on narrow
    viewports.

Requires `gnuplot` on $PATH.

Copyright (C) 2026 Google LLC
"""

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

DEPTHS = (10, 100, 1000, 10000)
LAYERS = (1, 2, 4, 8, 16)

ROW_RE = re.compile(r"^fs_bench / depth=(\d+), (\d+) domains$")


def load(path: Path) -> dict[int, dict[int, int]]:
    """Returns {depth: {layers: sys_clocks}}."""
    out: dict[int, dict[int, int]] = defaultdict(dict)
    with path.open() as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            m = ROW_RE.match(parts[0])
            if not m:
                continue
            depth = int(m.group(1))
            layers = int(m.group(2))
            try:
                sys_clocks = int(parts[1])
            except ValueError:
                continue
            out[depth][layers] = sys_clocks
    return out


def render_svg(depth: int,
               a: dict[int, int], b: dict[int, int],
               label_a: str, label_b: str) -> str:
    """Returns the SVG document for one depth as a string."""
    rows_a = "\n".join(f"{x} {a[x]}" for x in LAYERS if x in a)
    rows_b = "\n".join(f"{x} {b[x]}" for x in LAYERS if x in b)

    script = f"""
set terminal svg size 480,320 enhanced font 'system-ui,12'
set title "fs_bench, depth = {depth}" noenhanced
set xlabel "Landlock layers"
set ylabel "System clocks"
set logscale x 2
set xtics ({", ".join(str(x) for x in LAYERS)})
set yrange [0:*]
set grid ytics lc rgb "#dddddd"
set key top left
set border 3
set tics nomirror
plot \\
    '-' using 1:2 with linespoints pt 7 ps 0.8 lc rgb '#3b82f6' lw 2 title "{label_a}", \\
    '-' using 1:2 with linespoints pt 7 ps 0.8 lc rgb '#ef4444' lw 2 title "{label_b}"
{rows_a}
e
{rows_b}
e
"""
    res = subprocess.run(
        ["gnuplot"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-a", required=True, type=Path)
    ap.add_argument("--data-b", required=True, type=Path)
    ap.add_argument("--label-a", default="before")
    ap.add_argument("--label-b", default="after")
    args = ap.parse_args()

    a = load(args.data_a)
    b = load(args.data_b)

    svgs = []
    for d in DEPTHS:
        if d not in a or d not in b:
            print(f"warning: missing data for depth={d}", file=sys.stderr)
            continue
        svg = render_svg(d, a[d], b[d], args.label_a, args.label_b)
        # Strip the XML prologue / DOCTYPE so the <svg> can sit
        # directly inside the surrounding HTML.
        svg = re.sub(r"^<\?xml[^>]*\?>\s*", "", svg)
        svg = re.sub(r"<!DOCTYPE[^>]*>\s*", "", svg)
        svgs.append(svg)

    print('<div style="'
          'display: grid; '
          'grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); '
          'gap: 1em; '
          'max-width: 1000px;'
          '">')
    for svg in svgs:
        print('  <div>')
        print(svg)
        print('  </div>')
    print('</div>')
    return 0


if __name__ == "__main__":
    sys.exit(main())
