#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Compare Landlock micro-benchmarks between two kernel bzImages.
#
# Builds fs_bench / net_bench / scoped_bench from the current selftests
# tree, bundles them into a copy of the initramfs-base.cpio shared with
# ,kselftests, and boots that initramfs in QEMU once per kernel.
#
# The bench binaries are shipped under *.bin names and a small wrapper
# shell script (named like the bench so rcS picks it up via the
# `_bench$` glob) drives the desired sweep:
#   fs_bench     baseline + 1,2,4,8,16 layers, at depths 10/100/1000/10000
#   net_bench    baseline + 1,2,4,8,16 layers
#   scoped_bench baseline + 1,2,4,8,16 layers
# The wrapper also echoes its own /ctests/<name> path so the log parser
# can attribute scenarios to a bench.
#
# Usage:
#   bench_compare.sh -A bzImage-A -B bzImage-B [-a label-A] [-b label-B] \
#                    [-o report.md]
#
# Environment:
#   INITRAMFS_BASE  cpio archive used as the base rootfs.  Defaults to
#                   $HOME/git/qemu-go-tests/initramfs-base.cpio (same as
#                   ,kselftests).
#   KBUILD_OUTPUT   kernel build output directory (for selftests build).
#
# Copyright (C) 2026 Google LLC

set -euo pipefail

OUTPUT=""
HTML_OUTPUT=""
LABEL_A=""
LABEL_B=""
KERNEL_A=""
KERNEL_B=""

usage() {
    cat <<EOF
Usage: $0 -A bzImage-A -B bzImage-B [OPTIONS]

Options:
  -A PATH       bzImage of kernel A (required)
  -B PATH       bzImage of kernel B (required)
  -a LABEL      short label for kernel A (default: basename of -A)
  -b LABEL      short label for kernel B (default: basename of -B)
  -o FILE       write markdown report to FILE (default: stdout)
  -H FILE       also write a self-contained HTML chart report to FILE
  -h            this help
EOF
}

while getopts "hA:B:a:b:o:H:" opt; do
    case "$opt" in
        A) KERNEL_A="$OPTARG" ;;
        B) KERNEL_B="$OPTARG" ;;
        a) LABEL_A="$OPTARG" ;;
        b) LABEL_B="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        H) HTML_OUTPUT="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[[ -n "$KERNEL_A" && -n "$KERNEL_B" ]] || { usage >&2; exit 2; }
[[ -f "$KERNEL_A" ]] || { echo "error: $KERNEL_A not found" >&2; exit 1; }
[[ -f "$KERNEL_B" ]] || { echo "error: $KERNEL_B not found" >&2; exit 1; }

LABEL_A="${LABEL_A:-$(basename "$KERNEL_A")}"
LABEL_B="${LABEL_B:-$(basename "$KERNEL_B")}"

INITRAMFS_BASE="${INITRAMFS_BASE:-$HOME/git/qemu-go-tests/initramfs-base.cpio}"
[[ -f "$INITRAMFS_BASE" ]] || {
    echo "error: INITRAMFS_BASE $INITRAMFS_BASE not found" >&2; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
KBUILD_OUTPUT="${KBUILD_OUTPUT:-$KERNEL_DIR}"
export KBUILD_OUTPUT

WORK="$(mktemp -d -t landlock-bench-XXXXXX)"
if [[ -n "${KEEP_WORK:-}" ]]; then
    trap 'echo "# kept WORK dir: $WORK" >&2' EXIT
else
    trap 'rm -rf "$WORK"' EXIT
fi

echo "# Building bench programs..." >&2
make -s -C "$KERNEL_DIR/tools/testing/selftests/landlock" \
    fs_bench net_bench scoped_bench >/dev/null

BENCH_DIR="$KBUILD_OUTPUT/kselftest/landlock"
for b in fs_bench net_bench scoped_bench; do
    [[ -x "$BENCH_DIR/$b" ]] || { echo "error: missing $BENCH_DIR/$b" >&2; exit 1; }
done

mkdir "$WORK/ctests"
# Real bench binaries — renamed to *.bin so the rcS `_bench$` glob does
# not pick them up directly; the wrapper scripts below invoke them with
# our chosen sweep.
cp "$BENCH_DIR/fs_bench"     "$WORK/ctests/fs_bench.bin"
cp "$BENCH_DIR/net_bench"    "$WORK/ctests/net_bench.bin"
cp "$BENCH_DIR/scoped_bench" "$WORK/ctests/scoped_bench.bin"

cat >"$WORK/ctests/fs_bench" <<'EOF'
#!/bin/sh
echo /ctests/fs_bench
for d in 10 100 1000 10000; do
    /ctests/fs_bench.bin -L -d "$d" -l 1,2,4,8,16
done
EOF
cat >"$WORK/ctests/net_bench" <<'EOF'
#!/bin/sh
echo /ctests/net_bench
/ctests/net_bench.bin -L -l 1,2,4,8,16
EOF
cat >"$WORK/ctests/scoped_bench" <<'EOF'
#!/bin/sh
echo /ctests/scoped_bench
/ctests/scoped_bench.bin -L -l 1,2,4,8,16
EOF
chmod +x "$WORK/ctests/fs_bench" "$WORK/ctests/net_bench" \
    "$WORK/ctests/scoped_bench"

INITRAMFS="$WORK/initramfs"
cp "$INITRAMFS_BASE" "$INITRAMFS"
(cd "$WORK" && find ctests | cpio -H newc -o -A -F "$INITRAMFS" 2>/dev/null)

run_qemu() {
    local kernel="$1"
    local outlog="$2"
    timeout 3000 qemu-system-x86_64 \
        -nographic \
        -smp 2 \
        -m 2G \
        -enable-kvm \
        -append "console=ttyS0 lsm=landlock no_hash_pointers quiet" \
        -kernel "$kernel" \
        -initrd "$INITRAMFS" \
        </dev/null >"$outlog" 2>&1
}

# Parse a serial log into TSV rows: "KEY<TAB>SYS<TAB>USER".
# KEY is e.g. "fs_bench / depth=100, baseline" or
# "net_bench / 4 domains".  fs_bench's leading "<D> dirs, ..." info
# line carries the directory depth; net_bench / scoped_bench omit it.
parse_log() {
    awk '
        { sub(/\r$/, "") }
        /^\/ctests\// {
            bench=$0
            sub(/^\/ctests\//, "", bench)
            scenario=""; depth=""
            sys=""; usr=""
            next
        }
        /^\*\*\* Benchmark \*\*\*$/ {
            scenario=""; depth=""; sys=""; usr=""; next
        }
        # The fs_bench info line has the form:
        #   "<D> dirs, <N> iterations, [without Landlock|<K> Landlock domain(s)]"
        # so capture the depth here but fall through to the rules
        # below that classify the scenario.
        /^[0-9]+ dirs,/ { depth=$1 }
        /Landlock domain/ {
            # "... N Landlock domain(s)"
            for (i=1; i<=NF; i++)
                if ($i ~ /^[0-9]+$/ && $(i+1) ~ /^Landlock/) {
                    scenario = $i " domains"
                    break
                }
            if (depth != "")
                scenario = "depth=" depth ", " scenario
            next
        }
        /without Landlock/ {
            scenario = "baseline"
            if (depth != "")
                scenario = "depth=" depth ", " scenario
            next
        }
        /^System:/ { sys=$2 }
        /^User/ { usr=$3 }
        # The bench prints "*** Benchmark concluded ***" before the
        # System/User lines, so trigger on the trailing "Clocks per
        # second:" line which is the final line of each scenario.
        /^Clocks per second:/ {
            if (bench != "" && scenario != "" && sys != "")
                print bench " / " scenario "\t" sys "\t" usr
            scenario=""; depth=""; sys=""; usr=""
        }
    '
}

LOG_A="$WORK/log-A.txt"
LOG_B="$WORK/log-B.txt"

echo "# Running kernel A ($LABEL_A)..." >&2
run_qemu "$KERNEL_A" "$LOG_A"
echo "# Running kernel B ($LABEL_B)..." >&2
run_qemu "$KERNEL_B" "$LOG_B"

DATA_A="$WORK/data-A.tsv"
DATA_B="$WORK/data-B.tsv"
parse_log <"$LOG_A" >"$DATA_A"
parse_log <"$LOG_B" >"$DATA_B"

if [[ ! -s "$DATA_A" || ! -s "$DATA_B" ]]; then
    echo "error: no benchmark results parsed" >&2
    echo "--- tail of log A ---" >&2; tail -40 "$LOG_A" >&2
    echo "--- tail of log B ---" >&2; tail -40 "$LOG_B" >&2
    exit 1
fi

emit_report() {
    echo "# Landlock benchmark comparison"
    echo
    echo "- Kernel A: **$LABEL_A** (\`$KERNEL_A\`)"
    echo "- Kernel B: **$LABEL_B** (\`$KERNEL_B\`)"
    echo
    echo "Values are \"System\" clock ticks from times(2) (smaller = faster)."
    echo
    echo "| Scenario | $LABEL_A | $LABEL_B | Δ (B − A) | B/A |"
    echo "|---|---:|---:|---:|---:|"
    join -t $'\t' -1 1 -2 1 <(sort "$DATA_A") <(sort "$DATA_B") |
    while IFS=$'\t' read -r key sa _ua sb _ub; do
        if [[ "$sa" =~ ^[0-9]+$ && "$sb" =~ ^[0-9]+$ && "$sa" -gt 0 ]]; then
            delta=$((sb - sa))
            ratio=$(awk -v a="$sa" -v b="$sb" 'BEGIN{printf "%.3f", b/a}')
        else
            delta=""
            ratio=""
        fi
        printf "| %s | %s | %s | %s | %s |\n" "$key" "$sa" "$sb" "$delta" "$ratio"
    done
}

# Emit a self-contained HTML page with one grouped bar chart per bench
# program.  Reads the same joined TSV data as the markdown report.
emit_html() {
    # Build a python-ready JSON blob from the joined data, then render.
    local joined="$WORK/joined.tsv"
    join -t $'\t' -1 1 -2 1 <(sort "$DATA_A") <(sort "$DATA_B") >"$joined"

    python3 - "$joined" "$LABEL_A" "$LABEL_B" "$KERNEL_A" "$KERNEL_B" <<'PY'
import json, sys, html, re
path, label_a, label_b, kernel_a, kernel_b = sys.argv[1:6]

# Preserve a natural scenario ordering: group by depth (if any), then
# baseline first, then increasing domain count.
def scen_key(s):
    m = re.match(r"depth=(\d+), (.*)", s)
    if m:
        depth = int(m.group(1))
        rest = m.group(2)
        if rest == "baseline":
            return (1, depth, 0, 0)
        m2 = re.match(r"(\d+) domains", rest)
        if m2:
            return (1, depth, 1, int(m2.group(1)))
        return (1, depth, 2, 0)
    if s == "baseline":
        return (0, 0, 0, 0)
    m = re.match(r"(\d+) domains", s)
    if m:
        return (0, 0, 1, int(m.group(1)))
    return (2, 0, 0, 0)

charts = {}  # bench -> {scenario: (sa, sb)}
with open(path) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        key, sa, _ua, sb, _ub = parts[0], parts[1], parts[2], parts[3], parts[4]
        if " / " not in key:
            continue
        bench, scenario = key.split(" / ", 1)
        try:
            sa_i = int(sa); sb_i = int(sb)
        except ValueError:
            continue
        charts.setdefault(bench, {})[scenario] = (sa_i, sb_i)

datasets = []
for bench in sorted(charts):
    scenarios = sorted(charts[bench], key=scen_key)
    datasets.append({
        "bench": bench,
        "labels": scenarios,
        "a": [charts[bench][s][0] for s in scenarios],
        "b": [charts[bench][s][1] for s in scenarios],
    })

tmpl = """<!doctype html>
<html><head><meta charset="utf-8">
<title>Landlock benchmark comparison</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; }
h1 { margin-bottom: 0.2em; }
.meta { color: #555; margin-bottom: 2em; }
.chart-wrap { margin: 2em 0; }
canvas { max-width: 100%; }
code { background: #f4f4f4; padding: 1px 4px; border-radius: 3px; }
</style>
</head><body>
<h1>Landlock benchmark comparison</h1>
<p class="meta">
  <strong>__LABEL_A__</strong>: <code>__KERNEL_A__</code><br>
  <strong>__LABEL_B__</strong>: <code>__KERNEL_B__</code><br>
  Y axis: &ldquo;System&rdquo; clock ticks from <code>times(2)</code> (smaller is faster).
</p>
__CANVASES__
<script>
const data = __DATA__;
for (const d of data) {
  const ctx = document.getElementById("c_" + d.bench);
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: d.labels,
      datasets: [
        { label: __JSON_LABEL_A__, data: d.a, backgroundColor: "#3b82f6" },
        { label: __JSON_LABEL_B__, data: d.b, backgroundColor: "#ef4444" },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: d.bench, font: { size: 16 } },
        legend: { position: "top" },
      },
      scales: { y: { beginAtZero: true, title: { display: true, text: "System clocks" } } },
    },
  });
}
</script>
</body></html>
"""

canvases = "\n".join(
    f'<div class="chart-wrap"><canvas id="c_{html.escape(d["bench"])}" height="120"></canvas></div>'
    for d in datasets
)

out = (tmpl
       .replace("__LABEL_A__", html.escape(label_a))
       .replace("__LABEL_B__", html.escape(label_b))
       .replace("__KERNEL_A__", html.escape(kernel_a))
       .replace("__KERNEL_B__", html.escape(kernel_b))
       .replace("__CANVASES__", canvases)
       .replace("__DATA__", json.dumps(datasets))
       .replace("__JSON_LABEL_A__", json.dumps(label_a))
       .replace("__JSON_LABEL_B__", json.dumps(label_b)))
sys.stdout.write(out)
PY
}

if [[ -n "$OUTPUT" ]]; then
    emit_report >"$OUTPUT"
    echo "# Report written to $OUTPUT" >&2
else
    emit_report
fi

if [[ -n "$HTML_OUTPUT" ]]; then
    emit_html >"$HTML_OUTPUT"
    echo "# HTML report written to $HTML_OUTPUT" >&2
fi
