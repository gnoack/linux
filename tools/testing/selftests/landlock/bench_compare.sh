#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Compare Landlock micro-benchmarks between two kernel bzImages.
#
# Builds fs_bench / net_bench / scoped_bench from the current selftests
# tree, bundles them into a copy of the initramfs-base.cpio shared with
# ,kselftests, and boots that initramfs in QEMU once per kernel.  The
# benches sweep baseline + 1, 2, 4, 8 layers on their own when invoked
# without arguments by rcS, so one boot per kernel produces the full
# data set.
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
  -h            this help
EOF
}

while getopts "hA:B:a:b:o:" opt; do
    case "$opt" in
        A) KERNEL_A="$OPTARG" ;;
        B) KERNEL_B="$OPTARG" ;;
        a) LABEL_A="$OPTARG" ;;
        b) LABEL_B="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
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
cp "$BENCH_DIR/fs_bench" "$BENCH_DIR/net_bench" "$BENCH_DIR/scoped_bench" \
    "$WORK/ctests/"

INITRAMFS="$WORK/initramfs"
cp "$INITRAMFS_BASE" "$INITRAMFS"
(cd "$WORK" && find ctests | cpio -H newc -o -A -F "$INITRAMFS" 2>/dev/null)

run_qemu() {
    local kernel="$1"
    local outlog="$2"
    timeout 300 qemu-system-x86_64 \
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
# KEY is e.g. "fs_bench / baseline" or "fs_bench / 4 domains".
parse_log() {
    awk '
        { sub(/\r$/, "") }
        /^\/ctests\// {
            bench=$0
            sub(/^\/ctests\//, "", bench)
            scenario=""
            sys=""; usr=""
            next
        }
        /^\*\*\* Benchmark \*\*\*$/ { scenario="?"; sys=""; usr=""; next }
        /Landlock domain/ {
            # "... N Landlock domain(s)"
            for (i=1; i<=NF; i++)
                if ($i ~ /^[0-9]+$/ && $(i+1) ~ /^Landlock/) {
                    scenario = $i " domains"
                    break
                }
            next
        }
        /without Landlock/ { scenario="baseline"; next }
        /^System:/ { sys=$2 }
        /^User/ { usr=$3 }
        /^\*\*\* Benchmark concluded/ {
            if (bench != "" && scenario != "")
                print bench " / " scenario "\t" sys "\t" usr
            scenario=""
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

if [[ -n "$OUTPUT" ]]; then
    emit_report >"$OUTPUT"
    echo "# Report written to $OUTPUT" >&2
else
    emit_report
fi
