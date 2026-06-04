#!/usr/bin/env bash
# 3-way transfer benchmark: mftp vs scp vs zap (+ mftp --fec on the lossy cell).
#
# Pushes a file to a remote host with each tool, across a matrix of netem latency
# /loss conditions, timing the WALL CLOCK of each run (the fairest cross-tool
# measure — it includes SSH/handshake/process startup). Reports the median of N
# samples per cell. Page cache is dropped on BOTH ends before every run.
#
#   scp      : single TCP stream over SSH
#   zap      : parallel SSH streams (https://github.com/nuttyartist/zap-like tools;
#              tool default — 20 — verified near-optimal for an 8-core receiver)
#   mftp     : default (auto QUIC/TCP, adaptive streams, adaptive zstd)
#   mftp-fec : mftp --fec 8:2 (Reed-Solomon parity) — only on the lossy cell
#
# netem is applied on the remote NIC egress, so a "delay Xms" label is ~one-way
# added latency (RTT ≈ base + X).
#
# Requirements (mirrors tests/bench.sh):
#   - mftp built:           cargo build --release
#   - remote mftp installed: scp target/release/mftp $REMOTE_USER@$REMOTE_HOST:$REMOTE_MFTP
#   - zap on PATH (or set ZAP_BIN)
#   - SSH key auth to the remote
#   - passwordless sudo on the remote for `tc` (netem) AND, on BOTH hosts, for
#     dropping caches (a sudoers rule for `tee /proc/sys/vm/drop_caches`);
#     cache-drop is best-effort and silently skipped if not permitted.
#   - test files staged (incompressible + a small slice for the lossy cell +
#     a compressible log file from tests/gen_logs.py), e.g.:
#       head -c $((1024*1024*1024)) /dev/urandom > /tmp/test_1g_random.bin
#       head -c $((256*1024*1024))  /tmp/test_1g_random.bin > /tmp/test_256m_random.bin
#       python3 tests/gen_logs.py $((1024*1024*1024)) > /tmp/test_1g_logs.bin
#
# Env overrides (REMOTE_USER and REMOTE_HOST are required):
#   REMOTE_USER, REMOTE_HOST   SSH target
#   REMOTE_DIR    remote destination dir          (default /tmp)
#   REMOTE_MFTP   remote mftp binary path          (default $REMOTE_DIR/mftp)
#   IFACE         remote NIC for tc netem          (default ens33)
#   ZAP_BIN       zap binary                        (default: zap on PATH)
#   MFTP_LOCAL    local mftp binary                 (default ./target/release/mftp)
#   FILE_RANDOM   incompressible source            (default /tmp/test_1g_random.bin)
#   FILE_SMALL    smaller incompressible (loss)    (default /tmp/test_256m_random.bin)
#   FILE_LOGS     compressible log source          (default /tmp/test_1g_logs.bin)
#   SAMPLES       samples per cell                  (default 3)
set -uo pipefail

REMOTE_USER=${REMOTE_USER:?set REMOTE_USER (e.g. export REMOTE_USER=myuser)}
REMOTE_HOST=${REMOTE_HOST:?set REMOTE_HOST (e.g. export REMOTE_HOST=192.168.1.1)}
REMOTE=${REMOTE_USER}@${REMOTE_HOST}
REMOTE_DIR=${REMOTE_DIR:-/tmp}
REMOTE_MFTP=${REMOTE_MFTP:-$REMOTE_DIR/mftp}
IFACE=${IFACE:-ens33}
ZAP=${ZAP_BIN:-zap}
MFTP_LOCAL=${MFTP_LOCAL:-./target/release/mftp}
FILE_RANDOM=${FILE_RANDOM:-/tmp/test_1g_random.bin}
FILE_SMALL=${FILE_SMALL:-/tmp/test_256m_random.bin}
FILE_LOGS=${FILE_LOGS:-/tmp/test_1g_logs.bin}
SAMPLES=${SAMPLES:-3}

# Job matrix: "label|file|netem|timeout|comma,separated,tools"
JOBS=(
    "LAN|$FILE_RANDOM||600|scp,zap,mftp"
    "50ms|$FILE_RANDOM|delay 50ms|600|scp,zap,mftp"
    "150ms|$FILE_RANDOM|delay 150ms|600|scp,zap,mftp"
    "150ms+1%loss|$FILE_SMALL|delay 150ms loss 1%|150|scp,zap,mftp,mftp-fec"
    "50ms-logs|$FILE_LOGS|delay 50ms|600|scp,zap,mftp"
)

OUT=${OUT:-/tmp/mftp_compare_results.csv}
echo "scenario,dataset,tool,sample,seconds,mibps" > "$OUT"

ssh_q(){ ssh -o BatchMode=yes "$REMOTE" "$@"; }
tc_set(){ ssh_q "sudo tc qdisc del dev $IFACE root 2>/dev/null||true"; sleep .5; [ -n "${1:-}" ]&&{ ssh_q "sudo tc qdisc add dev $IFACE root netem $1"; sleep 1; }; }
drop_caches(){ sync; echo 1|sudo -n tee /proc/sys/vm/drop_caches >/dev/null 2>&1||true; ssh_q 'sync; echo 1|sudo -n tee /proc/sys/vm/drop_caches >/dev/null 2>&1||true'; }
clean_remote(){ ssh_q "rm -f $REMOTE_DIR/$1 $REMOTE_DIR/*.mftp-resume" 2>/dev/null||true; }
cleanup(){ tc_set ""; }
trap cleanup EXIT
mibps(){ awk -v b="$1" -v s="$2" 'BEGIN{if(s>0)printf "%.1f",b/s/1048576; else print "0"}'; }

# run_tool <tool> <file> <timeout> -> "<seconds> <mibps>"
run_tool(){
    local tool=$1 file=$2 to=$3 base size t0 t1 rc el rsize
    base=$(basename "$file"); size=$(stat -c %s "$file")
    clean_remote "$base"; drop_caches
    t0=$(date +%s.%N)
    case "$tool" in
        scp)      timeout "$to" scp -q "$file" "$REMOTE:$REMOTE_DIR/" >/dev/null 2>&1; rc=$? ;;
        zap)      timeout "$to" "$ZAP" -q "$file" "$REMOTE:$REMOTE_DIR/" >/dev/null 2>&1; rc=$? ;;
        mftp)     timeout "$to" "$MFTP_LOCAL" send --remote-mftp "$REMOTE_MFTP" "$file" "$REMOTE:$REMOTE_DIR/" >/dev/null 2>&1; rc=$? ;;
        mftp-fec) timeout "$to" "$MFTP_LOCAL" send --fec 8:2 --remote-mftp "$REMOTE_MFTP" "$file" "$REMOTE:$REMOTE_DIR/" >/dev/null 2>&1; rc=$? ;;
    esac
    t1=$(date +%s.%N)
    [ $rc -ne 0 ] && { echo "FAIL 0"; return; }
    rsize=$(ssh_q "stat -c %s $REMOTE_DIR/$base 2>/dev/null" || echo 0)
    [ "$rsize" != "$size" ] && { echo "BADSIZE 0"; return; }
    el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f",b-a}')
    echo "$el $(mibps "$size" "$el")"
}
median(){ printf '%s\n' "$@"|sort -n|awk '{a[NR]=$1}END{print a[int((NR+1)/2)]}'; }

declare -A MED
echo "samples=$SAMPLES | remote=$REMOTE | $(date)"
for job in "${JOBS[@]}"; do
    IFS='|' read -r label file rule to tools <<<"$job"
    [ -f "$file" ] || { echo "!! missing $file — skipping $label"; continue; }
    ds=$(basename "$file"); szmib=$(( $(stat -c %s "$file")/1024/1024 ))
    echo; echo "=== $label | $ds (${szmib} MiB) | netem '${rule:-none}' | timeout ${to}s ==="
    tc_set "$rule"
    IFS=',' read -ra tlist <<<"$tools"
    for tool in "${tlist[@]}"; do
        vals=()
        for i in $(seq 1 "$SAMPLES"); do
            read -r secs mbs <<<"$(run_tool "$tool" "$file" "$to")"
            echo "$label,$ds,$tool,$i,$secs,$mbs" >> "$OUT"
            printf "  %-8s sample %d: %9s s  %9s MiB/s\n" "$tool" "$i" "$secs" "$mbs"
            [ "$mbs" != "0" ] && vals+=("$mbs")
        done
        ((${#vals[@]})) && MED[$label,$tool]=$(median "${vals[@]}") || MED[$label,$tool]="FAIL"
    done
done

echo; echo "================ MEDIAN THROUGHPUT (MiB/s of original size) ================"
printf "%-16s %8s %8s %8s %9s\n" "scenario" "scp" "zap" "mftp" "mftp-fec"
for job in "${JOBS[@]}"; do
    label="${job%%|*}"
    printf "%-16s %8s %8s %8s %9s\n" "$label" \
        "${MED[$label,scp]:-–}" "${MED[$label,zap]:-–}" "${MED[$label,mftp]:-–}" "${MED[$label,mftp-fec]:-–}"
done
echo "Raw: $OUT"; echo "Done: $(date)"
