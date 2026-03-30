#!/usr/bin/env bash
# mftp throughput benchmark suite
#
# Usage:
#   ./tests/bench.sh [phase]
#
# Phases:
#   1  Positioning: mftp vs scp across latency conditions    (~25 min)
#   2  Stream sweep: find optimal stream count at each RTT   (~30 min)
#   3  Chunk sweep:  find optimal chunk size at each RTT     (~20 min)
#   4  Transport:    QUIC vs TCP+TLS at each RTT             (~15 min)
#   5  Compression:  random vs compressible, on vs off       (~10 min)
#   all  All phases in order (default)
#
# Results written to tests/results/<timestamp>/
# Each phase writes its own CSV; run tests/analyze.py to generate report.
#
# Requirements:
#   - mftp binary built: cargo build --release
#   - Remote binary installed: scp target/release/mftp mftp@10.1.1.168:/data/mftp
#   - Test files created: see tests/make_testfiles.sh
#   - SSH key auth to mftp@10.1.1.168

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

MFTP=./target/release/mftp
REMOTE_USER=mftp
REMOTE_HOST=10.1.1.168
REMOTE=mftp@10.1.1.168
REMOTE_MFTP=/data/mftp
REMOTE_DIR=/data
IFACE=ens33

FILE_RANDOM=/data/test_1g_random.bin
FILE_TEXT=/data/test_1g_text.bin
FILE_SIZE=$((1024 * 1024 * 1024))   # 1 GiB

PHASE=${1:-all}

# ── Output ────────────────────────────────────────────────────────────────────

RESULTS_DIR=tests/results/$(date +%Y%m%d_%H%M%S)
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/bench.log"

log()  { echo "[$(date +%T)] $*" | tee -a "$LOG"; }
header() { echo "" | tee -a "$LOG"; echo "═══ $* ═══" | tee -a "$LOG"; }

# ── TC helpers ────────────────────────────────────────────────────────────────

tc_clear() {
    ssh "$REMOTE" "sudo tc qdisc del dev $IFACE root 2>/dev/null; true"
}

tc_set() {
    # $1 = netem arguments, e.g. "delay 150ms" or "delay 600ms loss 1%"
    tc_clear
    if [[ -n "${1:-}" ]]; then
        ssh "$REMOTE" "sudo tc qdisc add dev $IFACE root netem $1"
    fi
}

# ── Transfer helpers ──────────────────────────────────────────────────────────

# Clean the remote destination before each run.
remote_clean() {
    ssh "$REMOTE" "rm -f $REMOTE_DIR/test_*.bin $REMOTE_DIR/*.mftp-resume" 2>/dev/null || true
}

# Run mftp and return throughput in MiB/s (parsed from "X MiB/s end-to-end").
# Usage: mftp_throughput <file> [extra mftp args...]
mftp_throughput() {
    local file=$1; shift
    remote_clean
    local output
    # --remote-mftp skips binary copy; --trust skips TOFU prompt
    output=$("$MFTP" send "$@" \
        --remote-mftp "$REMOTE_MFTP" \
        "$file" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" 2>&1) || true
    local mbs
    mbs=$(echo "$output" | grep -oP '\(\K[\d.]+(?= MiB/s end-to-end)' | tail -1)
    echo "${mbs:-0}"
}

# Run scp and compute throughput from elapsed wall time.
scp_throughput() {
    local file=$1
    remote_clean
    local start end elapsed mbs
    start=$(date +%s%3N)
    scp -q "$file" "$REMOTE:$REMOTE_DIR/" 2>/dev/null || true
    end=$(date +%s%3N)
    elapsed=$(( end - start ))
    mbs=$(python3 -c "print(f'{$FILE_SIZE/$elapsed*1000/1048576:.1f}')")
    echo "$mbs"
}

# Write one result row.
result() {
    local csv=$1 label=$2 mbs=$3 extra=${4:-}
    printf "%-56s  %8s MiB/s\n" "$label" "$mbs" | tee -a "$LOG"
    echo "$label,$mbs,$extra" >> "$csv"
}

# ── Phase 1: Positioning ──────────────────────────────────────────────────────
# Question: are we actually faster than scp in our target scenarios?
# Varying: RTT (0 / 10 / 50 / 150 / 400 / 600ms+1%), tool (scp / mftp)
# File: 1GB random (incompressible — disadvantages mftp compression, fair baseline)

phase1() {
    header "PHASE 1 — Positioning: mftp vs scp across latency"
    local csv="$RESULTS_DIR/phase1_positioning.csv"
    echo "label,mbs,tc_rule" > "$csv"

    declare -A SCENARIOS=(
        ["LAN (0ms)"]=""
        ["10ms"]="delay 10ms"
        ["50ms"]="delay 50ms"
        ["150ms"]="delay 150ms"
        ["400ms"]="delay 400ms"
        ["600ms+1%loss"]="delay 600ms loss 1%"
    )

    # Fixed order for display
    local -a ORDER=("LAN (0ms)" "10ms" "50ms" "150ms" "400ms" "600ms+1%loss")

    for scenario in "${ORDER[@]}"; do
        local tc_rule="${SCENARIOS[$scenario]}"
        tc_set "$tc_rule"
        log "Scenario: $scenario"

        local mbs_scp mbs_mftp mbs_mftp_tcp
        mbs_scp=$(scp_throughput "$FILE_RANDOM")
        result "$csv" "scp          $scenario" "$mbs_scp" "$tc_rule"

        mbs_mftp=$(mftp_throughput "$FILE_RANDOM")
        result "$csv" "mftp (auto)  $scenario" "$mbs_mftp" "$tc_rule"

        mbs_mftp_tcp=$(mftp_throughput "$FILE_RANDOM" --tcp)
        result "$csv" "mftp --tcp   $scenario" "$mbs_mftp_tcp" "$tc_rule"
    done

    tc_clear
}

# ── Phase 2: Stream count sweep ───────────────────────────────────────────────
# Question: is our stream count formula optimal?
# Formula: max(ceil(RTT_ms/5), min_cores), capped at 2*min(sender,receiver) = 8
# Varying: stream count at 3 representative RTTs
# File: 1GB random

phase2() {
    header "PHASE 2 — Stream count sweep"
    local csv="$RESULTS_DIR/phase2_streams.csv"
    echo "label,mbs,streams,rtt_ms" > "$csv"

    local -a STREAM_COUNTS=(1 2 4 8 16 32)
    local -a RTTS=("50ms:delay 50ms" "150ms:delay 150ms" "400ms:delay 400ms")

    for rtt_spec in "${RTTS[@]}"; do
        local rtt_label="${rtt_spec%%:*}"
        local tc_rule="${rtt_spec##*:}"
        tc_set "$tc_rule"
        log "RTT: $rtt_label"

        # Auto first (for comparison)
        local mbs_auto
        mbs_auto=$(mftp_throughput "$FILE_RANDOM")
        result "$csv" "mftp auto         RTT=$rtt_label" "$mbs_auto" "auto,$rtt_label"

        for n in "${STREAM_COUNTS[@]}"; do
            local mbs
            mbs=$(mftp_throughput "$FILE_RANDOM" -n "$n")
            result "$csv" "mftp -n $n         RTT=$rtt_label" "$mbs" "$n,$rtt_label"
        done
    done

    tc_clear
}

# ── Phase 3: Chunk size sweep ─────────────────────────────────────────────────
# Question: is our chunk size formula optimal?
# Current formula: <10ms→8M, 10-50ms→4M, 50-150ms→2M, ≥150ms→1M
# Varying: chunk size at 3 representative RTTs
# File: 1GB random

phase3() {
    header "PHASE 3 — Chunk size sweep"
    local csv="$RESULTS_DIR/phase3_chunksize.csv"
    echo "label,mbs,chunk_bytes,rtt_ms" > "$csv"

    local -a CHUNK_SIZES=(524288 1048576 2097152 4194304 8388608)   # 512K 1M 2M 4M 8M
    local -a RTTS=("50ms:delay 50ms" "150ms:delay 150ms" "400ms:delay 400ms")

    for rtt_spec in "${RTTS[@]}"; do
        local rtt_label="${rtt_spec%%:*}"
        local tc_rule="${rtt_spec##*:}"
        tc_set "$tc_rule"
        log "RTT: $rtt_label"

        local mbs_auto
        mbs_auto=$(mftp_throughput "$FILE_RANDOM")
        result "$csv" "mftp auto         RTT=$rtt_label" "$mbs_auto" "auto,$rtt_label"

        for cs in "${CHUNK_SIZES[@]}"; do
            local label_k=$(( cs / 1024 ))
            local mbs
            mbs=$(mftp_throughput "$FILE_RANDOM" --chunk-size "$cs")
            result "$csv" "mftp chunk=${label_k}K    RTT=$rtt_label" "$mbs" "$cs,$rtt_label"
        done
    done

    tc_clear
}

# ── Phase 4: Transport comparison ─────────────────────────────────────────────
# Question: does QUIC outperform TCP+TLS at high latency?
# Expected: yes, due to no HoL blocking; TCP wins only on LAN
# File: 1GB random

phase4() {
    header "PHASE 4 — Transport comparison: QUIC vs TCP+TLS"
    local csv="$RESULTS_DIR/phase4_transport.csv"
    echo "label,mbs,transport,rtt_ms" > "$csv"

    local -a RTTS=("LAN::" "10ms:delay 10ms" "50ms:delay 50ms" "150ms:delay 150ms"
                   "400ms:delay 400ms" "600ms+1%:delay 600ms loss 1%")

    for rtt_spec in "${RTTS[@]}"; do
        local rtt_label="${rtt_spec%%:*}"
        local tc_rule="${rtt_spec##*:}"
        tc_set "$tc_rule"
        log "RTT: $rtt_label"

        local mbs_quic mbs_tcp
        # Force QUIC (disable TCP fallback by setting threshold to 0)
        mbs_quic=$(mftp_throughput "$FILE_RANDOM" --tcp-below-rtt 0)
        result "$csv" "mftp QUIC    RTT=$rtt_label" "$mbs_quic" "quic,$rtt_label"

        mbs_tcp=$(mftp_throughput "$FILE_RANDOM" --tcp)
        result "$csv" "mftp TCP+TLS RTT=$rtt_label" "$mbs_tcp" "tcp,$rtt_label"
    done

    tc_clear
}

# ── Phase 5: Compression impact ───────────────────────────────────────────────
# Question: does adaptive compression help/hurt? Is magic-byte detection working?
# Varying: file type (random vs text), compression (on vs off)
# RTT: 150ms (representative)

phase5() {
    header "PHASE 5 — Compression impact"
    local csv="$RESULTS_DIR/phase5_compression.csv"
    echo "label,mbs,file_type,compress,rtt_ms" > "$csv"

    tc_set "delay 150ms"
    log "RTT: 150ms"

    for file_spec in "random:$FILE_RANDOM" "text:$FILE_TEXT"; do
        local file_label="${file_spec%%:*}"
        local file="${file_spec##*:}"

        local mbs_on mbs_off
        mbs_on=$(mftp_throughput "$file")
        result "$csv" "mftp compress=auto  file=$file_label" "$mbs_on" "$file_label,on,150ms"

        mbs_off=$(mftp_throughput "$file" --no-compress)
        result "$csv" "mftp compress=off   file=$file_label" "$mbs_off" "$file_label,off,150ms"
    done

    tc_clear
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "mftp benchmark suite — results in $RESULTS_DIR"
log "Local cores: $(nproc), Remote cores: $(ssh $REMOTE nproc)"
log "File size: $((FILE_SIZE / 1024 / 1024)) MiB"
log "mftp version: $($MFTP --version)"

trap 'tc_clear; log "TC rules cleared (trap)"' EXIT

case "$PHASE" in
    1) phase1 ;;
    2) phase2 ;;
    3) phase3 ;;
    4) phase4 ;;
    5) phase5 ;;
    all)
        phase1
        phase2
        phase3
        phase4
        phase5
        ;;
    *)
        echo "Unknown phase: $PHASE"; exit 1 ;;
esac

log "Done. Results in $RESULTS_DIR/"
