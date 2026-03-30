#!/usr/bin/env python3
"""
Analyze mftp benchmark results and print a formatted report with findings.
Usage: python3 tests/analyze.py tests/results/<timestamp>/
"""

import sys
import csv
import os
from collections import defaultdict

def load_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))

def mbs(row):
    try:
        return float(row['mbs'])
    except (ValueError, KeyError):
        return 0.0

def bar(value, max_val, width=40):
    filled = int(width * value / max_val) if max_val > 0 else 0
    return '█' * filled + '░' * (width - filled)

def print_section(title):
    print(f"\n{'═' * 70}")
    print(f"  {title}")
    print('═' * 70)

def parse_rtt_ms(scenario):
    """Return RTT in ms as a float, or None if not parseable."""
    import re
    m = re.match(r'^(\d+)ms', scenario)
    if m:
        return float(m.group(1))
    return None

def analyze_phase1(results_dir):
    rows = load_csv(os.path.join(results_dir, 'phase1_positioning.csv'))
    if not rows:
        return
    print_section("PHASE 1 — Positioning: mftp vs scp")

    # Label format: "tool  scenario" (two or more spaces as separator)
    import re
    by_scenario = defaultdict(dict)
    for r in rows:
        label = r['label'].strip()
        # Split on 2+ spaces: "mftp (auto)  150ms" → ["mftp (auto)", "150ms"]
        parts = re.split(r'  +', label, maxsplit=1)
        if len(parts) == 2:
            tool, scenario = parts[0].strip(), parts[1].strip()
        else:
            continue
        # Normalize tool name to a short key
        if tool == 'scp':
            key = 'scp'
        elif '(auto)' in tool:
            key = 'mftp'
        else:
            key = 'mftp--tcp'
        by_scenario[scenario][key] = mbs(r)

    order = ['LAN (0ms)', '10ms', '50ms', '150ms', '400ms', '600ms+1%loss']

    print(f"\n{'Scenario':<20} {'scp':>8} {'mftp':>8} {'mftp--tcp':>10}   Speedup(mftp/scp)")
    print('-' * 70)
    speedups = {}
    for s in order:
        if s not in by_scenario:
            continue
        d = by_scenario[s]
        scp_v   = d.get('scp', 0)
        mftp_v  = d.get('mftp', 0)
        tcp_v   = d.get('mftp--tcp', 0)
        speedup = mftp_v / scp_v if scp_v > 0 else float('nan')
        speedups[s] = speedup
        print(f"  {s:<18} {scp_v:>7.1f}  {mftp_v:>7.1f}  {tcp_v:>9.1f}   {speedup:>6.1f}x")

    print("\nFindings:")
    high_latency = {k: v for k, v in speedups.items()
                    if parse_rtt_ms(k) is not None and parse_rtt_ms(k) >= 150}
    if high_latency:
        valid = {k: v for k, v in high_latency.items() if not (v != v)}  # exclude NaN
        if valid:
            avg_speedup = sum(valid.values()) / len(valid)
            print(f"  • Average speedup at ≥150ms RTT: {avg_speedup:.1f}x vs scp")
    low_latency = speedups.get('LAN (0ms)', 1.0)
    if low_latency != low_latency:  # NaN
        low_latency = 0
    if low_latency < 0.9:
        print(f"  • LAN overhead: mftp is {(1-low_latency)*100:.0f}% slower than scp on LAN (expected for QUIC)")
    elif low_latency > 1.1:
        print(f"  • Surprising: mftp {(low_latency-1)*100:.0f}% faster than scp even on LAN")
    # Check TCP path
    tcp_vals = {s: by_scenario[s].get('mftp--tcp', 0) for s in order if s in by_scenario}
    poor_tcp = [(s, by_scenario[s].get('mftp--tcp', 0), by_scenario[s].get('mftp', 0))
                for s in order if s in by_scenario
                and by_scenario[s].get('mftp--tcp', 0) < by_scenario[s].get('mftp', 0) * 0.5]
    if poor_tcp:
        print(f"  • TCP path underperforms QUIC significantly at: "
              + ", ".join(f"{s} ({t:.0f} vs {q:.0f} MiB/s)" for s, t, q in poor_tcp))

def analyze_phase2(results_dir):
    rows = load_csv(os.path.join(results_dir, 'phase2_streams.csv'))
    if not rows:
        return
    print_section("PHASE 2 — Stream Count Sweep")

    by_rtt = defaultdict(dict)
    for r in rows:
        # streams column may be empty (old format with leading comma in extra)
        rtt = r.get('rtt_ms', '').strip()
        streams = r.get('streams', '').strip()
        if not rtt or not streams:
            # Fall back to parsing from label: "mftp -n 8  RTT=150ms"
            label = r['label']
            import re
            rtt_m = re.search(r'RTT=(\S+)', label)
            rtt = rtt_m.group(1) if rtt_m else '?'
            n_m = re.search(r'-n\s+(\d+)', label)
            streams = n_m.group(1) if n_m else 'auto'
        by_rtt[rtt][streams] = mbs(r)

    print(f"\n{'Streams':<10}", end='')
    rtts = sorted(by_rtt.keys())
    for rtt in rtts:
        print(f"  RTT={rtt:>6}", end='')
    print()
    print('-' * 60)

    stream_vals = ['auto', '1', '2', '4', '8', '16', '32']
    for s in stream_vals:
        print(f"  {s:<8}", end='')
        for rtt in rtts:
            v = by_rtt[rtt].get(s, 0)
            print(f"  {v:>9.1f}", end='')
        print()

    print("\nFindings:")
    for rtt in rtts:
        d = by_rtt[rtt]
        best_n = max(d, key=lambda x: d[x])
        best_v = d[best_n]
        auto_v = d.get('auto', 0)
        if best_n != 'auto' and auto_v > 0:
            diff = (best_v - auto_v) / auto_v * 100
            if abs(diff) > 5:
                direction = 'better' if diff > 0 else 'worse'
                print(f"  • RTT={rtt}: -n {best_n} is {abs(diff):.0f}% {direction} than auto "
                      f"({best_v:.1f} vs {auto_v:.1f} MiB/s)")

def analyze_phase3(results_dir):
    rows = load_csv(os.path.join(results_dir, 'phase3_chunksize.csv'))
    if not rows:
        return
    print_section("PHASE 3 — Chunk Size Sweep")

    by_rtt = defaultdict(dict)
    for r in rows:
        import re
        rtt = r.get('rtt_ms', '').strip()
        cs_bytes = r.get('chunk_bytes', '').strip()
        if not rtt or not cs_bytes:
            label = r['label']
            rtt_m = re.search(r'RTT=(\S+)', label)
            rtt = rtt_m.group(1) if rtt_m else '?'
            cs_m = re.search(r'chunk=(\d+K)', label)
            cs_bytes = str(int(cs_m.group(1)[:-1]) * 1024) if cs_m else 'auto'
        cs_label = f"{int(cs_bytes)//1024}K" if cs_bytes not in ('auto', '') else 'auto'
        by_rtt[rtt][cs_label] = mbs(r)

    chunk_vals = ['auto', '512K', '1024K', '2048K', '4096K', '8192K']
    rtts = sorted(by_rtt.keys())
    print(f"\n{'Chunk':<10}", end='')
    for rtt in rtts:
        print(f"  RTT={rtt:>6}", end='')
    print()
    print('-' * 60)
    for c in chunk_vals:
        print(f"  {c:<8}", end='')
        for rtt in rtts:
            v = by_rtt[rtt].get(c, 0)
            print(f"  {v:>9.1f}", end='')
        print()

    print("\nFindings:")
    for rtt in rtts:
        d = by_rtt[rtt]
        best_c = max(d, key=lambda x: d[x])
        best_v = d[best_c]
        auto_v = d.get('auto', 0)
        if best_c != 'auto' and auto_v > 0:
            diff = (best_v - auto_v) / auto_v * 100
            if abs(diff) > 5:
                direction = 'better' if diff > 0 else 'worse'
                print(f"  • RTT={rtt}: --chunk-size {best_c} is {abs(diff):.0f}% {direction} than auto")

def analyze_phase4(results_dir):
    rows = load_csv(os.path.join(results_dir, 'phase4_transport.csv'))
    if not rows:
        return
    print_section("PHASE 4 — Transport: QUIC vs TCP+TLS")

    quic = {}; tcp = {}
    for r in rows:
        rtt = r.get('rtt_ms', '?')
        transport = r.get('transport', '')
        if transport == 'quic':
            quic[rtt] = mbs(r)
        elif transport == 'tcp':
            tcp[rtt] = mbs(r)

    all_rtts = sorted(set(list(quic) + list(tcp)))
    print(f"\n{'RTT':<16} {'QUIC':>8} {'TCP+TLS':>8}   Winner")
    print('-' * 50)
    for rtt in all_rtts:
        q = quic.get(rtt, 0)
        t = tcp.get(rtt, 0)
        winner = 'QUIC' if q > t else 'TCP+TLS'
        margin = abs(q - t) / max(q, t) * 100 if max(q, t) > 0 else 0
        print(f"  {rtt:<14} {q:>7.1f}  {t:>7.1f}   {winner} (+{margin:.0f}%)")

def analyze_phase5(results_dir):
    rows = load_csv(os.path.join(results_dir, 'phase5_compression.csv'))
    if not rows:
        return
    print_section("PHASE 5 — Compression Impact")

    data = {}
    for r in rows:
        ft = r.get('file_type', '?')
        comp = r.get('compress', '?')
        data[(ft, comp)] = mbs(r)

    print(f"\n{'File type':<12} {'compress=auto':>14} {'compress=off':>13}   Impact")
    print('-' * 55)
    for ft in ['random', 'text']:
        on  = data.get((ft, 'on'), 0)
        off = data.get((ft, 'off'), 0)
        diff = (on - off) / off * 100 if off > 0 else 0
        sign = '+' if diff > 0 else ''
        print(f"  {ft:<10} {on:>13.1f}  {off:>12.1f}   {sign}{diff:.0f}%")

    print("\nFindings:")
    rand_on  = data.get(('random', 'on'), 0)
    rand_off = data.get(('random', 'off'), 0)
    if rand_on > 0 and rand_off > 0:
        diff = (rand_on - rand_off) / rand_off * 100
        if abs(diff) < 3:
            print("  • Magic-byte / probe detection is working: compression overhead is minimal on random data")
        elif diff < -3:
            print(f"  • Compression costs {-diff:.0f}% on random data — probe overhead is significant; "
                  "consider skipping the probe when the first 4 bytes match no format")

    text_on  = data.get(('text', 'on'), 0)
    text_off = data.get(('text', 'off'), 0)
    if text_on > 0 and text_off > 0:
        diff = (text_on - text_off) / text_off * 100
        if diff > 10:
            print(f"  • Compression gives {diff:.0f}% speedup on text data (good)")

def main():
    if len(sys.argv) < 2:
        # Find the latest results dir
        base = 'tests/results'
        if not os.path.exists(base):
            print("No results directory found. Run tests/bench.sh first.")
            sys.exit(1)
        dirs = sorted(os.listdir(base))
        if not dirs:
            print("No results found.")
            sys.exit(1)
        results_dir = os.path.join(base, dirs[-1])
        print(f"Using latest results: {results_dir}")
    else:
        results_dir = sys.argv[1]

    print(f"\nmftp Benchmark Analysis")
    print(f"Results: {results_dir}")

    analyze_phase1(results_dir)
    analyze_phase2(results_dir)
    analyze_phase3(results_dir)
    analyze_phase4(results_dir)
    analyze_phase5(results_dir)

    print(f"\n{'═' * 70}")
    print("  Raw CSVs for further analysis:")
    for f in sorted(os.listdir(results_dir)):
        if f.endswith('.csv'):
            print(f"    {results_dir}/{f}")

if __name__ == '__main__':
    main()
