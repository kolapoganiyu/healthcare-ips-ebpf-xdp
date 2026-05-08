#!/usr/bin/env python3
# collect_metrics.py — Records system performance during experiments
import psutil, time, json, os, subprocess
from datetime import datetime

RESULTS_DIR = "/home/student/ips_project/results/"
os.makedirs(RESULTS_DIR, exist_ok=True)

def get_net_stats(iface="enp0s8"):
    stats = psutil.net_io_counters(pernic=True)
    if iface in stats:
        return stats[iface].packets_recv, stats[iface].packets_sent
    return 0, 0

def measure(scenario_name, duration=120):
    print(f"\n[Metrics] Starting: {scenario_name} ({duration}s)")
    print(f"[Metrics] Recording every 2 seconds...")

    samples = []
    start   = time.time()
    pkt_start_rx, pkt_start_tx = get_net_stats()

    while time.time() - start < duration:
        cpu   = psutil.cpu_percent(interval=1)
        mem   = psutil.virtual_memory().percent
        rx, tx = get_net_stats()

        sample = {
            'time_s':    round(time.time() - start, 1),
            'cpu_pct':   cpu,
            'mem_pct':   mem,
            'pkts_rx':   rx,
            'pkts_tx':   tx,
        }
        samples.append(sample)
        print(f"  t={sample['time_s']:>5}s  "
              f"CPU={cpu:>5.1f}%  "
              f"MEM={mem:>5.1f}%  "
              f"RX_pkts={rx}")
        time.sleep(2)

    # Summary
    cpus = [s['cpu_pct'] for s in samples]
    total_pkts = samples[-1]['pkts_rx'] - pkt_start_rx

    summary = {
        'scenario':       scenario_name,
        'duration_s':     round(time.time() - start, 1),
        'cpu_mean':       round(sum(cpus)/len(cpus), 2),
        'cpu_max':        round(max(cpus), 2),
        'cpu_min':        round(min(cpus), 2),
        'total_pkts_rx':  total_pkts,
        'samples':        samples,
        'timestamp':      datetime.now().isoformat(),
    }

    fname = RESULTS_DIR + f"metrics_{scenario_name.replace(' ','_')}.json"
    with open(fname, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n[Metrics] Done!")
    print(f"  CPU mean: {summary['cpu_mean']}%")
    print(f"  CPU max:  {summary['cpu_max']}%")
    print(f"  Packets:  {summary['total_pkts_rx']:,}")
    print(f"  Saved:    {fname}")
    return summary

if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "test"
    dur  = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    measure(name, dur)
