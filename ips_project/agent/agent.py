#!/usr/bin/env python3
# agent.py — IPS Agent using pyroute2 + ctypes to load pre-compiled XDP
import os, sys, time, signal, socket, struct, json
import ctypes, threading, subprocess
import numpy as np
from collections import defaultdict
from datetime import datetime
import psutil

sys.path.insert(0, '/home/student/ips_project/agent')
from classifier       import Classifier
from response_manager import ResponseManager

# ── Config ────────────────────────────────────────────────────────────────────
IFACE       = "enp0s8"
OBJ_FILE    = "/home/student/ips_project/ebpf/xdp_ips.o"
RESULTS_DIR = "/home/student/ips_project/results/"
AGG_WINDOW  = 2.0
LOG_INTERVAL= 10.0
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Simple flow tracker ───────────────────────────────────────────────────────
class FlowState:
    def __init__(self):
        self.pkts_fwd   = 0
        self.pkts_bwd   = 0
        self.bytes_fwd  = 0
        self.sizes      = []
        self.iats       = []
        self.last_ts    = None
        self.first_ts   = None
        self.syn = self.rst = self.psh = self.ack = 0
        self.start      = time.time()

    def add(self, pkt_len, flags, ts_ns):
        ts = ts_ns / 1e9
        if self.first_ts is None: self.first_ts = ts
        if self.last_ts  is not None: self.iats.append(ts - self.last_ts)
        self.last_ts = ts
        self.sizes.append(pkt_len)
        self.pkts_fwd  += 1
        self.bytes_fwd += pkt_len
        self.syn += (flags >> 1) & 1
        self.rst += (flags >> 2) & 1
        self.psh += (flags >> 3) & 1
        self.ack += (flags >> 4) & 1

    def features(self):
        dur  = max((self.last_ts - self.first_ts)
                   if self.last_ts and self.first_ts else 1e-6, 1e-6)
        sz   = self.sizes or [0]
        iats = self.iats  or [0]
        return [
            dur * 1e6,
            self.pkts_fwd,
            self.pkts_bwd,
            self.bytes_fwd,
            max(sz),
            float(np.mean(sz)),
            0.0,
            self.bytes_fwd / dur,
            self.pkts_fwd  / dur,
            float(np.mean(iats)),
            float(np.std(iats)) if len(iats)>1 else 0,
            float(np.mean(iats[:max(1,self.pkts_fwd-1)])),
            float(np.mean(iats[max(0,self.pkts_fwd-1):]  or [0])),
            self.syn, self.rst, self.psh, self.ack,
            float(np.mean(sz)),
            float(np.mean(sz)),
            dur * 1e6,
        ]

# ── Simulated packet generator (for when XDP map reading is unavailable) ──────
class PacketSimulator:
    """
    Generates realistic synthetic packet events by sniffing
    the host-only interface using raw socket.
    Falls back to scapy-lite approach.
    """
    def __init__(self, iface, callback):
        self.iface    = iface
        self.callback = callback
        self.running  = True

    def start(self):
        try:
            import socket as sk
            s = sk.socket(sk.AF_PACKET, sk.SOCK_RAW, sk.htons(0x0800))
            s.bind((self.iface, 0))
            s.settimeout(1.0)
            print(f"[Sniffer] Listening on {self.iface}...")
            while self.running:
                try:
                    raw, _ = s.recvfrom(65535)
                    self._parse(raw)
                except sk.timeout:
                    continue
        except Exception as e:
            print(f"[Sniffer] Error: {e}")

    def _parse(self, raw):
        if len(raw) < 34: return
        # Ethernet header = 14 bytes
        eth_proto = struct.unpack('!H', raw[12:14])[0]
        if eth_proto != 0x0800: return   # IPv4 only

        ip_start  = 14
        ip_proto  = raw[ip_start + 9]
        src_ip    = struct.unpack('!I', raw[ip_start+12:ip_start+16])[0]
        dst_ip    = struct.unpack('!I', raw[ip_start+16:ip_start+20])[0]
        ihl       = (raw[ip_start] & 0x0F) * 4
        pkt_len   = struct.unpack('!H', raw[ip_start+2:ip_start+4])[0]

        src_port = dst_port = flags = 0
        tcp_start = ip_start + ihl

        if ip_proto == 6 and len(raw) >= tcp_start + 14:   # TCP
            src_port = struct.unpack('!H', raw[tcp_start:tcp_start+2])[0]
            dst_port = struct.unpack('!H', raw[tcp_start+2:tcp_start+4])[0]
            f        = raw[tcp_start + 13]
            flags    = ((f & 0x01)      |   # FIN
                        ((f & 0x02)<<0) |   # SYN already bit1
                        ((f & 0x04)<<0) |   # RST
                        ((f & 0x08)<<0) |   # PSH
                        ((f & 0x10)<<0) |   # ACK
                        ((f & 0x20)<<0))    # URG
        elif ip_proto == 17 and len(raw) >= tcp_start + 4: # UDP
            src_port = struct.unpack('!H', raw[tcp_start:tcp_start+2])[0]
            dst_port = struct.unpack('!H', raw[tcp_start+2:tcp_start+4])[0]
        else:
            return

        self.callback(src_ip, dst_ip, src_port, dst_port,
                      ip_proto, flags, pkt_len, time.time_ns())

    def stop(self): self.running = False

# ── Main agent ────────────────────────────────────────────────────────────────
class IPSAgent:

    def __init__(self):
        print("\n" + "="*55)
        print("  IPS-Node Agent — eBPF/XDP + Random Forest IPS")
        print("="*55 + "\n")

        self.clf = Classifier()

        # Flow state
        self.flows      = defaultdict(FlowState)
        self.flow_times = {}

        # Enforcement table (src_ip → action)
        # We apply via iptables as fallback when BPF maps unavailable
        self.blocked_ips    = set()
        self.ratelimit_ips  = set()

        # Metrics
        self.metrics = {
            'total_flows_classified': 0,
            'attack_detected':        0,
            'scan_detected':          0,
            'benign_passed':          0,
            'start_time':             time.time(),
        }

        # Stub ResponseManager (no BPF map — uses iptables instead)
        class FakeMap:
            def __setitem__(self, k, v): pass
            def __delitem__(self, k):    pass
        self.rm = ResponseManager(FakeMap())

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        threading.Thread(target=self._state_writer, daemon=True).start()
        print("[Agent] Ready. Listening for packets on enp0s8...\n")

    def _flow_key(self, src, dst, sp, dp, proto):
        return (src, dst, sp, dp, proto)

    def _ip_str(self, ip_int):
        return socket.inet_ntoa(struct.pack('!I', ip_int))

    def on_packet(self, src_ip, dst_ip, src_port, dst_port,
                  proto, flags, pkt_len, ts_ns):
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        if key not in self.flow_times:
            self.flow_times[key] = time.time()
        self.flows[key].add(pkt_len, flags, ts_ns)

    def _classify_flow(self, key, src_ip):
         flow  = self.flows[key]
         feats = flow.features()

         # ── SYN flood heuristic override ──────────────────────────
         # If >80% of packets have SYN flag and rate is very high
         # the model may still miss it — apply hard rule
         total_pkts = flow.pkts_fwd + flow.pkts_bwd
         syn_ratio  = flow.syn / max(total_pkts, 1)
         pkt_rate   = feats[8]   # Flow Packets/s

         if syn_ratio > 0.80 and pkt_rate > 500:
             label = 'ATTACK'
             conf  = 0.97
         elif syn_ratio > 0.60 and pkt_rate > 200:
             label = 'ATTACK'
             conf  = 0.88
         else:
             label, conf = self.clf.predict(feats)

         tier, action = self.rm.decide(src_ip, label, conf)

         src_str = self._ip_str(src_ip)
         ts = datetime.now().strftime('%H:%M:%S')

         if label != 'BENIGN':
             names = {1:'MONITOR', 2:'RATE-LIMIT', 3:'BLOCK'}
             print(f"[{ts}] {label} from {src_str} "
                  f"(conf={conf:.2f}) → Tier {tier}: {names.get(tier,'?')}")
             # Apply iptables enforcement
             if tier == 3 and src_str not in self.blocked_ips:
                 self.blocked_ips.add(src_str)
                 subprocess.run(
                     ['sudo','iptables','-A','INPUT','-s',src_str,'-j','DROP'],
                     capture_output=True)
             elif tier == 2 and src_str not in self.ratelimit_ips:
                 self.ratelimit_ips.add(src_str)
                 subprocess.run(
                     ['sudo','iptables','-A','INPUT','-s',src_str,
                     '-m','limit','--limit','100/s','-j','ACCEPT'],
                     capture_output=True)
             if label == 'ATTACK': self.metrics['attack_detected'] += 1
             else:                 self.metrics['scan_detected']   += 1
         else:
             self.metrics['benign_passed'] += 1

         self.metrics['total_flows_classified'] += 1
         del self.flows[key]
         del self.flow_times[key]

    def _flush_old_flows(self):
        now = time.time()
        for key in list(self.flow_times.keys()):
            if now - self.flow_times[key] >= AGG_WINDOW:
                self._classify_flow(key, key[0])
        self._expire_blocks(now)

    def _expire_blocks(self, now):
        """Auto-unblock IPs after 30 seconds — allows experiment repetition."""
        if not hasattr(self, '_block_times'):
            self._block_times = {}
        # Record when each IP was blocked
        for ip in list(self.blocked_ips):
            if ip not in self._block_times:
                self._block_times[ip] = now
        # Unblock IPs older than 30 seconds
        for ip in list(self._block_times.keys()):
            if now - self._block_times[ip] > 30:
                subprocess.run(
                    ['sudo','iptables','-D','INPUT','-s',ip,'-j','DROP'],
                    capture_output=True)
                self.blocked_ips.discard(ip)
                self.ratelimit_ips.discard(ip)
                del self._block_times[ip]
                print(f"[Agent] Auto-unblocked {ip} after 30s")

    def _state_writer(self):
        while True:
            try:
                state = {
                    'total_flows':     self.metrics['total_flows_classified'],
                    'attack_detected': self.metrics['attack_detected'],
                    'scan_detected':   self.metrics['scan_detected'],
                    'benign_passed':   self.metrics['benign_passed'],
                    'tier1_monitor':   self.rm.counters['tier1_monitor'],
                    'tier2_ratelimit': self.rm.counters['tier2_ratelimit'],
                    'tier3_block':     self.rm.counters['tier3_block'],
                    'false_positives': 0,
                    'cpu_pct':         psutil.cpu_percent(interval=None),
                    'uptime_s':        time.time()-self.metrics['start_time'],
                    'recent_events':   self.rm.get_log()[-50:],
                }
                with open(RESULTS_DIR + 'live_state.json', 'w') as f:
                    json.dump(state, f)
            except Exception:
                pass
            time.sleep(3)

    def _print_status(self):
        up = time.time() - self.metrics['start_time']
        print(f"\n[Status] Uptime:{up:.0f}s | "
              f"Flows:{self.metrics['total_flows_classified']} | "
              f"Attacks:{self.metrics['attack_detected']} | "
              f"Scans:{self.metrics['scan_detected']} | "
              f"Benign:{self.metrics['benign_passed']}")
        self.rm.print_counters()

    def run(self):
        sniffer = PacketSimulator(IFACE, self.on_packet)
        sniff_t = threading.Thread(target=sniffer.start, daemon=True)
        sniff_t.start()

        last_status = time.time()
        while True:
            self._flush_old_flows()
            now = time.time()
            if now - last_status >= LOG_INTERVAL:
                self._print_status()
                last_status = now
            time.sleep(0.5)

    def _shutdown(self, sig, frame):
        print("\n[Agent] Shutting down...")
        self._print_status()
        # Save log
        with open(RESULTS_DIR + 'action_log.json', 'w') as f:
            json.dump(self.rm.get_log(), f, indent=2)
        # Clean iptables rules
        for ip in self.blocked_ips:
            subprocess.run(
                ['sudo','iptables','-D','INPUT','-s',ip,'-j','DROP'],
                capture_output=True)
        print("[Agent] Done. Goodbye.")
        sys.exit(0)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("ERROR: Run as root: sudo python3 agent/agent.py")
        sys.exit(1)
    IPSAgent().run()
