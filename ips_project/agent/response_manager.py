# response_manager.py — confidence-based enforcement decision engine
import socket
import struct
import time

# Confidence thresholds (from Chapter 3 Table 3.6)
TIER1_THRESHOLD = 0.65   # below this: monitor only
TIER2_THRESHOLD = 0.85   # between T1-T2: rate limit
                          # above T2: block (XDP_DROP)

# Action codes (must match xdp_ips.c)
ACTION_PASS      = 0
ACTION_RATELIMIT = 1
ACTION_DROP      = 2

class ResponseManager:
    def __init__(self, enforcement_map):
        """
        enforcement_map: bpf map object from the loaded BPF program
        """
        self.enforcement_map = enforcement_map
        self.action_log      = []   # keep record for metrics
        self.counters = {
            'tier1_monitor':    0,
            'tier2_ratelimit':  0,
            'tier3_block':      0,
            'benign_passed':    0,
        }

    def decide(self, src_ip_int, label, confidence):
        """
        Given a classification result, determine and apply
        the appropriate enforcement action.

        src_ip_int : source IP as a 32-bit integer
        label      : 'BENIGN', 'ATTACK', or 'SCAN'
        confidence : float 0.0 – 1.0
        """
        action = ACTION_PASS
        tier   = 0

        if label == 'BENIGN':
            # Always pass benign traffic — remove any old block if present
            action = ACTION_PASS
            tier   = 0
            self.counters['benign_passed'] += 1
            # Clear enforcement entry if it exists
            try:
                del self.enforcement_map[struct.pack('I', src_ip_int)]
            except Exception:
                pass

        else:
            # Malicious traffic — apply tiered response
            if confidence < TIER1_THRESHOLD:
                action = ACTION_PASS    # too uncertain — just monitor
                tier   = 1
                self.counters['tier1_monitor'] += 1

            elif confidence < TIER2_THRESHOLD:
                action = ACTION_RATELIMIT
                tier   = 2
                self.counters['tier2_ratelimit'] += 1
                self._write_action(src_ip_int, ACTION_RATELIMIT)

            else:
                action = ACTION_DROP
                tier   = 3
                self.counters['tier3_block'] += 1
                self._write_action(src_ip_int, ACTION_DROP)

        # Log the decision
        entry = {
            'time':       time.time(),
            'src_ip':     self._int_to_ip(src_ip_int),
            'label':      label,
            'confidence': round(confidence, 4),
            'tier':       tier,
            'action':     ['PASS', 'RATELIMIT', 'DROP'][action],
        }
        self.action_log.append(entry)

        return tier, action

    def _write_action(self, src_ip_int, action_code):
        """Write enforcement action to BPF map."""
        try:
            key = struct.pack('I', src_ip_int)
            val = struct.pack('I', action_code)
            self.enforcement_map[key] = val
        except Exception as e:
            print(f"[ResponseManager] Map write error: {e}")

    def _int_to_ip(self, ip_int):
        return socket.inet_ntoa(struct.pack('!I', ip_int))

    def print_counters(self):
        print("\n[ResponseManager] Action counters:")
        print(f"  Tier 1 Monitor    : {self.counters['tier1_monitor']}")
        print(f"  Tier 2 Rate-limit : {self.counters['tier2_ratelimit']}")
        print(f"  Tier 3 Block      : {self.counters['tier3_block']}")
        print(f"  Benign Passed     : {self.counters['benign_passed']}")

    def get_log(self):
        return self.action_log
