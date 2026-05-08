#!/bin/bash
# ============================================================
# Config C — Traditional iptables IPS (No ML, No XDP)
# This simulates a conventional user-space IPS using only
# static iptables rules — the traditional approach
# ============================================================

RESULTS="/home/student/ips_project/results/"
LOG="${RESULTS}baseline_ips_log.txt"

echo "================================================" | tee $LOG
echo " CONFIG C — Traditional iptables IPS" | tee -a $LOG
echo " No ML, No XDP, Static rules only" | tee -a $LOG
echo "================================================" | tee -a $LOG

# Clear any existing rules
sudo iptables -F
sudo iptables -X

echo "[$(date +%H:%M:%S)] iptables rules cleared" | tee -a $LOG
echo "[$(date +%H:%M:%S)] Applying traditional IPS rules..." | tee -a $LOG

# Traditional IPS rules — static, signature-based
# Rule 1: Rate limit SYN packets (SYN flood protection)
sudo iptables -A INPUT -p tcp --syn \
    -m limit --limit 10/second --limit-burst 20 \
    -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP

# Rule 2: Block port scanning (limit new connections)
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Rule 3: Allow established connections
sudo iptables -A INPUT -m state \
    --state ESTABLISHED,RELATED -j ACCEPT

# Rule 4: Allow specific ports (simulate clinical traffic)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5201 -j ACCEPT

echo "[$(date +%H:%M:%S)] Rules applied. Current ruleset:" | tee -a $LOG
sudo iptables -L INPUT -n --line-numbers | tee -a $LOG

echo "" | tee -a $LOG
echo "[$(date +%H:%M:%S)] Config C is ACTIVE." | tee -a $LOG
echo "[$(date +%H:%M:%S)] Traditional IPS running — monitoring..." | tee -a $LOG
echo "" | tee -a $LOG
echo "NOTE: This IPS cannot DETECT attacks — it can only" | tee -a $LOG
echo "apply static rules. It has NO awareness of what is" | tee -a $LOG
echo "malicious vs legitimate beyond hardcoded thresholds." | tee -a $LOG
echo "It cannot detect port scans or novel attack patterns." | tee -a $LOG
echo "================================================" | tee -a $LOG
