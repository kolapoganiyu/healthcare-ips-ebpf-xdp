#!/bin/bash
echo "[Reset] Clearing all IPS iptables rules..."
sudo iptables -F INPUT
sudo iptables -F OUTPUT  
sudo iptables -F FORWARD
echo "[Reset] Done. All rules cleared."
echo "[Reset] Current rules:"
sudo iptables -L INPUT --line-numbers
