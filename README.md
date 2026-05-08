\# ML-Based Intrusion Prevention System for Healthcare Networks

\### Using eBPF and XDP | MSc Cyber Security Engineering — University of East London



\## Overview

An intelligent intrusion prevention system combining eBPF/XDP kernel-level 

packet interception with a Random Forest ML classifier and a confidence-based 

adaptive response framework, specifically designed for life-critical healthcare 

network deployment.



\## Key Results

| Metric | Result |

|--------|--------|

| Detection Accuracy | 98.62% |

| Weighted F1-Score | 98.62% |

| Inference Latency | 0.61ms |

| False Positive Rate (Benign) | 0% |

| Time-to-Mitigate (SYN Flood) | 1.2s vs 12.4s (traditional) |



\## System Architecture

Two-tier hybrid architecture:

\- \*\*Tier 1 — Kernel Space:\*\* eBPF/XDP module attaches at the XDP hook point,

&#x20; intercepts packets before the kernel networking stack, extracts flow features

&#x20; and enforces decisions via eBPF maps

\- \*\*Tier 2 — User Space:\*\* Python ML agent reads from the ring buffer, runs

&#x20; Random Forest inference, applies confidence-based response tier, writes

&#x20; enforcement decisions back to kernel via eBPF maps

\- \*\*SOC Dashboard:\*\* Flask web dashboard for real-time monitoring and alert management



\## Confidence-Based Response Framework

| Tier | Confidence | Action | Purpose |

|------|------------|--------|---------|

| A | < 60% | Monitor | Log only — protect clinical availability |

| B | 60–80% | Rate-Limit | Throttle suspicious flows |

| C | > 80% | Block | Hard drop — high confidence malicious |



\## Project Structure

ips\_project/

├── ebpf/

│   └── xdp\_ips.c              # eBPF/XDP kernel module

├── agent/

│   ├── agent.py               # ML classification engine

│   ├── classifier.py          # Random Forest inference

│   ├── response\_manager.py    # Enforcement manager

│   └── dashboard.py           # Flask SOC dashboard

├── ml/

│   └── train\_model.py         # Model training script

├── scripts/

│   └── ttm\_comparison.py      # Evaluation scripts

└── README.md



\## Environment

\- Ubuntu 22.04 LTS | Linux Kernel 5.15

\- Python 3.10

\- Dataset: CIC-IDS-2017



\## Setup

\### Prerequisites

```bash

sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

pip3 install scikit-learn pandas numpy joblib flask psutil

```



\### Load eBPF Module

```bash

cd ips\_project/ebpf

clang -O2 -g -target bpf -c xdp\_ips.c -o xdp\_ips.o

sudo ip link set enp0s8 xdp obj xdp\_ips.o sec xdp

```



\### Start ML Agent

```bash

sudo python3 agent/agent.py

```



\### Start SOC Dashboard

```bash

python3 agent/dashboard.py

\# Access at http://localhost:5000

```



\## Author

\*\*Ganiyu Kolapo Abdulrasheed\*\*

