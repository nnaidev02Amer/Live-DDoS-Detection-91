# Windows Setup Guide

## What this project is
An SDN (Software Defined Network) lab that detects DDoS floods with machine learning:
- **Mininet** simulates a network: 6 switches (s1-s6, Open vSwitch) and 18 hosts (h1-h18).
- **Ryu** is the SDN controller. Every 10 s it asks the switches for flow statistics
  (packets, bytes, durations, protocol, ports...).
- A **Random Forest** model (scikit-learn) is trained at start-up from `FlowStatsfile.csv`
  and classifies each flow as normal (0) or DDoS (1).
- If most flows look malicious, the **mitigation module** finds the victim port and
  installs rules on the switch to block traffic from that port.
- **hping3** generates ICMP / UDP / SYN / land-attack floods (inside the virtual network only).

## Folder map
| Path | Purpose |
|---|---|
| `Codes/mininet/topology.py` | Builds the 6-switch / 18-host network, connects to remote Ryu controller (IP 192.168.0.101:6653 - edit it) |
| `Codes/mininet/generate_benign_trafic.py` | Normal traffic (ping/HTTP) between hosts, for the "0" label |
| `Codes/mininet/generate_ddos_trafic.py` (`...1.py`) | Starts a web server on h1 and runs hping3 floods |
| `Codes/controller/switch.py` | Basic learning switch (Ryu app) |
| `Codes/controller/start_traffic_collection.py` / `collect_benign...` | Collects benign flow stats, writes `FlowStatsfile.csv` (label 0) |
| `Codes/controller/collect_ddos_trafic.py` | Appends attack flow stats (label 1) to the same CSV |
| `Codes/controller/switchm.py` | Learning switch used by the detector |
| `Codes/controller/controller.py` | Detection controller: trains Random Forest, predicts every 10 s |
| `Codes/controller/mitigation_module.py` | Same + blocks the attacked port |
| `Codes/controller/ML.py`, `Codes/ml/*.py` | Compare LR, KNN, SVM, NB, DT, RF on the CSV (work on Windows) |
| `Installation_setup/Readme.md` | Author's VM setup notes |

## Tools by platform
| Tool | Windows native? | How to run |
|---|---|---|
| Python, pandas, scikit-learn, matplotlib | Yes | `venv` (below) |
| Mininet, Open vSwitch, hping3 | **No** (Linux kernel features) | WSL2 Ubuntu (recommended) or VirtualBox Ubuntu VM |
| Ryu controller | **No** (needs older Python; fails to build on 3.14) | Same Ubuntu, Python 3.9/3.10 venv |

Docker is not installed on this machine. WSL has no Linux distro installed yet.
WSL2 + Mininet/OVS can be fiddly (kernel modules); if it fails, use a VirtualBox VM
(the author's Mininet VM, see `Installation_setup/Readme.md`).

## A. Windows part (done on this machine, Python 3.14.2)
```powershell
cd "C:\Users\DELL\Desktop\kits projects\DDoS-Attack-Detection-and-Mitigation"
python -m venv venv
.\venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
```

## B. Linux part (WSL2 Ubuntu or VM) - one-time install
Installing WSL needs admin and a reboot, so do it yourself (PowerShell as admin):
```powershell
wsl --install -d Ubuntu-22.04
```
Inside Ubuntu:
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 python3-venv python3-pip git
# Ryu works best on Python <= 3.9; use pyenv or the deadsnakes PPA for 3.9
python3.9 -m venv ~/ryu-env && source ~/ryu-env/bin/activate
pip install "setuptools<58" "eventlet==0.30.2" ryu pandas scikit-learn
git clone https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation.git
```
(If Mininet and Ryu run in the same Ubuntu, use `127.0.0.1` as controller IP.)

## C. Run order (three terminals, all Ubuntu/WSL)
Edit the controller IP in `Codes/mininet/topology.py` first (`127.0.0.1` for a single machine).

**Phase 1 - build the dataset (`FlowStatsfile.csv` is NOT in the repo)**
1. Terminal 1 (controller): `cd Codes/controller && ryu-manager start_traffic_collection.py`
   (collects benign data; it creates/overwrites the CSV)
2. Terminal 2 (network): `cd Codes/mininet && sudo python3 topology.py`
3. Terminal 3 / Mininet CLI: run `generate_benign_trafic.py` logic, then stop Terminal 1.
4. Restart controller with `ryu-manager collect_ddos_trafic.py` (appends attack rows),
   then run `generate_ddos_trafic.py`.

**Phase 2 - detect and mitigate**
1. Terminal 1: `cd Codes/controller && ryu-manager controller.py`
   (or `mitigation_module.py` for detection + blocking). Run it in the same folder as the CSV.
2. Terminal 2: `cd Codes/mininet && sudo python3 topology.py`
3. Mininet CLI: `h1 ping h2`, or generate attack: `h5 hping3 -S -p 80 --flood 10.0.0.1`
   (only inside the simulated network).

**Compare ML models (Windows OK once the CSV exists)**
```powershell
copy path\to\FlowStatsfile.csv Codes\ml\
cd Codes\ml
..\..\venv\Scripts\python.exe RF.py
```

## Status
- [x] Repo cloned (branch `main`)
- [x] venv + pandas / scikit-learn / matplotlib installed
- [x] ML scripts compile; they stop at "FlowStatsfile.csv not found" (dataset missing)
- [ ] WSL distro / VM with Mininet, OVS, hping3 - not installed
- [ ] Ryu - cannot install on Windows / Python 3.14
- [ ] Generate dataset, then run detection

## Known issues in the code (not changed)
- `generate_ddos_trafic.py` uses `python -m SimpleHTTPServer` (Python 2). On Python 3 use
  `python3 -m http.server 80`.
- Code expects directories like `/home/mininet/webserver`.
- Pandas 3 may complain about `.str.replace('.', '')` regex behaviour; if so, use
  `.str.replace('.', '', regex=False)`. Ask before changing.
