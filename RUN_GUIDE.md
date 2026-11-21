# Run Guide (Windows)

## What this project is
An SDN lab: Mininet simulates a network, a Ryu controller collects flow statistics every
10 s, a Random Forest (scikit-learn) classifies flows as normal (0) or DDoS (1), and the
mitigation module blocks the attacked port. **There is no web interface** - it is
command-line / SDN based. The only parts that run on Windows are the ML scripts in `Codes/ml`.

## Versions
- Python 3.14.2 (works; no older Python needed for the ML scripts).
- Pinned in `requirements.txt`: pandas 3.1.1, scikit-learn 1.9.1, matplotlib 3.11.2, numpy 2.5.5.
- Original (unpinned) file kept as `requirements_old.txt`.

## Start again next time (PowerShell)
```powershell
cd "C:\Users\DELL\Desktop\kits projects\DDoS-Attack-Detection-and-Mitigation"
git switch update-packages
python -m venv venv                  # only if venv/ does not exist yet
.\venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
# put your FlowStatsfile.csv in the folder you run from, then:
python Codes\ml\RF.py                # Random Forest result + confusion matrix + chart
python Codes\ml\ML.py                # compare LR, KNN, NB, DT, RF
```
Close a chart window to let the script finish. Stop anything running with Ctrl + C.
`FlowStatsfile.csv` is not in the repo; you create it in Linux (see below) or supply your own.

## Linux-only parts (Mininet, Open vSwitch, hping3, Ryu) - run in WSL2
In PowerShell as Administrator (then reboot): `wsl --install -d Ubuntu-22.04`
Inside Ubuntu:
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 python3-venv python3-pip git
# Ryu needs Python <= 3.9: install 3.9 (deadsnakes PPA / pyenv), then
python3.9 -m venv ~/ryu-env && source ~/ryu-env/bin/activate
pip install "setuptools<58" "eventlet==0.30.2" ryu pandas scikit-learn
```
Run order: see section C of `SETUP_WINDOWS.md` (collect benign data -> collect attack data ->
`ryu-manager controller.py` + `sudo python3 topology.py`). Use `127.0.0.1` as the controller IP
in `Codes/mininet/topology.py`. If WSL2 lacks Open vSwitch kernel modules, use a VirtualBox
Ubuntu VM instead.

## Public link options (nothing is deployed yet)
Only relevant if a web dashboard is added.
| Option | Needs | Notes |
|---|---|---|
| Streamlit Community Cloud | GitHub account + pushed repo (free account) | Permanent link for a Streamlit app |
| Render | Account, Flask/Gunicorn app, GitHub repo | Free tier sleeps when idle |
| ngrok / cloudflared tunnel | Free account/binary | Temporary link to your PC; only while it runs |

## What changed on this branch
- `Codes/ml/*.py`: matplotlib style `seaborn-darkgrid` renamed to
  `seaborn-v0_8-darkgrid` (old name removed in matplotlib 3.8; same look).
- `requirements.txt` pinned; `.gitignore` added (venv, caches, CSVs).

## Status
Working: venv, pinned packages (`pip check` clean), all `Codes/ml` scripts run on a synthetic
CSV in the real column format (accuracy numbers from that test are NOT real results).
Not working / not run: Ryu controller, Mininet, hping3 (need Linux), real dataset (missing),
web dashboard (not built yet).
