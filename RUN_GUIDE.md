# Run Guide (Windows)

## What this project is
An SDN lab: Mininet simulates a network, a Ryu controller collects flow statistics every
10 s, machine learning classifies flows as normal (0) or DDoS (1), and a mitigation step
blocks attack traffic. On Windows you run the **web dashboard** (simulation); the live network
parts need Linux.

## Versions
- Python 3.14.2.
- Pinned in `requirements.txt`: pandas 3.1.1, scikit-learn 1.9.1, matplotlib 3.11.2,
  numpy 2.5.5, joblib 1.6.0, streamlit 1.67.0, plotly 7.1.0.
- Original (unpinned) file kept as `requirements_old.txt`.

## Web dashboard - http://localhost:8501
Run these in the project folder (the folder that contains this file):
```powershell
python -m venv venv                  # only if venv\ does not exist yet
.\venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt      # only the first time
streamlit run dashboard\app.py       # stop with Ctrl + C
```
If the dashboard was started in the background and you need to stop it:
```powershell
Get-NetTCPConnection -LocalPort 8501 -State Listen |
  ForEach-Object { Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" } |
  Select-Object ProcessId, CommandLine      # check that it is "streamlit run dashboard/app.py"
Stop-Process -Id <ProcessId>
```

## Command line tools and tests
```powershell
python -m ddos sample  --out data
python -m ddos train   --data data\synthetic_FlowStatsfile.csv --out models\random_forest.joblib
python -m ddos predict --model models\random_forest.joblib --data data\synthetic_monitor.csv
python -m unittest discover -s tests -t .
```

## Original ML scripts
They read `FlowStatsfile.csv` from the folder you run them in:
```powershell
cd data
copy synthetic_FlowStatsfile.csv FlowStatsfile.csv   # or put your real file here
python ..\Codes\ml\RF.py             # Random Forest result + confusion matrix + chart
python ..\Codes\ml\ML.py             # compare LR, KNN, NB, DT, RF
```
Close a chart window to let the script finish. These scripts use identifier columns as
features, so their scores differ in method from the dashboard's.

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
Ubuntu VM instead. **None of this has been run or verified on this machine.**

## Public link options (nothing is deployed)
| Option | Needs | Notes |
|---|---|---|
| Streamlit Community Cloud | GitHub account + pushed repo (free account) | Remove `address = "localhost"` from `.streamlit/config.toml` |
| ngrok / cloudflared tunnel | Free account/binary | Temporary link to your PC; only while it runs |

The dashboard has no login. Do not expose it publicly with private data.
