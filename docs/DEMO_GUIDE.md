# Demonstration Guide (about 10 minutes)

## Before the viva

1. In the project folder: `.\venv\Scripts\Activate.ps1`, then `streamlit run dashboard\app.py`.
2. Open <http://localhost:8501>. Internet is not needed after installation.
3. Open each page once so the models are already trained.
4. Create demo files: `python -m ddos sample --out data`.
5. For the invalid-file demo, open `data\synthetic_FlowStatsfile.csv` in a text editor or
   Excel, delete the `packet_count` column and save it as `data\broken.csv`.
6. Do not refresh the browser during the demo: a refresh clears uploads, rules and the log.

## Opening statement

"This project detects DDoS attacks from SDN flow statistics with machine learning and shows how
a controller would respond. The data you will see is synthetic and the mitigation is simulated."

Say this **first**. It is much better than being asked.

## Steps

| Min | Page | Do | Say |
|---|---|---|---|
| 1 | About Project -> Architecture | Show both diagrams | Three SDN layers; where our modules sit |
| 2 | Overview Dashboard | Point at totals and timeline | 6,000 flows, 1,569 flagged, attack period windows 20-35 |
| 3 | Live DDoS Detection | Window 25 (default) | 109 flows, 17 % legitimate, below 80 % -> attack, victim h1 |
| 4 | same | Slide to window 5 | 107 flows, 96 % legitimate -> normal |
| 5 | same | Press *Next attack window* | Detection starts at window 20 |
| 6 | Machine Learning Models | Chart, table, confusion matrix | Five models; why scores are high; features left out |
| 7 | Network Traffic Dataset -> Upload CSV | Upload `broken.csv`, then the good file | Validation protects the model; nothing is invented |
| 8 | Attack Mitigation -> Respond | Set the slider to window 25, then press *Install* | 76 rules for window 25 (simulated) |
| 9 | Active rules | Show the command and Ryu message | "Not executed" - what a real controller would send |
| 10 | Timeline replay, Event log | Run replay | 59 % of attack flows matched, 31 normal flows too |

After step 7, press **Return to the synthetic sample** (tab *Current data*) so that the numbers
in the table above apply again. Changing data clears rules and the log.

## Honest answers to likely challenges

- **"Is 100 % accuracy realistic?"** No. The synthetic classes do not overlap. The page shows
  the ranges. We have no real-world accuracy figure.
- **"Is it blocking traffic now?"** No. It is a simulator. The interface is ready for a real
  controller, which is future work.
- **"Why is window 35 an attack when the burst ends at 34?"** Arrival times are random, and
  about half of window 35 is labelled attack in this sample.
- **"Why does the replay miss many attack flows?"** A rule is created only after a flow group
  has been detected.

## If something goes wrong

| Problem | Fix |
|---|---|
| `Activate.ps1` is blocked | `Set-ExecutionPolicy -Scope Process Bypass` |
| Port 8501 in use | `streamlit run dashboard\app.py --server.port 8502` |
| Theme looks white | Start the command from the project folder |
| `No module named streamlit` | Activate `venv`, then `pip install -r requirements.txt` |
| Odd state after many clicks | Refresh the browser (resets to the synthetic sample) |
