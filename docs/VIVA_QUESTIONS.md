# Viva Questions and Answers

**Short on time? Prepare these 20 first:** 1, 5, 6, 7, 11, 12, 13, 14, 16, 17, 18, 20, 21, 25, 26, 27, 28, 29, 30, 35.

## Networking and attacks

**1. What is a DoS attack? How is DDoS different?**
A DoS attack tries to make a service unavailable. A DDoS attack does this from many machines at
once, so it is stronger and harder to block.

**2. Name some DDoS flood types in this project.**
ICMP flood, UDP flood, TCP SYN flood and LAND attack, generated with hping3 inside the virtual
network.

**3. What is a TCP SYN flood?**
The attacker sends many connection requests (SYN) and never completes the handshake. The server
keeps half-open connections until it runs out of resources.

**4. What is a flow?**
A group of packets with the same identifying fields: source IP, destination IP, ports and
protocol. A switch counts packets and bytes for each flow.

## SDN

**5. What is SDN?**
A network design that separates decision making (control plane) from packet forwarding (data
plane), so software controls the network centrally.

**6. What are the three layers of SDN?**
Application, control and infrastructure.

**7. What is OpenFlow?**
The protocol between the controller and the switches. It installs flow rules and requests
statistics. The project uses version 1.3.

**8. What are Ryu, Mininet and Open vSwitch?**
Ryu is an SDN controller framework in Python. Mininet creates a virtual network of hosts and
switches on one Linux computer. Open vSwitch is the software switch.

**9. How does the controller get statistics?**
Every 10 seconds it sends a flow statistics request to each switch and receives a reply with
the counters.

**10. How does a flow rule drop traffic?**
It matches packets and has an empty action list. Its priority is higher than the forwarding
rules, and a timeout removes it later.

## Machine learning

**11. Which type of problem is this?**
Supervised binary classification: normal (0) or DDoS (1).

**12. Why Random Forest?**
It handles numeric features without scaling, models non-linear patterns, resists overfitting
better than one tree, is fast to predict and shows feature importance.

**13. How does Random Forest work?**
It trains many decision trees on random samples of the data and features. The class with the
most votes (average probability) wins.

**14. Which five models were compared?**
Random Forest, Decision Tree, Logistic Regression, K-Nearest Neighbors and Support Vector
Machine.

**15. Why do some models need scaling?**
KNN, SVM and Logistic Regression are affected by the size of numbers. Byte counts would
dominate small features such as the protocol.

**16. What are precision and recall?**
Precision: of the flows called DDoS, the share that really are. Recall: of the real DDoS flows,
the share that were found.

**17. Why is accuracy not enough?**
If 99 % of traffic is normal, a model that always says "normal" has 99 % accuracy and finds no
attack.

**18. What is a confusion matrix?**
A table of actual against predicted classes: true negatives, false positives, false negatives
and true positives.

**19. Which error is worse here?**
A missed attack (false negative) lets the attack continue. A false alarm (false positive) can
block a real user. Both matter; the balance depends on the network.

**20. What is data leakage?**
When the model receives information during training that it will not have in real use, which
makes test scores look better than reality.

**21. Where could leakage happen here and how is it prevented?**
The timestamp and IP addresses reveal when and where the lab attack ran, so they are not
features. Rows of one flow stay on one side of the split. Scaling and filling are learnt from
training data only.

**22. What is cross-validation?**
The training data is divided into parts (folds). The model is trained on some and tested on the
rest, several times, and the scores are averaged. We use 3 folds to choose the best model.

**23. How are results made reproducible?**
A fixed random seed and fixed library versions.

**24. How is the model saved?**
With joblib, together with the feature list, library version and data source. Loading checks
them. Pickle files from unknown people must never be loaded.

**25. What does the model confidence mean?**
The average vote of the trees for DDoS. It shows agreement between trees. It is not a
calibrated probability.

## This project

**26. Why is your accuracy 100 %? Is it real?**
It is not a real-world result. The data is synthetic and the two classes use number ranges that
do not overlap. It only shows that the pipeline works.

**27. Why did you use synthetic data?**
The real dataset was not in the repository. The dashboard accepts a real CSV when one is
collected.

**28. How is an attack decided for a window?**
If 80 % or less of the flows in the 10-second window are predicted normal.

**29. How is the victim found?**
The destination address that receives the most flagged flows in an attack window.

**30. Is your mitigation real?**
No. The dashboard installs rules in a simulator and counts recorded flows that would match. It
shows the command a real controller would send.

**31. What does the original mitigation code do?**
After detecting an attack it blocks the switch port that sends packets with a source address
never seen in ARP on that port, for 120 seconds.

**32. Why does the dashboard use a different rule?**
The CSV files have no port or ARP information, so it uses source, destination and protocol.

**33. What bug did you fix in the original controller?**
It used the predicted label (0 or 1) as the row number when reading the victim address, so it
read the wrong row. It now uses the row of the flagged flow.

**34. What is collateral damage in mitigation?**
Normal traffic that a rule blocks. In the synthetic replay 31 of 4,431 normal flows matched a
rule.

**35. What are the main limitations?**
Synthetic data, simulated mitigation, no live capture, two classes only, and source-based rules
that cannot stop random spoofing.

**36. What would you do next?**
Collect real data in Mininet, test on a different session, connect a Ryu controller through the
controller interface and add attack-type classification.

**37. Why Streamlit?**
It builds an interactive web dashboard in Python only, which suits a small data project.

**38. How did you test the project?**
39 automated tests of the engine and pages, a browser test of pages, uploads and mitigation,
and a large-file test. The Linux SDN lab was not tested.
