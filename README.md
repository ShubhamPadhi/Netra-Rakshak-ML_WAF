# 🛡️ Netra-Rakshak: AI-Driven Hybrid WAF
### Naval Innovathon 2025 Submission
**Theme:** Artificial Intelligence | **Project:** Intelligent Web Application Firewall

---

## 📖 Project Overview
**Netra-Rakshak** is a next-generation Web Application Firewall designed to protect naval and defense infrastructure from both known cyber threats and unknown **Zero-Day anomalies**.

Unlike traditional WAFs that rely solely on static signatures, Netra-Rakshak employs a **Hybrid Engine** combining:
1.  **Rule-Based Filter:** Instantly blocks known signatures (SQLi, XSS, Path Traversal).
2.  **Machine Learning (Isolation Forest):** Unsupervised learning to detect statistical anomalies in "never-before-seen" attacks.
3.  **EWMA Reputation System:** A "Memory" layer that tracks IP behavior over time, preventing **Low-and-Slow** attacks that bypass single-request checks.
4.  **Adaptive Feedback Loop:** A human-in-the-loop system where administrators can whitelist false positives, triggering **instant retraining** of the AI model.

---

## 🚀 How to Run the Project
We have containerized the entire solution for a one-step deployment.
### 1. Clone the Repository
Open your terminal and run the following commands:
```bash
git clone https://github.com/ShubhamPadhi/Netra-Rakshak-ML_WAF.git
cd Netra-Rakshak-ML_WAF
# Only run this if your docker-compose.yml is inside this subfolder:
# cd ML-WAF_Netra-Rakshak  <-- LIKELY NOT NEEDED, BUT CHECK GITHUB
```
### 2. Build and Launch
Open your terminal in the project root and run:
```bash
docker-compose up --build
```
### 3. Access the Dashboard
Once the server is running, access the real-time monitoring dashboard via your browser:

👉 **Dashboard URL:** [http://localhost:8501](http://localhost:8501)
👉 **Backend API:** [https://localhost:5000](https://localhost:5000)

> **Important Security Note:** Since this project uses self-signed SSL certificates for security simulation, your browser will warn you ("Your connection is not private").
> **Action:** Click **"Advanced"** -> **"Proceed to localhost (unsafe)"**.

---

## Configuration & Best Practices

### Recommended Threshold: `0.5`
For the best balance between security and usability, **keep the Blocking Threshold at 0.50**.

* **Why 0.5?** This setting effectively filters out anomalies without disrupting normal user traffic.
* **Risk of Lowering (< 0.4):** While lowering the threshold makes the AI extremely sensitive to **Zero-Day anomalies**, it drastically increases the **False Positive Rate**. This means valid, complex requests (like large data uploads) might be blocked. Only lower this if the system is under an active, high-intensity siege.

---

##  How to Test (Attack Simulation)
We have included a testing script inside the container to simulate various traffic patterns.

1.  **Find your Container ID:**
    ```bash
    docker ps
    ```
2.  **Run the Test Suite:**
    Run the following command (replace `<Container ID>` with your actual ID):
    ```bash
    docker exec -it <Container ID> bash -c "cd backend && python test.py"
    ```

**What happens next?**
Check the Dashboard at `http://localhost:8501`. You will see live logs appearing as the script simulates Normal Traffic, XSS Attacks, SQL Injections, and High-Entropy Zero-Day Anomalies.

> **Note:** The model is already trained on dataset hence no need to train again.
---

## 🧠 The Architecture (Algorithm Explained)

Netra-Rakshak uses a **Multi-Layered Defense Strategy** to ensure no attack slips through.

### Layer 1: The Rule Engine (Speed & Known Threats)
* **Algorithm:** Regex & Keyword Matching.
* **Function:** Checks for obvious signatures (e.g., `UNION SELECT`, `<script>`).
* **Outcome:** If matched, the request is blocked immediately with a score of **1.0**.

### Layer 2: Isolation Forest (Intelligence & Zero-Days)
* **Algorithm:** Unsupervised Anomaly Detection (Sklearn).
* **Function:** It builds a statistical profile of "Normal Traffic" based on Payload Size, Entropy (randomness), and Request Rate.
* **Logic:** Instead of looking for specific attacks, it looks for *deviations*. If a request is statistically "rare" (e.g., a mathematical formula with high entropy), it is flagged as an anomaly.

### Layer 3: EWMA Reputation System (Memory)
* **Algorithm:** Exponential Weighted Moving Average.
* **Function:** Tracks the behavior of an IP address over time.
* **Logic:** A user doesn't get blocked just for one mistake. However, if an IP generates consistent anomalies, their "Reputation Score" rises. This prevents "Low-and-Slow" attacks.

### Layer 4: Hybrid Voting Mechanism (The Consensus)
* **Algorithm:** Weighted Ensemble Scoring.
* **Function:** The final decision is not made by one layer alone. The system calculates a weighted consensus:
  > `Final_Score = (Rule_Score * 0.5) + (ML_Reputation_Score * 0.5)`
* **The Logic:**
  * **Known Attacks** trigger the Rule Engine instantly.
  * **Unknown Attacks** raise the ML Score.
  * **Hybrid Attacks** (Complex attacks) trigger both, resulting in the highest possible risk score.
  * The request is blocked **only if the Combined Score > 0.50**.

---

## 📊 Understanding Attack Classifications

When you view the dashboard, you will see three types of classifications. Here is how to interpret them:

| Classification | Meaning | Why? |
| :--- | :--- | :--- |
| **Known Attack** | Signature Match | The payload contained a banned keyword (e.g., `admin' --`). |
| **Zero-Day Anomaly** | ML Detection | The payload looked weird (High Entropy/Length) but matched no known rules. |
| **Hybrid Attack** | **Highest Danger** | The attack triggered **BOTH** a Rule match AND an ML Anomaly. |

> **Note on Hybrid Attacks:** You will see many known attacks classified as **"Hybrid Attack"**. This is expected behavior!
>
> *Reason:* A massive SQL Injection payload is both "Forbidden" (Rule match) AND "Statistically Unusual" (ML match). This double confirmation gives us 100% confidence to block the request.

---

## 🔄 The Feedback Loop (Demo Feature)
1.  If a legitimate request (e.g., a complex math formula) is blocked as an **Anomaly**.
2.  The Admin clicks **"Mark as Safe"** on the dashboard.
3.  **Action:**
    * The payload hash is **Whitelisted** (Instant access).
    * The EWMA Score for that IP is **Reset to 0.0** (Instant unblock).
    * The ML Model **Retrains** in the background on this new data (Long-term learning).

---

### 👨‍💻 Contributors
* **Shubham Padhi** - AI & Backend Logic
