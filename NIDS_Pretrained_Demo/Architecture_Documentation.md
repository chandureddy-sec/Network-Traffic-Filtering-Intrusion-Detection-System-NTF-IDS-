# Zero-Day Network Intrusion Detection System (NIDS)
## Architecture & Project Documentation

### 1. Project Overview
This project is an end-to-end **Network Intrusion Detection System (NIDS)** designed to simulate real-time, deep-packet inspection using Machine Learning. Unlike traditional rule-based firewalls, this system relies on AI to identify anomalies. By understanding the signature of "normal" safe traffic, it is fully capable of capturing **Zero-Day Attacks** (threats that have never been seen or categorized before).

---

### 2. High-Level Architecture
The project follows a standard **Three-Tier Architecture** consisting of an AI Engine (Model), a Backend Application (API Server), and a Frontend Web Client (User Interface).

```mermaid
graph TD;
    A[Frontend Dashboard<br/>index.html] -->|GET /api/scan_next| B(Flask Backend<br/>app.py);
    B -->|Reads Packet Row| C[(test_traffic.csv)];
    B -->|Predict Packet Features| D{Pre-Trained AI<br/>pretrained_model.pkl};
    D -->|Returns: 0 (Safe) / 1 (Threat)| B;
    B -->|JSON Response| A;
```

---

### 3. Core Components 

#### A. The AI Engine (`pretrained_model.pkl`)
- **Technology**: Built using Python's `scikit-learn`.
- **Algorithm**: **Random Forest Classifier**.
- **Dataset**: Trained on a subset of the famous **KDD Cup 99 Dataset**.
- **Role**: This file holds the mathematical "brain" of the operation. It was trained offline, meaning the system doesn't need to rebuild or learn during execution. It loads the "weights" instantly into memory and waits for raw network features to classify them as either `Safe` or `Threat`.

#### B. The Traffic Buffer (`test_traffic.csv`)
- **Role**: In an enterprise firewall, packets stream over internet cables via PCAP (Packet Capture) buffers. For this college project, we simulate that live cable using a CSV file containing 50 intercepted connections.
- Each time the Dashboard requests a packet, the backend reads the next row in this file, pulling out its digital signature (features like ping length, protocol type, payload size) to scan it.

#### C. The Backend API Server (`app.py`)
- **Technology**: Python **Flask**.
- **Role**: The RESTful API that connects the AI to the Web Browser.
- **Workflow**:
  1. On startup, Flask loads `pretrained_model.pkl` to memory.
  2. When a user navigates to `localhost:5000`, it serves `index.html`.
  3. When `index.html` calls `/api/scan_next`, Flask runs `model.predict()` on the pending packet and replies with a clean JSON output containing the result.

#### D. The Frontend UI (`templates/index.html`)
- **Technology**: Vanilla HTML, Native CSS, JavaScript (No heavy frameworks).
- **Aesthetics**: Styled using modern **Glassmorphism** against a dark-mode thematic background.
- **Role**: A responsive operator dashboard. When the user clicks **"Start Live Analysis"**, a JavaScript recursive loop (using `fetch()`) constantly pings the Backend Server simulating real-time internet traffic scanning. It dynamically updates tracking metrics (Total, Safe, Blocked) based on the AI’s real-time decisions.

---

### 4. Technical Execution Flow
1. **Boot**: The user runs `python app.py`. The Flask interpreter starts locally on `PORT 5000`.
2. **Access**: The user opens the dashboard in the browser. 
3. **Execution**: The user presses the glowing  <kbd>Start Live Analysis</kbd> button.
4. **The Loop**: 
   - Javascript calls `GET /api/scan_next`
   - Flask feeds array `[0.34, 1.22, 0.00...]` to the `pretrained_model.pkl`.
   - The model votes. If it classifies it as malicious (`Prediction == 1`), Flask sets `is_threat = true`.
   - Javascript parses the JSON and injects a flashing red row `[X] ALARM: MALICIOUS ANOMALY DETECTED` into the main UI log.
5. **Conclusion**: The loop continues until all 50 packets inside the traffic buffer are exhausted.

---

### 5. Educational Value (Zero-Day Emulation)
This project perfectly demonstrates how modern cybersecurity works securely. Because the model relies on generalized anomaly feature sets rather than specifically hardcoded IP bans or virus definitions, it effectively performs **Zero-Day detection**—flagging packets as dangerous simply because their behavior deviates maliciously from the standard learned normal traffic baseline.
