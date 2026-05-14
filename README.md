# Network Anomaly Detection Dashboard

A real-time network packet monitoring and anomaly detection dashboard built with Python, Flask, Scapy, and Machine Learning. This project captures live network traffic, analyzes packet behavior using a pretrained ML model, and visualizes suspicious activity through a web dashboard.

---

## Features

- Real-time packet capture using Scapy
- Machine Learning-based anomaly detection
- Flask-powered web dashboard
- Live packet statistics
- Protocol distribution analytics
- Threat classification (Low / Medium / High)
- PCAP upload and offline analysis
- Export captured traffic as PCAP
- Packet trend visualization
- Top suspicious IP tracking
- Time-series packet behavior analysis

---

## Technologies Used

- Python 3
- Flask
- Scapy
- NumPy
- Scikit-learn
- Joblib
- HTML/CSS/JavaScript
- Machine Learning

---

## Project Structure

```text
project/
│
├── app.py
├── pretrained_model.pkl
├── capture_session.pcap
├── templates/
│   └── index.html
├── static/
│   ├── css/
│   ├── js/
│   └── assets/
└── README.md
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/your-username/network-anomaly-dashboard.git
cd network-anomaly-dashboard
```

---

### Create Virtual Environment

```bash
python -m venv venv
```

Activate environment:

#### Linux/macOS

```bash
source venv/bin/activate
```

#### Windows

```bash
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install flask scapy numpy scikit-learn joblib
```

---

## Install Npcap (Windows Only)

For live packet capture on Windows:

- Install Npcap
- Enable:
  - WinPcap Compatibility Mode
  - Packet Capture Support

Run terminal or VS Code as Administrator.

---

## Run the Application

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000
```

---

## Machine Learning Model

The project uses a pretrained anomaly detection model loaded from:

```text
pretrained_model.pkl
```

The model processes:

- Packet size
- Protocol type
- Traffic variance
- Sequential packet behavior
- Time-series aggregated features

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/api/interfaces` | GET | List available interfaces |
| `/api/start_capture` | POST | Start live packet capture |
| `/api/stop_capture` | POST | Stop capture |
| `/api/live_scan` | GET | Get live statistics |
| `/api/get_packets` | GET | Fetch packet logs |
| `/api/analytics` | GET | Analytics and trends |
| `/api/upload_pcap` | POST | Analyze uploaded PCAP |
| `/api/download_pcap` | GET | Download captured PCAP |

---

## Threat Classification

### Low Risk
Normal traffic patterns with expected behavior.

### Medium Risk
Suspicious packet patterns or unusual communication behavior.

### High Risk
Potential malicious activity such as:
- Port scanning
- Flooding attacks
- Protocol abuse
- Abnormal traffic spikes

---

## Live Capture

The system captures:
- TCP packets
- UDP packets
- ICMP traffic
- IP metadata
- Source/Destination ports
- Packet length

---

## PCAP Analysis

Upload `.pcap` files for offline threat analysis.

Supported features:
- Batch packet processing
- Threat scoring
- Risk analytics
- Suspicious IP identification

---

## Example Workflow

1. Start packet capture
2. Generate network traffic
3. View live dashboard updates
4. Analyze suspicious packets
5. Export PCAP for forensic analysis

---

## Future Improvements

- Deep Learning (LSTM/Transformer) models
- Real intrusion detection signatures
- GeoIP visualization
- Threat intelligence integration
- WebSocket live updates
- Docker deployment
- Authentication system
- SIEM integration

---

## Security Notes

- Run with administrator/root privileges for packet capture.
- Use only in authorized environments.
- This tool is intended for educational and defensive security purposes.

---

## Screenshots

Add screenshots here:

```text
screenshots/dashboard.png
screenshots/analytics.png
```

---

## License

MIT License

---

## Author

Developed by Chandu

Cybersecurity | Network Security | Machine Learning

---

## Disclaimer

This project is intended strictly for:
- Educational purposes
- Research
- Authorized network monitoring

Unauthorized packet interception may violate laws or organizational policies.
