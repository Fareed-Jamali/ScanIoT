# ScanIoT

ScanIoT
Intelligent IoT Traffic Monitoring, Feature Extraction & Dataset Generation Platform




**Overview**
ScanIoT is a modular IoT security research platform designed to capture network traffic, process it into structured features, and generate machine-learning-ready datasets.
It combines:
* Backend IoT data processing pipeline (Python)
* Web-based visualization interface (HTML templates + static assets)
* Dataset generation for ML/AI-based device fingerprinting

The system is designed for research in:
* Smart home security
* IoT anomaly detection
* Network traffic analysis
* Behavioral profiling of IoT devices

**System Architecture**
<pre>
IoT Devices / Network Traffic
            │
            ▼
   Packet Capture Layer
   (tcpdump / scapy / sockets)
            │
            ▼
   Preprocessing Engine
   ├── Traffic filtering
   └── Flow reconstruction
            │
            ▼
   Dataset Generator
   ├── CSV export
   └── ML-ready labeling
            │
            ▼
   Web Interface Layer
   ├── templates/ (HTML views)
   └── static/ (CSS / JS / assets)
            │
            ▼
   Visualization Dashboard
   ├── Traffic insights
   └── Device behavior
</pre>

**Project Structure**
<pre>
ScanIoT/
│
│
├── templates/              # Web UI HTML templates (dashboard/views)
│   ├── index.html
│   ├── dashboard.html
│   ├── analytics.html
│   └── layout templates
│
├── static/                 # Frontend assets
│   ├── css/
│   ├── js/
│   ├── images/
│
├── app.py                 # Main pipeline entry point
├── requirements.txt       # List of requirements
└── README.md
</pre>
            
**Web Dashboard**
ScanIoT includes a lightweight web interface for visualizing IoT network behavior.
Features of /templates + /static layer:
* Real-time traffic visualization
* IoT device activity monitoring
* Interactive dashboard UI

**Tech Stack**
HTML5 (Jinja2-compatible structure if Flask is used)
CSS3 (UI styling)
JavaScript (interactive charts / frontend logic)
Optional: Chart.js / D3.js

**Installation**
requirements: Python 3.8+, pip, tcpdump / libpcap (for traffic capture) Setup
 <pre>
git clone https://github.com/Fareed-Jamali/ScanIoT.git
cd ScanIoT
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
 </pre>

pip install -r requirements.txt
▶️ Running the System
1. Start full pipeline
python main.py
2. Start web dashboard (if Flask-based)
python app.py
Then open:
http://127.0.0.1:5000
📊 Output Dataset Format
Generated datasets include structured IoT traffic features:
Feature	Description
timestamp	Packet arrival time
src_ip	Source device IP
dst_ip	Destination IP
protocol	Network protocol
packet_size	Packet size in bytes
flow_duration	Session duration
bytes_sent	Traffic volume
label	Normal / Anomalous / Device class
Output location:
dataset/iot_dataset.csv
🔬 Use Cases
IoT Intrusion Detection Systems (IDS)
Smart home security monitoring
Machine learning dataset generation
Network traffic behavior analysis
Academic research in cybersecurity
🧩 Key Features
Real-time IoT traffic capture
Modular preprocessing pipeline
Feature extraction engine
ML-ready dataset generation
Web-based visualization dashboard
Clean separation of backend & frontend layers
🧠 Future Enhancements
Real-time streaming dashboard (WebSockets)
Deep learning-based anomaly detection
Multi-device IoT simulation support
Cloud integration (AWS / GCP)
Encrypted traffic analysis support
Role-based dashboard authentication
⚠️ Disclaimer
ScanIoT is intended strictly for educational and research purposes only.
Users must ensure compliance with all applicable laws and privacy regulations when capturing network traffic.

ScanIoT is a traffic collection tool that provides a Flask-based web application for network monitoring. While it is primarily designed to capture traffic from IoT devices within a smart home environment, it can also be used to monitor traffic from any connected device. ScanIoT operates as an access point, allowing all network traffic to pass through it for inspection and capture.

The provided code is tailored for deployment on a Raspberry Pi, developed using Visual Studio with a virtual environment setup. All necessary dependencies and setup details are listed in the requirements.txt file.

After activating the virtual environment, to run the code use:

<pre> sudo myenv/bin/python3 app.py </pre>

For citation purposes, use following:
Jamali, A.F. and Fung, C., 2024, October. ScanIoT, an Application to collect IoT dataset for HomeGuard. In 2024 7th Conference on Cloud and Internet of Things (CIoT) (pp. 1-2). IEEE.
