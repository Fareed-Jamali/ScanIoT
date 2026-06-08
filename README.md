# ScanIoT

ScanIoT is a traffic collection tool that provides a Flask-based web application for network monitoring. While it is primarily designed to capture traffic from IoT devices within a smart home environment, it can also be used to monitor traffic from any connected device. ScanIoT operates as an access point, allowing all network traffic to pass through it for inspection and capture.



**Overview**
ScanIoT is a modular IoT security research platform designed to capture network traffic and generate the quality dataset for machine-learning algorithms for device fingerprinting. It combines:
* Backend data processing pipeline (Python)
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
│   ├── capture_progress
│   ├── dashboard
│   └── login
│   
│
├── static/                 # Frontend assets
│   ├── css/
│   └── js/
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

To install the requirements
<pre> pip install -r requirements.txt </pre>

**Running the System**
Start full pipeline, including dashboard

<pre> python main.py </pre>

Then open:

<pre> http://127.0.0.1:5000 </pre>

**Use Cases**
The system is designed as a lightweight and portable network traffic collection tool with a wide range of additional use cases.
* Smart home security monitoring
* Network traffic behavior analysis
* Academic research in cybersecurity

**Disclaimer**
ScanIoT is intended strictly for educational and research purposes only.
Users must ensure compliance with all applicable laws and privacy regulations when capturing network traffic.


The provided code is tailored for deployment on a Raspberry Pi, developed using Visual Studio with a virtual environment setup. All necessary dependencies and setup details are listed in the requirements.txt file.

After activating the virtual environment, to run the code use:

<pre> sudo myenv/bin/python3 app.py </pre>

For **citation** purposes, use following:
Jamali, A.F. and Fung, C., 2024, October. ScanIoT, an Application to collect IoT dataset for HomeGuard. In 2024 7th Conference on Cloud and Internet of Things (CIoT) (pp. 1-2). IEEE.

Jamali, A.F., Rostami, D. and Fung, C., 2025, September. IoT Device Identification using Deep Learning. In 2025 16th International Conference on Network of the Future (NoF) (pp. 46-54). IEEE.
