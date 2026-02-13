# CyberShield AI - Cyber Defense System

Welcome to **CyberShield AI**, a comprehensive cybersecurity framework featuring machine learning-powered threat detection, network monitoring, and incident response capabilities.

## 🛡️ Core Features

### 1. **AI-Powered Threat Detection**
- **Anomaly Detection**: Isolation Forest algorithm detects unusual security patterns
- **Intrusion Detection**: Random Forest classifier identifies attack signatures
- **Threat Classification**: Multi-level severity assessment (Safe → Critical)
- **Real-time Analysis**: Immediate threat evaluation with confidence scoring

### 2. **Network Security Monitoring**
- **DDoS Detection**: Volumetric and flood attack identification
- **Port Scan Detection**: Identifies reconnaissance activity
- **Brute Force Detection**: Login attempt anomaly tracking
- **Traffic Analysis**: Real-time bandwidth and connection monitoring

### 3. **Password Security**
- **Strength Analysis**: Entropy calculation and weakness detection
- **Dictionary Matching**: Identifies common weak passwords
- **Scoring System**: 0-6 comprehensive strength rating

### 4. **Web Dashboard**
- **Real-time Monitoring**: Live threat visualization
- **Event Logging**: Complete security event history
- **Emergency Controls**: Lockdown capability for critical situations
- **Custom Analysis**: On-demand security scanning

---

## 📋 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager
- 2GB RAM minimum
- Network access for external threat intelligence updates

### Step 1: Install Dependencies

```bash
cd cyberDefense
pip install -r requirements.txt
```

**Dependencies installed:**
- numpy, pandas - Data processing
- scikit-learn - Machine learning models
- tensorflow/keras - Deep learning
- Flask - Web framework
- Scapy - Network packet analysis
- psutil - System monitoring
- cryptography - Security operations

### Step 2: Configure Environment (Optional)

Create `.env` file in the project root:
```
THREAT_THRESHOLD=50
API_KEY=your_api_key_here
LOG_LEVEL=INFO
```

---

## 🚀 Quick Start

### Method 1: Web Dashboard

```bash
python dashboard.py
```

Then open **http://localhost:5000** in your browser.

**Dashboard Features:**
- 🎯 Real-time threat level display
- 📊 System health and performance metrics
- 📝 Live security event log
- 🔐 Password strength analyzer
- 🔒 Emergency lockdown button
- 📈 Threat statistics and trends

### Method 2: Command Line Usage

```python
from cyber_shield import CyberShield

# Initialize the system
shield = CyberShield("MyShield")

# Analyze a security event
event = {
    'source_ip': '192.168.1.100',
    'destination_ip': '10.0.0.1',
    'port': 443,
    'payload': 'GET / HTTP/1.1',
    'protocol': 'TCP',
    'payload_size': 256,
    'flag_count': 2,
    'duration': 120,
    'src_bytes': 1024,
    'dst_bytes': 2048,
}

result = shield.analyze_security_event(event)
print(f"Threat Level: {result['threat_level']}")
print(f"Threat Score: {result['threat_score']}")

# Generate report
report = shield.generate_security_report()
print(report)
```

### Method 3: Network Monitoring

```python
from network_monitor import NetworkSecurityMonitor, NetworkPacket

monitor = NetworkSecurityMonitor()

# Simulate network traffic
packet = NetworkPacket(
    timestamp=time.time(),
    source_ip='192.168.1.100',
    dest_ip='8.8.8.8',
    source_port=54321,
    dest_port=53,
    protocol='UDP',
    size=128,
    flags=0
)

# Analyze packet
alerts = monitor.analyze_packet(packet)
for alert in alerts:
    print(f"ALERT: {alert}")
```

---

## 🔬 ML Model Training

The system comes with pre-trained models, but you can train on custom datasets:

```python
from cyber_shield import CyberShield
import pandas as pd

shield = CyberShield("CustomShield")

# Load your security event dataset
dataset = pd.read_csv('security_events.csv')

# Train all models
shield.train_on_dataset(dataset)

# Save trained models (optional)
import pickle
with open('trained_models.pkl', 'wb') as f:
    pickle.dump(shield, f)
```

**Required CSV columns:**
- protocol, src_bytes, dst_bytes, duration
- payload_size, flag_count, port
- anomaly_label (0=normal, 1=anomaly)

---

## 📊 API Reference

### REST Endpoints (when dashboard.py is running)

#### Get System Status
```
GET /api/status
```
Response:
```json
{
  "shield_name": "CyberShield AI",
  "status": "ACTIVE",
  "health": 98,
  "threat_level": "SAFE",
  "threat_score": 0,
  "statistics": {
    "threats_detected": 0,
    "attacks_blocked": 0,
    "anomalies_detected": 0
  }
}
```

#### Analyze Security Event
```
POST /api/analyze
```
Response:
```json
{
  "threat_level": "SAFE",
  "threat_score": 12,
  "anomaly_score": 0.05,
  "attack_probability": 0.01,
  "timestamp": "2024-01-15T10:30:45"
}
```

#### Check Password Strength
```
POST /api/check-password
Content-Type: application/json

{
  "password": "MyP@ssw0rd123!"
}
```
Response:
```json
{
  "strength": "STRONG",
  "score": 5,
  "entropy": 45.2,
  "feedback": [
    "Include special characters in more places"
  ]
}
```

#### Get Security Report
```
GET /api/report
```

#### Emergency Lockdown
```
POST /api/lockdown
```

---

## 🎯 Use Cases

### 1. Enterprise Network Security
- Deploy on perimeter servers
- Monitor incoming traffic in real-time
- Automatic threat response and blocking
- Compliance reporting (PCI-DSS, HIPAA)

### 2. Intrusion Detection System (IDS)
```
python network_monitor.py
# Analyzes network traffic for suspicious patterns
# Logs and alerts on detected attacks
```

### 3. Password Policy Enforcement
```python
shield.check_password_strength("UserPassword123!")
# Returns strength assessment and improvement suggestions
```

### 4. Security Event Analysis
- Extract security events from SIEM systems
- Feed into CyberShield for intelligent analysis
- Generate automated incident reports

---

## 🔒 Security Best Practices

### 1. Run in Isolated Environment
```bash
python -m venv cyber_env
source cyber_env/bin/activate  # Linux/Mac
# or
cyber_env\Scripts\activate  # Windows
```

### 2. Restrict Dashboard Access
Update dashboard.py:
```python
app.run(host='127.0.0.1', port=5000)  # Local only
# or add authentication
```

### 3. Enable Logging
```python
import logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
```

### 4. Regular Model Updates
- Retrain models monthly with new security data
- Update threat signatures from threat intelligence feeds
- Monitor system performance metrics

---

## 🧪 Testing

### Run Example Analysis
```python
from cyber_shield import CyberShield

shield = CyberShield("TestShield")

# Test normal traffic
normal_event = {
    'source_ip': '192.168.1.100',
    'destination_ip': '8.8.8.8',
    'port': 443,
    'payload': 'normal https traffic',
    'protocol': 'TCP',
    'payload_size': 256,
    'flag_count': 2,
    'duration': 120,
    'src_bytes': 1024,
    'dst_bytes': 2048,
}

result = shield.analyze_security_event(normal_event)
assert result['threat_level'] == 'SAFE'

# Test suspicious traffic
suspicious_event = {
    'source_ip': '203.0.113.45',
    'destination_ip': '10.0.0.1',
    'port': 22,
    'payload': "' OR '1'='1",  # SQL injection attempt
    'protocol': 'TCP',
    'payload_size': 8192,
    'flag_count': 16,
    'duration': 0,
    'src_bytes': 65536,
    'dst_bytes': 32,
}

result = shield.analyze_security_event(suspicious_event)
assert result['threat_level'] in ['HIGH', 'CRITICAL']
```

---

## 📈 Performance Tuning

### Optimize for Speed
```python
# Use smaller batch sizes for real-time processing
# Reduce feature set for faster inference
# Consider GPU acceleration: pip install tensorflow-gpu
```

### Optimize for Accuracy
```python
# Retrain models more frequently
# Increase training dataset size
# Ensemble multiple models
```

---

## 🆘 Troubleshooting

### Issue: Models take too long to train
**Solution**: Use a smaller dataset or GPU acceleration
```bash
pip install tensorflow-gpu
```

### Issue: High false positive rate
**Solution**: Adjust threat threshold in configuration
```python
shield.threat_threshold = 45  # Lower sensitivity
```

### Issue: Dashboard not accessible
**Solution**: Check firewall and Flask configuration
```bash
# Run on public IP (careful with security!)
python dashboard.py  # Change host='0.0.0.0'
```

### Issue: Memory issues with large datasets
**Solution**: Process data in chunks
```python
for chunk in pd.read_csv('large_file.csv', chunksize=10000):
    shield.train_on_dataset(chunk)
```

---

## 📋 Architecture Overview

```
CyberShield AI System
│
├─ ThreatDatabase
│  ├─ Malware Signatures
│  ├─ Suspicious Ports
│  ├─ Malicious Patterns
│  └─ IP Reputation
│
├─ AnomalyDetector (ML)
│  ├─ Isolation Forest
│  ├─ Pattern Recognition
│  └─ Statistical Analysis
│
├─ IntrusionDetectionSystem (ML)
│  ├─ Random Forest Classifier
│  ├─ Feature Extraction
│  └─ Attack Prediction
│
├─ PasswordAnalyzer
│  ├─ Entropy Calculation
│  ├─ Dictionary Checking
│  └─ Strength Scoring
│
├─ NetworkSecurityMonitor
│  ├─ DDoS Detector
│  ├─ PortScan Detector
│  ├─ BruteForce Detector
│  └─ Traffic Analyzer
│
└─ Web Dashboard (Flask)
   ├─ REST API
   ├─ Real-time Visualization
   ├─ Event Logging
   └─ Control Interface
```

---

## 📚 File Structure

```
cyberDefense/
├── cyber_shield.py          # Main threat detection engine
├── network_monitor.py       # Network security monitoring
├── dashboard.py             # Web dashboard & API
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

---

## 🔐 Compliance & Standards

- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **CIS Controls**: Implementation of critical security controls
- **ISO 27001**: Information security management principles
- **OWASP Top 10**: Web application security focus

---

## 📞 Support & Contributing

For issues, questions, or contributions:
1. Check this README for common issues
2. Review code comments for detailed explanations
3. Test with provided example datasets

---

## 📄 License

This cybersecurity framework is provided as-is for defensive purposes. Ensure compliance with relevant laws and regulations in your jurisdiction.

---

## 🎓 Learning Resources

- **Machine Learning**: scikit-learn documentation
- **Network Security**: Scapy packet manipulation guide
- **Web Security**: OWASP security guidelines
- **Cryptography**: Python cryptography.io

---

**CyberShield AI v1.0** - Enterprise-Grade Threat Detection
*Defense Through Intelligence* 🛡️

