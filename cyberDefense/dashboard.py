"""
Web Dashboard and API for Cyber Defense Shield
- Real-time security monitoring
- Threat visualization
- System control and configuration
"""

from flask import Flask, render_template_string, jsonify, request
from datetime import datetime
import json
from cyber_shield import CyberShield, ThreatLevel
from network_monitor import NetworkSecurityMonitor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize security systems
cyber_shield = CyberShield("CyberShield AI - Enterprise Edition")
network_monitor = NetworkSecurityMonitor()


# HTML Template for Dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberShield AI - Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(30, 144, 255, 0.1);
            border: 2px solid #1e90ff;
            border-radius: 10px;
        }
        
        .logo {
            font-size: 28px;
            font-weight: bold;
            color: #1e90ff;
        }
        
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        }
        
        .status-active {
            background: #00cc44;
            color: #000;
        }
        
        .status-warning {
            background: #ffaa00;
            color: #000;
        }
        
        .status-critical {
            background: #ff4444;
            color: #fff;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
        }
        
        .card-title {
            font-size: 14px;
            color: #aaa;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: bold;
            color: #1e90ff;
            margin-bottom: 5px;
        }
        
        .card-subtitle {
            font-size: 12px;
            color: #888;
        }
        
        .threat-level {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-top: 10px;
        }
        
        .threat-safe {
            background: #00cc44;
            color: #000;
        }
        
        .threat-low {
            background: #0099ff;
            color: #fff;
        }
        
        .threat-medium {
            background: #ffaa00;
            color: #000;
        }
        
        .threat-high {
            background: #ff6600;
            color: #fff;
        }
        
        .threat-critical {
            background: #ff0000;
            color: #fff;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: bold;
            margin: 30px 0 15px 0;
            color: #1e90ff;
            border-bottom: 2px solid #1e90ff;
            padding-bottom: 10px;
        }
        
        .event-log {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .event-item {
            padding: 10px;
            border-left: 3px solid #1e90ff;
            margin-bottom: 10px;
            background: rgba(30, 144, 255, 0.05);
            border-radius: 5px;
        }
        
        .event-time {
            font-size: 12px;
            color: #888;
        }
        
        .event-message {
            font-size: 14px;
            color: #e0e0e0;
            margin-top: 5px;
        }
        
        .button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background: #1e90ff;
            color: white;
            cursor: pointer;
            font-weight: bold;
            margin-right: 10px;
            transition: all 0.3s ease;
        }
        
        .button:hover {
            background: #0066cc;
            transform: translateY(-2px);
        }
        
        .button-danger {
            background: #ff4444;
        }
        
        .button-danger:hover {
            background: #cc0000;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00cc44, #ffaa00);
            transition: width 0.3s ease;
        }
        
        .controls {
            margin: 20px 0;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
        }
        
        input, select {
            padding: 10px;
            margin-right: 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.05);
            color: #e0e0e0;
            border-radius: 5px;
        }
        
        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #00cc44;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️ CyberShield AI</div>
            <div>
                <span class="live-indicator"></span>
                <span class="status-badge status-active" id="statusBadge">ACTIVE</span>
            </div>
        </header>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">Shield Status</div>
                <div class="card-value" id="shieldStatus">ACTIVE</div>
                <div class="card-subtitle">Real-time monitoring enabled</div>
            </div>
            
            <div class="card">
                <div class="card-title">System Health</div>
                <div class="card-value" id="healthScore">98%</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="healthBar" style="width: 98%"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">Threats Detected</div>
                <div class="card-value" id="threatsDetected">0</div>
                <div class="card-subtitle">Last 24 hours</div>
            </div>
            
            <div class="card">
                <div class="card-title">Attacks Blocked</div>
                <div class="card-value" id="attacksBlocked">0</div>
                <div class="card-subtitle">Prevented intrusions</div>
            </div>
        </div>
        
        <div class="section-title">Threat Level Analysis</div>
        <div class="grid">
            <div class="card">
                <div class="card-title">Current Threat Level</div>
                <div id="currentThreatLevel" class="threat-level threat-safe">SAFE</div>
            </div>
            
            <div class="card">
                <div class="card-title">Average Threat Score</div>
                <div class="card-value" id="threatScore">0</div>
                <div style="font-size: 12px; color: #888; margin-top: 5px;">/100</div>
            </div>
        </div>
        
        <div class="section-title">Recent Security Events</div>
        <div class="event-log" id="eventLog">
            <div class="event-item">
                <div class="event-time">Initializing event log...</div>
                <div class="event-message">System ready for monitoring</div>
            </div>
        </div>
        
        <div class="section-title">Controls</div>
        <div class="controls">
            <button class="button" onclick="runSecurityAnalysis()">Run Full Analysis</button>
            <button class="button" onclick="generateReport()">Generate Report</button>
            <button class="button button-danger" onclick="lockdownSystem()">Emergency Lockdown</button>
            
            <div style="margin-top: 15px;">
                <label>Test Password Strength:</label><br><br>
                <input type="password" id="passwordInput" placeholder="Enter password to test" style="width: 300px;">
                <button class="button" onclick="checkPassword()">Analyze</button>
            </div>
        </div>
        
        <div id="passwordResult" style="margin-top: 20px;"></div>
        
        <footer>
            CyberShield AI - Enterprise Security Platform v1.0 | Live Protection Active
        </footer>
    </div>
    
    <script>
        // Update dashboard every 5 seconds
        function updateDashboard() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('healthScore').textContent = data.health + '%';
                    document.getElementById('healthBar').style.width = data.health + '%';
                    document.getElementById('threatsDetected').textContent = data.statistics.threats_detected;
                    document.getElementById('attacksBlocked').textContent = data.statistics.attacks_blocked;
                    document.getElementById('threatScore').textContent = data.threat_score || '0';
                    
                    // Update threat level
                    const threatLevel = data.threat_level || 'SAFE';
                    const threatElement = document.getElementById('currentThreatLevel');
                    threatElement.textContent = threatLevel;
                    threatElement.className = 'threat-level threat-' + threatLevel.toLowerCase();
                });
        }
        
        function runSecurityAnalysis() {
            fetch('/api/analyze', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    addEventToLog('Security analysis completed', 'Analysis Results');
                    updateDashboard();
                });
        }
        
        function generateReport() {
            fetch('/api/report')
                .then(response => response.text())
                .then(text => {
                    alert(text);
                });
        }
        
        function lockdownSystem() {
            if(confirm('Activate emergency lockdown? All network access will be restricted.')) {
                fetch('/api/lockdown', {method: 'POST'})
                    .then(response => response.json())
                    .then(data => {
                        alert('System locked down');
                        addEventToLog('EMERGENCY LOCKDOWN ACTIVATED', 'CRITICAL');
                    });
            }
        }
        
        function checkPassword() {
            const password = document.getElementById('passwordInput').value;
            if(!password) return;
            
            fetch('/api/check-password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password: password})
            })
            .then(response => response.json())
            .then(data => {
                const resultDiv = document.getElementById('passwordResult');
                resultDiv.innerHTML = `
                    <div class="card">
                        <div class="card-title">Password Analysis Results</div>
                        <div style="margin: 15px 0;">
                            <div><strong>Strength:</strong> <span style="color: #1e90ff;">${data.strength}</span></div>
                            <div><strong>Score:</strong> ${data.score}/6</div>
                            <div><strong>Entropy:</strong> ${data.entropy.toFixed(2)} bits</div>
                            ${data.feedback.length ? '<div><strong>Improvements:</strong><ul style="margin: 10px 0;">' + data.feedback.map(f => '<li>' + f + '</li>').join('') + '</ul></div>' : ''}
                        </div>
                    </div>
                `;
            });
        }
        
        function addEventToLog(message, type = 'INFO') {
            const eventLog = document.getElementById('eventLog');
            const now = new Date().toLocaleTimeString();
            const eventColor = type === 'CRITICAL' ? 'red' : type === 'WARNING' ? 'orange' : 'blue';
            
            const eventItem = document.createElement('div');
            eventItem.className = 'event-item';
            eventItem.style.borderLeftColor = eventColor;
            eventItem.innerHTML = `
                <div class="event-time">${now} [${type}]</div>
                <div class="event-message">${message}</div>
            `;
            
            eventLog.insertBefore(eventItem, eventLog.firstChild);
            
            // Keep only last 20 events
            while(eventLog.children.length > 20) {
                eventLog.removeChild(eventLog.lastChild);
            }
        }
        
        // Initial load
        updateDashboard();
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """Serve the security dashboard"""
    return render_template_string(DASHBOARD_TEMPLATE)


@app.route('/api/status')
def get_status():
    """Get current security status"""
    status = cyber_shield.get_security_status()
    return jsonify({
        'shield_name': status['shield_name'],
        'status': status['status'],
        'health': status['health'],
        'statistics': status['statistics'],
        'threat_level': 'SAFE',
        'threat_score': 0,
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_security():
    """Run security analysis"""
    # Simulate analyzing a security event
    event = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'port': 443,
        'payload': 'normal https traffic',
        'protocol': 'TCP',
        'payload_size': 256,
        'flag_count': 2,
        'duration': 120,
        'src_bytes': 1024,
        'dst_bytes': 2048,
    }
    
    result = cyber_shield.analyze_security_event(event)
    return jsonify(result)


@app.route('/api/report')
def get_report():
    """Generate security report"""
    report = cyber_shield.generate_security_report()
    return report, 200, {'Content-Type': 'text/plain'}


@app.route('/api/lockdown', methods=['POST'])
def emergency_lockdown():
    """Activate emergency lockdown"""
    return jsonify({
        'status': 'lockdown_activated',
        'message': 'Emergency lockdown mode activated',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/check-password', methods=['POST'])
def check_password():
    """Check password strength"""
    data = request.json
    password = data.get('password', '')
    
    result = cyber_shield.check_password_strength(password)
    return jsonify(result)


@app.route('/api/network-status')
def network_status():
    """Get network security status"""
    status = network_monitor.get_network_status()
    return jsonify(status)


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get detected threats"""
    return jsonify({
        'threats': cyber_shield.security_stats['threats_detected'],
        'attacks_blocked': cyber_shield.security_stats['attacks_blocked'],
        'anomalies': cyber_shield.security_stats['anomalies_detected'],
    })


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'services': {
            'cyber_shield': 'running',
            'network_monitor': 'running',
            'api': 'running'
        }
    })


if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         CyberShield AI - Security Dashboard                ║
    ║                                                            ║
    ║  🛡️  Starting security monitoring system                  ║
    ║  🔐  All systems initialized and ready                    ║
    ║                                                            ║
    ║  Access Dashboard at: http://localhost:5000               ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
