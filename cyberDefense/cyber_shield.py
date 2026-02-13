"""
Comprehensive Cyber Defense AI Shield
- Threat Detection with Machine Learning
- Network Security Monitoring
- Intrusion Detection System
- Real-time Anomaly Detection
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import json
import hashlib
from dataclasses import dataclass
from enum import Enum
import logging

# ML Libraries
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SecurityEvent:
    """Represents a security event"""
    timestamp: datetime
    event_type: str
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    payload_size: int
    flag_count: int
    severity: ThreatLevel
    description: str
    
    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'protocol': self.protocol,
            'payload_size': self.payload_size,
            'flag_count': self.flag_count,
            'severity': self.severity.name,
            'description': self.description
        }


class ThreatDatabase:
    """Manages known threats and signatures"""
    
    def __init__(self):
        self.known_malware = {
            'trojan': ['keylogger', 'backdoor', 'spyware'],
            'ransomware': ['lockware', 'cryptowall', 'petya'],
            'worm': ['propagating', 'self_replicating'],
            'botnet': ['command_control', 'distributed', 'zombie'],
        }
        
        self.suspicious_ports = {
            23: 'Telnet (unencrypted)',
            139: 'NetBIOS (legacy)',
            445: 'SMB (ransomware)',
            3389: 'RDP (brute force)',
            5432: 'PostgreSQL (exposed)',
            27017: 'MongoDB (exposed)',
            6379: 'Redis (exposed)',
            9200: 'Elasticsearch (exposed)',
        }
        
        self.malicious_patterns = {
            'sql_injection': ['select', 'union', 'drop', 'insert', 'delete'],
            'xss': ['<script>', 'onerror=', 'onload=', 'javascript:'],
            'path_traversal': ['..//', '..\\\\', '%2e%2e'],
            'command_injection': [';rm', '&&rm', '|cat', '`whoami`'],
        }
        
        self.malicious_ips = set()
        self.whitelist_ips = set()
    
    def add_malicious_ip(self, ip: str):
        """Add IP to malicious list"""
        self.malicious_ips.add(ip)
    
    def check_ip_reputation(self, ip: str) -> bool:
        """Check if IP is known malicious"""
        return ip in self.malicious_ips
    
    def check_payload(self, payload: str) -> List[str]:
        """Check payload for known attack patterns"""
        threats = []
        payload_lower = payload.lower()
        
        for threat_type, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if pattern.lower() in payload_lower:
                    threats.append(threat_type)
                    break
        
        return threats


class AnomalyDetector:
    """ML-based anomaly detection using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = None
    
    def prepare_features(self, events: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """Extract features from security events"""
        features = []
        
        for event in events:
            feature_vector = [
                event.get('payload_size', 0),
                event.get('flag_count', 0),
                event.get('port', 0),
                event.get('packet_rate', 0),  # packets per second
                event.get('protocol_type', 0),  # encoded protocol
                event.get('failed_logins', 0),
                event.get('connection_duration', 0),
                event.get('data_rate', 0),
            ]
            features.append(feature_vector)
        
        return np.array(features), [
            'payload_size', 'flag_count', 'port', 'packet_rate',
            'protocol_type', 'failed_logins', 'connection_duration', 'data_rate'
        ]
    
    def train(self, events: List[Dict]):
        """Train anomaly detection model"""
        features, self.feature_names = self.prepare_features(events)
        
        if len(features) > 0:
            features_scaled = self.scaler.fit_transform(features)
            self.model.fit(features_scaled)
            self.is_trained = True
            logger.info(f"Anomaly detector trained on {len(events)} events")
    
    def detect(self, event: Dict) -> Tuple[bool, float]:
        """Detect anomalies in a security event"""
        if not self.is_trained:
            return False, 0.0
        
        features, _ = self.prepare_features([event])
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = -self.model.score_samples(features_scaled)[0]
        
        is_anomaly = prediction == -1
        return is_anomaly, float(anomaly_score)


class IntrusionDetectionSystem:
    """ML-based Intrusion Detection System"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = None
    
    def prepare_features(self, events: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """Extract IDS features from events"""
        features = []
        
        for event in events:
            feature_vector = [
                event.get('duration', 0),
                event.get('protocol_type', 0),
                event.get('service', 0),
                event.get('flag', 0),
                event.get('src_bytes', 0),
                event.get('dst_bytes', 0),
                event.get('land', 0),
                event.get('wrong_fragment', 0),
                event.get('urgent', 0),
                event.get('hot', 0),
                event.get('num_failed_logins', 0),
                event.get('logged_in', 0),
            ]
            features.append(feature_vector)
        
        return np.array(features), [
            'duration', 'protocol_type', 'service', 'flag',
            'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in'
        ]
    
    def train(self, events: List[Dict], labels: List[int]):
        """Train IDS model"""
        features, self.feature_names = self.prepare_features(events)
        
        if len(features) > 0:
            features_scaled = self.scaler.fit_transform(features)
            self.model.fit(features_scaled, labels)
            self.is_trained = True
            logger.info(f"IDS trained on {len(events)} events")
    
    def predict(self, event: Dict) -> Tuple[int, float]:
        """Predict if event is attack (1) or normal (0)"""
        if not self.is_trained:
            return 0, 0.0
        
        features, _ = self.prepare_features([event])
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        confidence = max(self.model.predict_proba(features_scaled)[0])
        
        return int(prediction), float(confidence)


class PasswordAnalyzer:
    """Analyzes password strength and detects common patterns"""
    
    WEAK_PASSWORDS = {
        'password', '123456', 'qwerty', 'abc123', 'letmein',
        'admin', 'welcome', 'monkey', 'dragon', 'master'
    }
    
    @staticmethod
    def calculate_strength(password: str) -> Dict[str, Any]:
        """Calculate password strength"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        # Complexity checks
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Dictionary check
        if password.lower() in PasswordAnalyzer.WEAK_PASSWORDS:
            score = max(0, score - 3)
            feedback.insert(0, "Password is commonly used")
        
        strength_levels = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Fair',
            3: 'Good',
            4: 'Strong',
            5: 'Very Strong',
            6: 'Excellent'
        }
        
        return {
            'score': min(6, score),
            'strength': strength_levels.get(min(6, score), 'Unknown'),
            'feedback': feedback,
            'entropy': len(password) * np.log2(256)
        }


class CyberShield:
    """Main Cyber Defense AI Shield"""
    
    def __init__(self, name: str = "CyberShield AI"):
        self.name = name
        self.threat_database = ThreatDatabase()
        self.anomaly_detector = AnomalyDetector()
        self.ids = IntrusionDetectionSystem()
        self.event_log = []
        self.security_stats = {
            'total_events': 0,
            'threats_detected': 0,
            'attacks_blocked': 0,
            'anomalies_detected': 0,
        }
        
        logger.info(f"Initializing {self.name}...")
    
    def analyze_security_event(self, event: Dict) -> Dict[str, Any]:
        """Comprehensive security event analysis"""
        threat_score = 0
        threats = []
        mitigations = []
        
        # IP Reputation Check
        source_ip = event.get('source_ip', '')
        if self.threat_database.check_ip_reputation(source_ip):
            threat_score += 40
            threats.append('Known Malicious IP')
            mitigations.append('Block IP immediately')
        
        # Suspicious Port Check
        port = event.get('port', 0)
        if port in self.threat_database.suspicious_ports:
            threat_score += 20
            threats.append(f"Suspicious Port {port}")
            mitigations.append(f"Monitor {self.threat_database.suspicious_ports[port]}")
        
        # Payload Analysis
        payload = event.get('payload', '')
        payload_threats = self.threat_database.check_payload(payload)
        if payload_threats:
            threat_score += 30
            threats.extend(payload_threats)
            mitigations.append('Isolate endpoint and investigate')
        
        # Anomaly Detection
        is_anomaly, anomaly_score = self.anomaly_detector.detect(event)
        if is_anomaly:
            threat_score += int(anomaly_score * 10)
            threats.append('Anomalous Behavior Detected')
            mitigations.append('Flag for manual review')
            self.security_stats['anomalies_detected'] += 1
        
        # IDS Check
        ids_prediction, ids_confidence = self.ids.predict(event)
        if ids_prediction == 1:
            threat_score += int(ids_confidence * 30)
            threats.append(f'Intrusion Detected (confidence: {ids_confidence:.2%})')
            mitigations.append('Activate emergency response protocol')
            self.security_stats['attacks_blocked'] += 1
        
        # Determine threat level
        threat_level = ThreatLevel.SAFE
        if threat_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif threat_score >= 60:
            threat_level = ThreatLevel.HIGH
        elif threat_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif threat_score >= 20:
            threat_level = ThreatLevel.LOW
        
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'threat_score': threat_score,
            'threat_level': threat_level.name,
            'threats_detected': threats,
            'mitigations': mitigations,
            'is_blocked': threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL],
            'confidence': min(100, threat_score) / 100
        }
        
        # Update statistics
        self.security_stats['total_events'] += 1
        if threats:
            self.security_stats['threats_detected'] += 1
        
        # Log event
        self.event_log.append(analysis_result)
        
        return analysis_result
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status"""
        return {
            'shield_name': self.name,
            'status': 'ACTIVE',
            'timestamp': datetime.now().isoformat(),
            'statistics': self.security_stats,
            'health': self._calculate_health_score(),
            'recent_events': self.event_log[-10:] if self.event_log else []
        }
    
    def _calculate_health_score(self) -> float:
        """Calculate system health score (0-100)"""
        total = self.security_stats['total_events']
        if total == 0:
            return 100.0
        
        threat_ratio = self.security_stats['threats_detected'] / total
        health = max(0, 100 - (threat_ratio * 100))
        
        return round(health, 2)
    
    def check_password_strength(self, password: str) -> Dict:
        """Analyze password strength"""
        return PasswordAnalyzer.calculate_strength(password)
    
    def generate_security_report(self) -> str:
        """Generate comprehensive security report"""
        status = self.get_security_status()
        
        report = f"""
{'='*60}
{status['shield_name']} - Security Report
{'='*60}
Generated: {status['timestamp']}
Shield Status: {status['status']}
System Health: {status['health']}%

STATISTICS:
- Total Events Analyzed: {status['statistics']['total_events']}
- Threats Detected: {status['statistics']['threats_detected']}
- Attacks Blocked: {status['statistics']['attacks_blocked']}
- Anomalies Found: {status['statistics']['anomalies_detected']}

RECENT SECURITY EVENTS:
{'-'*60}
"""
        
        for event in status['recent_events'][-5:]:
            report += f"""
Event: {event['timestamp']}
Threat Level: {event['threat_level']}
Threat Score: {event['threat_score']}/100
Threats: {', '.join(event['threats_detected']) if event['threats_detected'] else 'None'}
Status: {'BLOCKED' if event['is_blocked'] else 'ALLOWED'}
"""
        
        report += f"\n{'='*60}\n"
        return report
    
    def train_on_dataset(self, events: List[Dict], labels: List[int] = None):
        """Train AI models on security event dataset"""
        try:
            if labels is None:
                labels = [0] * len(events)
            
            self.anomaly_detector.train(events)
            self.ids.train(events, labels)
            logger.info("AI models trained successfully")
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")


if __name__ == "__main__":
    # Example usage
    shield = CyberShield("CyberShield AI v1.0")
    
    # Example security events
    test_events = [
        {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'port': 22,
            'payload': 'normal ssh login',
            'protocol': 'TCP',
            'payload_size': 256,
            'flag_count': 2,
            'duration': 120,
            'protocol_type': 1,
            'service': 1,
            'flag': 0,
            'src_bytes': 1024,
            'dst_bytes': 2048,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,
            'packet_rate': 10,
            'failed_logins': 0,
            'connection_duration': 120,
            'data_rate': 512,
        },
        {
            'source_ip': '203.0.113.45',
            'destination_ip': '10.0.0.1',
            'port': 445,
            'payload': 'SELECT * FROM users; DROP TABLE users;--',
            'protocol': 'TCP',
            'payload_size': 1024,
            'flag_count': 8,
            'duration': 5,
            'protocol_type': 2,
            'service': 2,
            'flag': 1,
            'src_bytes': 5120,
            'dst_bytes': 512,
            'land': 0,
            'wrong_fragment': 1,
            'urgent': 1,
            'hot': 5,
            'num_failed_logins': 10,
            'logged_in': 0,
            'packet_rate': 100,
            'failed_logins': 10,
            'connection_duration': 5,
            'data_rate': 5120,
        }
    ]
    
    # Train models
    shield.train_on_dataset(test_events, [0, 1])
    
    # Analyze events
    print("\n" + "="*60)
    print("ANALYZING SECURITY EVENTS")
    print("="*60)
    
    for event in test_events:
        result = shield.analyze_security_event(event)
        print(f"\nEvent from {event['source_ip']}:")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Threat Score: {result['threat_score']}/100")
        print(f"  Blocked: {result['is_blocked']}")
        if result['threats_detected']:
            print(f"  Threats: {', '.join(result['threats_detected'])}")
    
    # Check password strength
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*60)
    
    passwords = ['password123', 'MyStr0ng!Pass2024', 'abc123']
    for pwd in passwords:
        strength = shield.check_password_strength(pwd)
        print(f"\nPassword: {'*' * len(pwd)}")
        print(f"  Strength: {strength['strength']}")
        print(f"  Score: {strength['score']}/6")
        print(f"  Entropy: {strength['entropy']:.2f} bits")
        if strength['feedback']:
            print(f"  Feedback: {', '.join(strength['feedback'])}")
    
    # Generate report
    print(shield.generate_security_report())
