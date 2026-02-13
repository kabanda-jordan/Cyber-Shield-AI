"""
Network Security Monitoring Module
- Real-time packet analysis
- DDoS detection
- Port scanning detection
- Traffic anomaly detection
"""

import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class NetworkPacket:
    """Represents a network packet"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    size: int
    flags: List[str] = None


class TrafficAnalyzer:
    """Analyzes network traffic patterns"""
    
    def __init__(self, window_size: int = 300):  # 5 minute window
        self.window_size = window_size
        self.traffic_history = defaultdict(deque)
        self.connection_attempts = defaultdict(lambda: defaultdict(int))
        self.bandwidth_usage = defaultdict(float)
    
    def process_packet(self, packet: NetworkPacket) -> Dict:
        """Process network packet and detect anomalies"""
        timestamp = packet.timestamp
        source_key = packet.source_ip
        dest_key = f"{packet.destination_ip}:{packet.destination_port}"
        
        # Track traffic
        self.traffic_history[source_key].append((timestamp, packet.size))
        self.bandwidth_usage[source_key] += packet.size
        
        # Clean old entries
        cutoff_time = timestamp - timedelta(seconds=self.window_size)
        while self.traffic_history[source_key] and self.traffic_history[source_key][0][0] < cutoff_time:
            self.traffic_history[source_key].popleft()
        
        # Track connection attempts
        self.connection_attempts[source_key][dest_key] += 1
        
        analysis = {
            'source_ip': packet.source_ip,
            'destination': dest_key,
            'protocol': packet.protocol,
            'packet_size': packet.size,
            'packets_in_window': len(self.traffic_history[source_key]),
            'bandwidth_mbps': (self.bandwidth_usage[source_key] * 8 / 1_000_000) / (self.window_size / 60),
        }
        
        return analysis


class DDoSDetector:
    """Detects Distributed Denial of Service attacks"""
    
    def __init__(self, threshold: int = 1000, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.packets_per_source = defaultdict(deque)
        self.packets_per_dest = defaultdict(deque)
    
    def analyze_packet(self, packet: NetworkPacket) -> Tuple[bool, Dict]:
        """Check if packet is part of DDoS attack"""
        timestamp = packet.timestamp
        cutoff_time = timestamp - timedelta(seconds=self.window_seconds)
        
        # Check source traffic
        self.packets_per_source[packet.source_ip].append(timestamp)
        while self.packets_per_source[packet.source_ip] and \
              self.packets_per_source[packet.source_ip][0] < cutoff_time:
            self.packets_per_source[packet.source_ip].popleft()
        
        # Check destination traffic
        self.packets_per_dest[packet.destination_ip].append(timestamp)
        while self.packets_per_dest[packet.destination_ip] and \
              self.packets_per_dest[packet.destination_ip][0] < cutoff_time:
            self.packets_per_dest[packet.destination_ip].popleft()
        
        source_rate = len(self.packets_per_source[packet.source_ip])
        dest_rate = len(self.packets_per_dest[packet.destination_ip])
        
        is_attack = False
        attack_info = {
            'source_packets_per_minute': source_rate,
            'dest_packets_per_minute': dest_rate,
            'attack_detected': False,
            'attack_type': None,
        }
        
        # Volumetric attack detection
        if dest_rate > self.threshold:
            is_attack = True
            attack_info['attack_detected'] = True
            attack_info['attack_type'] = 'Volumetric DDoS'
        
        # Flood detection from single source
        if source_rate > self.threshold / 10:  # Single source sending many packets
            is_attack = True
            attack_info['attack_detected'] = True
            attack_info['attack_type'] = 'Flood Attack'
        
        return is_attack, attack_info


class PortScanDetector:
    """Detects port scanning activities"""
    
    def __init__(self, sensitivity: int = 10):  # Ports scanned in 60 seconds
        self.sensitivity = sensitivity
        self.ports_contacted = defaultdict(set)
        self.contact_times = defaultdict(deque)
    
    def analyze_connection(self, source_ip: str, dest_ip: str, 
                          port: int, timestamp: datetime) -> Tuple[bool, Dict]:
        """Detect port scanning patterns"""
        source_key = f"{source_ip}-{dest_ip}"
        
        # Record contact
        self.ports_contacted[source_key].add(port)
        self.contact_times[source_key].append((timestamp, port))
        
        # Clean old entries (last 60 seconds)
        cutoff_time = timestamp - timedelta(seconds=60)
        while self.contact_times[source_key] and \
              self.contact_times[source_key][0][0] < cutoff_time:
            self.contact_times[source_key].popleft()
        
        # Detect scanning
        is_scan = False
        ports_in_window = len(set(port for _, port in self.contact_times[source_key]))
        
        result = {
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'unique_ports_contacted': len(self.ports_contacted[source_key]),
            'ports_in_60s': ports_in_window,
            'scan_detected': False,
            'scan_type': None,
        }
        
        if ports_in_window >= self.sensitivity:
            is_scan = True
            result['scan_detected'] = True
            result['scan_type'] = 'Port Scanner Detected'
        
        return is_scan, result


class BruteForceDetector:
    """Detects brute force attack attempts"""
    
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.failed_attempts = defaultdict(deque)
    
    def log_attempt(self, source_ip: str, destination_ip: str, 
                   port: int, success: bool, timestamp: datetime) -> Tuple[bool, Dict]:
        """Log login attempt and detect brute force"""
        key = f"{source_ip}-{destination_ip}:{port}"
        
        if not success:
            self.failed_attempts[key].append(timestamp)
        
        # Clean old entries
        cutoff_time = timestamp - timedelta(seconds=self.window_seconds)
        while self.failed_attempts[key] and self.failed_attempts[key][0] < cutoff_time:
            self.failed_attempts[key].popleft()
        
        failed_count = len(self.failed_attempts[key])
        
        result = {
            'source_ip': source_ip,
            'target': f"{destination_ip}:{port}",
            'failed_attempts': failed_count,
            'brute_force_detected': False,
        }
        
        is_attack = failed_count >= self.threshold
        if is_attack:
            result['brute_force_detected'] = True
            result['message'] = f'Brute force attack from {source_ip}'
        
        return is_attack, result


class NetworkSecurityMonitor:
    """Main network security monitoring system"""
    
    def __init__(self):
        self.traffic_analyzer = TrafficAnalyzer()
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()
        self.brute_force_detector = BruteForceDetector()
        
        self.alerts = []
        self.blocked_ips = set()
        
        logger.info("Network Security Monitor initialized")
    
    def analyze_traffic(self, packets: List[NetworkPacket]) -> Dict:
        """Analyze network traffic for threats"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': len(packets),
            'threats_found': 0,
            'ddos_attacks': [],
            'port_scans': [],
            'brute_forces': [],
            'alerts': [],
        }
        
        for packet in packets:
            # DDoS detection
            is_ddos, ddos_info = self.ddos_detector.analyze_packet(packet)
            if is_ddos:
                results['ddos_attacks'].append(ddos_info)
                results['threats_found'] += 1
                self.alerts.append({
                    'type': 'DDoS',
                    'info': ddos_info,
                    'timestamp': packet.timestamp
                })
            
            # Port scan detection
            is_scan, scan_info = self.port_scan_detector.analyze_connection(
                packet.source_ip, packet.destination_ip, 
                packet.destination_port, packet.timestamp
            )
            if is_scan:
                results['port_scans'].append(scan_info)
                results['threats_found'] += 1
                self.alerts.append({
                    'type': 'Port Scan',
                    'info': scan_info,
                    'timestamp': packet.timestamp
                })
            
            # Traffic analysis
            self.traffic_analyzer.process_packet(packet)
        
        return results
    
    def block_ip(self, ip: str):
        """Add IP to block list"""
        self.blocked_ip
s.add(ip)
        logger.warning(f"IP {ip} blocked")
    
    def get_network_status(self) -> Dict:
        """Get overall network status"""
        return {
            'timestamp': datetime.now().isoformat(),
            'monitor_status': 'ACTIVE',
            'blocked_ips': len(self.blocked_ips),
            'recent_alerts': self.alerts[-10:],
            'total_alerts': len(self.alerts),
        }


def simulate_network_traffic() -> List[NetworkPacket]:
    """Simulate network traffic for testing"""
    packets = []
    now = datetime.now()
    
    # Normal traffic
    for i in range(100):
        packet = NetworkPacket(
            timestamp=now - timedelta(seconds=i),
            source_ip=f"192.168.1.{i % 50}",
            destination_ip="10.0.0.1",
            source_port=50000 + i,
            destination_port=443,
            protocol="TCP",
            size=1024 + (i % 500),
            flags=['ACK']
        )
        packets.append(packet)
    
    # Suspicious traffic (potential DDoS)
    for i in range(500):
        packet = NetworkPacket(
            timestamp=now - timedelta(seconds=i),
            source_ip=f"203.0.113.{i % 256}",
            destination_ip="10.0.0.1",
            source_port=60000 + i,
            destination_port=80,
            protocol="TCP",
            size=64,
            flags=['SYN']
        )
        packets.append(packet)
    
    # Port scanning traffic
    for port in range(22, 1000, 10):
        packet = NetworkPacket(
            timestamp=now,
            source_ip="203.0.113.50",
            destination_ip="10.0.0.5",
            source_port=54321,
            destination_port=port,
            protocol="TCP",
            size=64,
            flags=['SYN']
        )
        packets.append(packet)
    
    return packets


if __name__ == "__main__":
    monitor = NetworkSecurityMonitor()
    
    # Simulate traffic
    packets = simulate_network_traffic()
    
    # Analyze
    results = monitor.analyze_traffic(packets)
    
    print("\n" + "="*60)
    print("NETWORK SECURITY ANALYSIS REPORT")
    print("="*60)
    print(f"Total Packets Analyzed: {results['total_packets']}")
    print(f"Threats Found: {results['threats_found']}")
    print(f"\nDDoS Attacks Detected: {len(results['ddos_attacks'])}")
    print(f"Port Scans Detected: {len(results['port_scans'])}")
    
    if results['ddos_attacks']:
        print("\n--- DDoS Attack Details ---")
        for attack in results['ddos_attacks'][:3]:
            print(f"  Attack Type: {attack['attack_type']}")
            print(f"  Destination: {attack.get('destination', 'N/A')}")
            print(f"  Dest Packets/min: {attack['dest_packets_per_minute']}")
    
    if results['port_scans']:
        print("\n--- Port Scan Details ---")
        for scan in results['port_scans']:
            print(f"  Scanner: {scan['source_ip']}")
            print(f"  Target: {scan['destination_ip']}")
            print(f"  Unique Ports: {scan['unique_ports_contacted']}")
    
    print(f"\nNetwork Status: {monitor.get_network_status()['monitor_status']}")
