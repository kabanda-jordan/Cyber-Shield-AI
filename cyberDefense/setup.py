#!/usr/bin/env python3
"""
CyberShield AI - Installation & Setup Wizard
Automated setup for quick deployment
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from typing import Optional


class SetupWizard:
    """Installation and configuration wizard"""
    
    def __init__(self):
        self.os = platform.system()
        self.project_root = Path(__file__).parent
        self.venv_path = self.project_root / 'venv'
        
    def print_banner(self):
        """Print welcome banner"""
        print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     🛡️  CyberShield AI - Installation Wizard v1.0  🛡️         ║
║                                                                ║
║     Enterprise-Grade Cybersecurity Framework                   ║
║     Powered by Machine Learning & Threat Intelligence         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
        """)
    
    def check_python_version(self):
        """Check Python version requirement"""
        print("📋 Checking Python version...")
        version = sys.version_info
        
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print("❌ Python 3.8+ required!")
            print(f"   Current: {version.major}.{version.minor}")
            return False
        
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    
    def check_dependencies(self):
        """Check system dependencies"""
        print("\n📋 Checking system dependencies...")
        
        if self.os == 'Windows':
            print("   ℹ️  Windows detected - some dependencies may need compilation")
        elif self.os == 'Darwin':
            print("✅ macOS detected - compatible")
        else:
            print("✅ Linux detected - compatible")
        
        return True
    
    def create_venv(self):
        """Create virtual environment"""
        print("\n🔧 Setting up virtual environment...")
        
        if self.venv_path.exists():
            print("   ℹ️  Virtual environment already exists")
            return True
        
        try:
            subprocess.run(
                [sys.executable, '-m', 'venv', str(self.venv_path)],
                check=True
            )
            print(f"✅ Virtual environment created: {self.venv_path}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create virtual environment: {e}")
            return False
    
    def get_python_executable(self) -> str:
        """Get Python executable in virtual environment"""
        if self.os == 'Windows':
            return str(self.venv_path / 'Scripts' / 'python.exe')
        else:
            return str(self.venv_path / 'bin' / 'python')
    
    def install_requirements(self):
        """Install Python dependencies"""
        print("\n📦 Installing dependencies...")
        print("   This may take a few minutes...")
        
        requirements_file = self.project_root / 'requirements.txt'
        if not requirements_file.exists():
            print("❌ requirements.txt not found!")
            return False
        
        python_exe = self.get_python_executable()
        
        try:
            subprocess.run(
                [python_exe, '-m', 'pip', 'install', '--upgrade', 'pip'],
                check=True,
                capture_output=True
            )
            
            subprocess.run(
                [python_exe, '-m', 'pip', 'install', '-r', str(requirements_file)],
                check=True
            )
            
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    
    def create_env_file(self):
        """Create .env configuration file"""
        print("\n⚙️  Creating environment configuration...")
        
        env_file = self.project_root / '.env'
        if env_file.exists():
            print("   ℹ️  .env file already exists")
            return True
        
        env_content = """# CyberShield AI Configuration
ENVIRONMENT=development
THREAT_THRESHOLD=50
LOG_LEVEL=INFO
API_TIMEOUT=30

# Security Settings
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_REQUIRE_NUMBERS=true

# ML Model Settings
ANOMALY_DETECTION_THRESHOLD=0.7
ATTACK_PROBABILITY_THRESHOLD=0.6
MODEL_TRAINING_EPOCHS=100

# Network Monitoring
DDoS_THRESHOLD_PPM=1000
PORT_SCAN_THRESHOLD=10
BRUTE_FORCE_THRESHOLD=5

# Optional: Database
# DATABASE_URL=postgresql://user:password@localhost/cybershield
"""
        
        try:
            env_file.write_text(env_content)
            print(f"✅ Configuration file created: .env")
            return True
        except Exception as e:
            print(f"❌ Failed to create .env: {e}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("\n📁 Creating project directories...")
        
        directories = [
            'logs',
            'models',
            'data',
            'reports',
            'deployment',
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True)
        
        print(f"✅ {len(directories)} directories ready")
        return True
    
    def run_tests(self):
        """Run test suite"""
        print("\n🧪 Running tests...")
        
        test_file = self.project_root / 'test_cybershield.py'
        if not test_file.exists():
            print("   ℹ️  Test file not found - skipping")
            return True
        
        python_exe = self.get_python_executable()
        
        try:
            result = subprocess.run(
                [python_exe, str(test_file)],
                timeout=60
            )
            
            if result.returncode == 0:
                print("✅ All tests passed!")
                return True
            else:
                print("⚠️  Some tests failed - check output above")
                return False
        except subprocess.TimeoutExpired:
            print("⚠️  Tests timed out")
            return False
        except Exception as e:
            print(f"⚠️  Failed to run tests: {e}")
            return False
    
    def print_next_steps(self):
        """Print next steps for user"""
        python_exe = self.get_python_executable()
        
        print("""
╔════════════════════════════════════════════════════════════════╗
║                    ✅ Setup Complete!                          ║
╚════════════════════════════════════════════════════════════════╝

📊 QUICK START GUIDE:

1️⃣  START WEB DASHBOARD:
    $ python dashboard.py
    
    Then open: http://localhost:5000

2️⃣  RUN SECURITY ANALYSIS:
    $ python -c "from cyber_shield import CyberShield; shield = CyberShield('Test'); print(shield.get_security_status())"

3️⃣  RUN TESTS:
    $ python test_cybershield.py

4️⃣  MONITOR NETWORK:
    $ python network_monitor.py

📚 USAGE EXAMPLES:

    # Analyze a security event
    from cyber_shield import CyberShield
    
    shield = CyberShield("MyShield")
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
    
    # Check password strength
    pwd_result = shield.check_password_strength("MyP@ss123!")
    print(f"Strength: {pwd_result['strength']}")
    
    # Generate report
    report = shield.generate_security_report()
    print(report)

🐳 DOCKER DEPLOYMENT:

    $ docker build -t cybershield:latest .
    $ docker run -p 5000:5000 cybershield:latest
    
    Or with Docker Compose:
    $ docker-compose up -d

☸️  KUBERNETES DEPLOYMENT:

    $ kubectl apply -f deployment/kubernetes.yaml

🔐 SECURITY BEST PRACTICES:

   ✓ Run dashboard on local network only (for development)
   ✓ Use HTTPS in production (configure nginx.conf)
   ✓ Store sensitive data in environment variables
   ✓ Regular model retraining with new security data
   ✓ Monitor logs: tail -f logs/security.log
   ✓ Keep dependencies updated: pip install --upgrade -r requirements.txt

📖 DOCUMENTATION:

   - README.md       : Complete feature overview
   - cyber_shield.py : Threat detection engine (500+ lines with docs)
   - network_monitor.py : Network security module (480+ lines with docs)
   - dashboard.py    : Web interface and API
   - config.py       : Configuration management
   
🆘 TROUBLESHOOTING:

   No module errors:
   >>> pip install -r requirements.txt
   
   Tests failing:
   >>> python test_cybershield.py -v
   
   Dashboard not running:
   >>> Check port 5000 is available
   >>> Try: python dashboard.py --host 127.0.0.1 --port 8000

💡 NEXT STEPS:

   1. Review README.md carefully
   2. Explore cyber_shield.py and network_monitor.py
   3. Start dashboard and test web interface
   4. Review test_cybershield.py to understand system behavior
   5. Configure for your environment in config.py
   6. Deploy to production with Docker/Kubernetes

🎓 LEARNING PATH:

   Beginner:  Use dashboard.py for monitoring
   Intermediate: Write custom event analyzers using CyberShield
   Advanced: Retrain ML models, integrate with SIEM systems

📊 SYSTEM ARCHITECTURE:

   CyberShield Core
   ├─ ThreatDatabase (Signature-based detection)
   ├─ AnomalyDetector (ML-based detection)
   ├─ IntrusionDetectionSystem (Attack classification)
   ├─ PasswordAnalyzer (Strength analysis)
   └─ NetworkSecurityMonitor (Traffic analysis)

🚀 You're ready to defend against threats!

╔════════════════════════════════════════════════════════════════╗
║     For help: Review README.md or check code comments          ║
║     License: Use for defensive purposes only                   ║
╚════════════════════════════════════════════════════════════════╝
        """)
    
    def run(self):
        """Run complete setup"""
        self.print_banner()
        
        # Check Python
        if not self.check_python_version():
            return False
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Create virtual environment
        if not self.create_venv():
            return False
        
        # Install requirements
        if not self.install_requirements():
            return False
        
        # Create configuration
        if not self.create_env_file():
            return False
        
        # Create directories
        if not self.create_directories():
            return False
        
        # Run tests
        print("\n⚙️  Would you like to run tests? (y/n): ", end='')
        if input().lower() == 'y':
            self.run_tests()
        
        # Print next steps
        self.print_next_steps()
        
        return True


if __name__ == '__main__':
    wizard = SetupWizard()
    success = wizard.run()
    sys.exit(0 if success else 1)
