"""
CyberShield AI - Deployment & Configuration Guide
Multi-environment support for development, staging, and production
"""

import os
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Dict, Any

# Load environment variables
load_dotenv()


@dataclass
class Config:
    """Base configuration"""
    ENVIRONMENT = "development"
    DEBUG = True
    THREAT_THRESHOLD = 50
    LOG_LEVEL = "INFO"
    MAX_EVENTS_LOG = 1000
    API_TIMEOUT = 30
    ENABLE_SSL = False
    
    # Security settings
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_REQUIRE_NUMBERS = True
    
    # ML Model settings
    ANOMALY_DETECTION_THRESHOLD = 0.7
    ATTACK_PROBABILITY_THRESHOLD = 0.6
    MODEL_TRAINING_EPOCHS = 100
    MODEL_BATCH_SIZE = 32
    
    # Network monitoring
    DDoS_THRESHOLD_PPM = 1000  # packets per minute
    PORT_SCAN_THRESHOLD = 10   # unique ports
    BRUTE_FORCE_THRESHOLD = 5  # failed attempts
    
    # Database settings
    DATABASE_ENABLED = False
    DATABASE_URL = None
    BACKUP_ENABLED = False


@dataclass
class DevelopmentConfig(Config):
    """Development environment configuration"""
    ENVIRONMENT = "development"
    DEBUG = True
    THREAT_THRESHOLD = 40  # Lower for testing
    LOG_LEVEL = "DEBUG"
    API_TIMEOUT = 60


@dataclass
class StagingConfig(Config):
    """Staging environment configuration"""
    ENVIRONMENT = "staging"
    DEBUG = False
    THREAT_THRESHOLD = 50
    LOG_LEVEL = "INFO"
    API_TIMEOUT = 45
    ENABLE_SSL = True
    DATABASE_ENABLED = True
    BACKUP_ENABLED = True


@dataclass
class ProductionConfig(Config):
    """Production environment configuration"""
    ENVIRONMENT = "production"
    DEBUG = False
    THREAT_THRESHOLD = 60  # Higher to reduce false positives
    LOG_LEVEL = "WARNING"
    API_TIMEOUT = 30
    ENABLE_SSL = True
    DATABASE_ENABLED = True
    BACKUP_ENABLED = True
    MAX_EVENTS_LOG = 100000
    
    # Production-grade security
    PASSWORD_MIN_LENGTH = 16
    ANOMALY_DETECTION_THRESHOLD = 0.8
    ATTACK_PROBABILITY_THRESHOLD = 0.75
    DDoS_THRESHOLD_PPM = 800  # More sensitive in production
    PORT_SCAN_THRESHOLD = 5
    BRUTE_FORCE_THRESHOLD = 3


class ConfigManager:
    """Manages configuration for different environments"""
    
    @staticmethod
    def get_config(environment: str = None) -> Config:
        """
        Get configuration for specified environment
        
        Args:
            environment: 'development', 'staging', 'production'
                        If None, uses ENVIRONMENT env variable
        
        Returns:
            Config object with appropriate settings
        """
        env = environment or os.getenv('ENVIRONMENT', 'development').lower()
        
        configs = {
            'development': DevelopmentConfig,
            'staging': StagingConfig,
            'production': ProductionConfig,
        }
        
        config_class = configs.get(env, DevelopmentConfig)
        config = config_class()
        
        # Override with environment variables if present
        if os.getenv('THREAT_THRESHOLD'):
            config.THREAT_THRESHOLD = int(os.getenv('THREAT_THRESHOLD'))
        if os.getenv('LOG_LEVEL'):
            config.LOG_LEVEL = os.getenv('LOG_LEVEL')
        
        return config
    
    @staticmethod
    def print_config(config: Config) -> None:
        """Pretty print configuration"""
        print(f"\n{'='*60}")
        print(f"CyberShield AI - {config.ENVIRONMENT.upper()} Configuration")
        print(f"{'='*60}\n")
        
        for key, value in config.__dict__.items():
            if not key.startswith('_'):
                print(f"  {key:<35} : {value}")
        
        print(f"\n{'='*60}\n")


# Deployment scripts

DOCKER_CONFIG = """
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port
EXPOSE 5000

# Set environment
ENV ENVIRONMENT=production
ENV PYTHONUNBUFFERED=1

# Run application
CMD ["python", "dashboard.py"]
"""

DOCKER_COMPOSE_CONFIG = """
version: '3.8'

services:
  cybershield:
    build: .
    container_name: cybershield-api
    ports:
      - "5000:5000"
    environment:
      ENVIRONMENT: production
      THREAT_THRESHOLD: 60
      LOG_LEVEL: INFO
    volumes:
      - ./logs:/app/logs
      - ./models:/app/models
    restart: unless-stopped
    networks:
      - cybershield-net
  
  postgres:
    image: postgres:15
    container_name: cybershield-db
    environment:
      POSTGRES_DB: cybershield
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: secure_password_here
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - cybershield-net
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: cybershield-cache
    ports:
      - "6379:6379"
    networks:
      - cybershield-net
    restart: unless-stopped

volumes:
  pgdata:

networks:
  cybershield-net:
    driver: bridge
"""

KUBERNETES_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cybershield
  labels:
    app: cybershield
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cybershield
  template:
    metadata:
      labels:
        app: cybershield
    spec:
      containers:
      - name: cybershield
        image: cybershield:latest
        ports:
        - containerPort: 5000
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: THREAT_THRESHOLD
          value: "60"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: cybershield-service
spec:
  selector:
    app: cybershield
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
  type: LoadBalancer
"""

NGINX_CONFIG = """
upstream cybershield {
    server localhost:5000;
}

server {
    listen 80;
    server_name cybershield.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cybershield.example.com;
    
    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/cybershield.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybershield.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Proxy settings
    location / {
        proxy_pass http://cybershield;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass http://cybershield/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }
    
    # Rate limiting zone
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}
"""


def save_deployment_files():
    """Save all deployment configuration files"""
    
    files = {
        'Dockerfile': DOCKER_CONFIG,
        'docker-compose.yml': DOCKER_COMPOSE_CONFIG,
        'kubernetes.yaml': KUBERNETES_DEPLOYMENT,
        'nginx.conf': NGINX_CONFIG,
    }
    
    deployment_dir = './deployment'
    os.makedirs(deployment_dir, exist_ok=True)
    
    for filename, content in files.items():
        filepath = os.path.join(deployment_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Created: {filepath}")


# Usage examples
if __name__ == "__main__":
    # Get configuration for current environment
    config = ConfigManager.get_config()
    ConfigManager.print_config(config)
    
    # Save deployment files
    print("\nGenerating deployment configurations...")
    save_deployment_files()
    print("\nDeployment files saved to ./deployment/")
    
    # Print environment setup instructions
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║        CyberShield AI - Deployment Instructions           ║
    ╚════════════════════════════════════════════════════════════╝
    
    1. LOCAL DEVELOPMENT:
       $ python dashboard.py
       -> Access at http://localhost:5000
    
    2. DOCKER DEPLOYMENT:
       $ docker build -t cybershield:latest .
       $ docker run -p 5000:5000 cybershield:latest
    
    3. DOCKER COMPOSE:
       $ docker-compose up -d
       -> Includes PostgreSQL, Redis, and CyberShield
    
    4. KUBERNETES:
       $ kubectl apply -f deployment/kubernetes.yaml
       -> Creates deployment, service, and exposes via LoadBalancer
    
    5. NGINX REVERSE PROXY:
       $ sudo cp deployment/nginx.conf /etc/nginx/sites-available/cybershield
       $ sudo systemctl restart nginx
    
    ENVIRONMENT VARIABLES:
       ENVIRONMENT       : development | staging | production
       THREAT_THRESHOLD  : 40-60 (lower = more sensitive)
       LOG_LEVEL         : DEBUG | INFO | WARNING | ERROR
       API_TIMEOUT       : Seconds for API response timeout
    
    MONITORING:
       $ curl http://localhost:5000/api/health
       $ curl http://localhost:5000/api/status
    
    LOGS:
       Docker:   docker logs cybershield-api
       Local:    tail -f security.log
    
    ╚════════════════════════════════════════════════════════════╝
    """)
