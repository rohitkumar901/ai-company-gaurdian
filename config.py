import os
from pathlib import Path

# Base Paths (Fully dynamic and relative)
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "guardian.db"
MODEL_PATH = DATA_DIR / "isolation_forest_model.joblib"
LOG_QUARANTINE_PATH = DATA_DIR / "quarantine_logs.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "AI Company Guardian"
APP_TAGLINE = "Enterprise AI-Driven SIEM & SOC Threat Hunting Platform"
APP_VERSION = "2.5.0-ENTERPRISE"

# Default Detection & SOAR Thresholds
DEFAULT_SETTINGS = {
    "brute_force_failure_threshold": 5,      # Failed attempts count
    "brute_force_window_minutes": 10,       # Window for burst in minutes
    "off_hours_start": 8,                   # 08:00 (8 AM)
    "off_hours_end": 20,                    # 20:00 (8 PM)
    "ip_spray_threshold": 10,               # Distinct user failures from same IP
    "ip_spray_window_minutes": 15,          # Window in minutes
    "ml_contamination_rate": 0.05,          # Isolation Forest contamination expectation
    "ml_anomaly_threshold": 0.65,           # Normalized score cutoff for alert generation
    "auto_containment_enabled": False,      # Automatic IP block on CRITICAL alerts
    "alert_retention_days": 180,            # Retention policy
    "smtp_enabled": False,                  # Email dispatch
    "smtp_server": "smtp.company.internal",
    "smtp_port": 587,
    "smtp_sender": "soc-alerts@company.internal",
    "smtp_recipient": "security-incident-response@company.internal",
    "smtp_username": "",
    "smtp_password": ""
}

# Supported Log Formats
SUPPORTED_EXTENSIONS = [".csv", ".json"]
REQUIRED_COLUMNS = ["timestamp", "username", "ip_address", "login_result"]
OPTIONAL_COLUMNS = ["event_type", "device_info", "country_code", "is_vpn"]

# Valid Login Results
VALID_LOGIN_RESULTS = {"SUCCESS", "FAILURE"}

# Known Attack Tool User-Agents (MITRE ATT&CK T1071.001)
SUSPICIOUS_USER_AGENTS = [
    "hydra",
    "sqlmap",
    "nmap",
    "nikto",
    "python-requests",
    "go-http-client",
    "curl",
    "wget",
    "metasploit",
    "masscan"
]
