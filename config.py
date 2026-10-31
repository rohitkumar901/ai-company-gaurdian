import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "guardian.db"
MODEL_PATH = DATA_DIR / "isolation_forest_model.joblib"
LOG_QUARANTINE_PATH = DATA_DIR / "quarantine_logs.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "AI Company Guardian"
APP_TAGLINE = "AI-Powered Authentication & Security Log Intelligence Platform"
APP_VERSION = "1.0.0-PROTOTYPE"

# Default Detection Thresholds
DEFAULT_SETTINGS = {
    "brute_force_failure_threshold": 5,      # Failed attempts count
    "brute_force_window_minutes": 10,       # Window for burst in minutes
    "off_hours_start": 8,                   # 08:00 (8 AM)
    "off_hours_end": 20,                    # 20:00 (8 PM)
    "ip_spray_threshold": 10,               # Distinct user failures from same IP
    "ip_spray_window_minutes": 15,          # Window in minutes
    "ml_contamination_rate": 0.05,          # Isolation Forest contamination expectation
    "ml_anomaly_threshold": 0.65,           # Normalised score cutoff for alert generation
    "alert_retention_days": 90,             # Retention policy
    "smtp_enabled": False,                  # Email dispatch
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "smtp_sender": "guardian-alerts@company.internal",
    "smtp_recipient": "soc-team@company.internal",
    "smtp_username": "",
    "smtp_password": ""
}

# Supported Log Formats
SUPPORTED_EXTENSIONS = [".csv", ".json"]
REQUIRED_COLUMNS = ["timestamp", "username", "ip_address", "login_result"]
OPTIONAL_COLUMNS = ["event_type", "device_info", "country_code", "is_vpn"]

# Valid Login Results
VALID_LOGIN_RESULTS = {"SUCCESS", "FAILURE"}
