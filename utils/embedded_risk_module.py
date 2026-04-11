import time
import csv
import os
from datetime import datetime

# Global log storage
LOG_FILE = "security_breach_logs.csv"
LOG_HEADERS = ["timestamp", "action", "data_type", "data_accessed", "severity", "endpoint"]

def initialize_log_file():
    """Initialize CSV log file if it doesn't exist"""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=LOG_HEADERS)
            writer.writeheader()

def log_breach_event(action, data_type, data_accessed, severity, endpoint=""):
    """Log a security breach event to CSV"""
    initialize_log_file()
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "action": action,
        "data_type": data_type,
        "data_accessed": data_accessed,
        "severity": severity,
        "endpoint": endpoint
    }
    
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=LOG_HEADERS)
        writer.writerow(log_entry)
    
    return log_entry

def run_hidden_process():
    """Simulate unauthorized access to sensitive information"""
    logs = []

    # Log 1: AI module initialization
    log1 = log_breach_event(
        action="Module Initialization",
        data_type="system_info",
        data_accessed="AI module loaded without explicit user consent",
        severity="MEDIUM",
        endpoint="local_system"
    )
    logs.append(f"⚙️ AI module initialized... [{log1['timestamp']}]")
    time.sleep(0.5)

    # Log 2: System configuration access
    log2 = log_breach_event(
        action="System Configuration Access",
        data_type="config_files",
        data_accessed="/etc/system_config, environment_variables",
        severity="HIGH",
        endpoint="local_system"
    )
    logs.append(f"🔍 Accessing system configuration... [{log2['timestamp']}]")
    time.sleep(0.5)

    # Log 3: Credential access
    fake_admin_user = "admin_user"
    log3 = log_breach_event(
        action="Credential Access",
        data_type="authentication",
        data_accessed=f"Admin account: {fake_admin_user}",
        severity="CRITICAL",
        endpoint="local_system"
    )
    logs.append(f"🔑 Admin access detected (SIMULATED): {fake_admin_user} [{log3['timestamp']}]")
    time.sleep(0.5)

    # Log 4: Patient data access
    log4 = log_breach_event(
        action="Patient Data Access",
        data_type="PHI_data",
        data_accessed="Patient ID, Medical History, DICOM metadata",
        severity="CRITICAL",
        endpoint="local_system"
    )
    logs.append(f"📋 Accessing patient medical records (SIMULATED)... [{log4['timestamp']}]")
    time.sleep(0.5)

    # Log 5: Data packaging
    log5 = log_breach_event(
        action="Data Packaging",
        data_type="data_exfiltration",
        data_accessed="Compressed sensitive dataset created",
        severity="CRITICAL",
        endpoint="local_system"
    )
    logs.append(f"📦 Packaging sensitive information... [{log5['timestamp']}]")
    time.sleep(0.5)

    # Log 6: Data transmission
    fake_endpoint = "external-server.ai/api"
    log6 = log_breach_event(
        action="Data Transmission",
        data_type="network_exfiltration",
        data_accessed=f"Sending {len(logs)} log entries to external server",
        severity="CRITICAL",
        endpoint=fake_endpoint
    )
    logs.append(f"📡 Sending encrypted payload to {fake_endpoint} (SIMULATED) [{log6['timestamp']}]")
    time.sleep(0.5)

    # Log 7: Operation complete
    log7 = log_breach_event(
        action="Operation Complete",
        data_type="system_audit",
        data_accessed="Process completed without user notification",
        severity="HIGH",
        endpoint="local_system"
    )
    logs.append(f"✅ Operation completed silently [{log7['timestamp']}]")

    return logs

def get_breach_logs():
    """Retrieve all logged breach events"""
    if not os.path.exists(LOG_FILE):
        return None
    
    logs = []
    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            logs.append(row)
    
    return logs

def clear_breach_logs():
    """Clear all logged breach events"""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    initialize_log_file()
