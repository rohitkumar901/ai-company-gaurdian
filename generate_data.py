import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

def generate_datasets():
    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 10, 25, 9, 0, 0)
    users = ["alice_dev", "bob_hr", "charlie_sales", "david_ops", "eve_qa", "grace_fin", "hank_sec"]
    internal_ips = ["10.0.1.15", "10.0.1.22", "10.0.2.45", "192.168.1.101", "192.168.1.150"]
    devices = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"
    ]

    events = []

    # 1. Normal business hour logins across 5 days (Mon-Fri, 9am - 6pm)
    for day in range(5):
        day_date = base_time + timedelta(days=day)
        for u in users:
            for _ in range(random.randint(3, 6)):
                hour = random.randint(9, 17)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = day_date.replace(hour=hour, minute=minute, second=second)
                # 97% success rate for normal users
                result = "SUCCESS" if random.random() < 0.97 else "FAILURE"
                events.append({
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "username": u,
                    "ip_address": random.choice(internal_ips),
                    "login_result": result,
                    "event_type": "LOGIN",
                    "device_info": random.choice(devices),
                    "country_code": "US",
                    "is_attack": 0
                })

    # 2. Attack Scenario 1: Brute-force burst on charlie_sales
    bf_start = base_time + timedelta(days=1, hours=14, minutes=10)
    attacker_ip_1 = "198.51.100.42"
    for i in range(8):
        ts = bf_start + timedelta(seconds=i * 25)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": "charlie_sales",
            "ip_address": attacker_ip_1,
            "login_result": "FAILURE",
            "event_type": "LOGIN",
            "device_info": "Python-requests/2.31.0",
            "country_code": "RU",
            "is_attack": 1
        })

    # 3. Attack Scenario 2: Brute-force burst followed by SUCCESS (Compromise) on david_ops
    comp_start = base_time + timedelta(days=2, hours=11, minutes=30)
    attacker_ip_2 = "203.0.113.88"
    for i in range(6):
        ts = comp_start + timedelta(seconds=i * 20)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": "david_ops",
            "ip_address": attacker_ip_2,
            "login_result": "FAILURE",
            "event_type": "LOGIN",
            "device_info": "Hydra/9.5",
            "country_code": "CN",
            "is_attack": 1
        })
    # The breakthrough success
    events.append({
        "timestamp": (comp_start + timedelta(seconds=130)).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "david_ops",
        "ip_address": attacker_ip_2,
        "login_result": "SUCCESS",
        "event_type": "LOGIN",
        "device_info": "Hydra/9.5",
        "country_code": "CN",
        "is_attack": 1
    })

    # 4. Attack Scenario 3: Password spraying across multiple users from single IP
    spray_start = base_time + timedelta(days=3, hours=15, minutes=0)
    spray_ip = "185.220.101.5"
    spray_targets = ["alice_dev", "bob_hr", "eve_qa", "grace_fin", "hank_sec", "admin_root", "service_backup"]
    for idx, target in enumerate(spray_targets * 2):
        ts = spray_start + timedelta(seconds=idx * 15)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": target,
            "ip_address": spray_ip,
            "login_result": "FAILURE",
            "event_type": "LOGIN",
            "device_info": "Go-http-client/1.1",
            "country_code": "DE",
            "is_attack": 1
        })

    # 5. Attack Scenario 4: Off-hours stealth logins (2:15 AM - 3:30 AM)
    off_hours_start = base_time + timedelta(days=4, hours=17, minutes=30) # Friday night / Sat early morning
    for i in range(5):
        ts = off_hours_start + timedelta(minutes=i * 12)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": random.choice(["alice_dev", "eve_qa"]),
            "ip_address": "45.33.32.156",
            "login_result": "FAILURE" if i % 2 == 0 else "SUCCESS",
            "event_type": "LOGIN",
            "device_info": "Tor Browser/13.0",
            "country_code": "NL",
            "is_attack": 1
        })

    # Sort all events chronologically
    events.sort(key=lambda x: x["timestamp"])

    # Write sample_auth_logs.csv (without is_attack label, typical real-world raw log)
    sample_csv_path = data_dir / "sample_auth_logs.csv"
    with open(sample_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "username", "ip_address", "login_result", "event_type", "device_info", "country_code"])
        writer.writeheader()
        for ev in events:
            row = {k: v for k, v in ev.items() if k != "is_attack"}
            writer.writerow(row)

    # Write test_labeled_logs.csv (with is_attack label for ML benchmark)
    labeled_csv_path = data_dir / "test_labeled_logs.csv"
    with open(labeled_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "username", "ip_address", "login_result", "event_type", "device_info", "country_code", "is_attack"])
        writer.writeheader()
        for ev in events:
            writer.writerow(ev)

    print(f"Generated {len(events)} events.")
    print(f"Sample log: {sample_csv_path}")
    print(f"Labeled log: {labeled_csv_path}")

if __name__ == "__main__":
    generate_datasets()
