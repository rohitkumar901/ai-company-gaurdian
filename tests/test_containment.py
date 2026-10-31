import pytest
from database.db import init_db
from database.queries import list_blocked_ips, list_suspended_accounts
from core.containment import (
    execute_ip_block_action,
    execute_user_suspension_action,
    execute_mfa_reset_action,
    generate_firewall_scripts
)

@pytest.fixture
def setup_db(tmp_path):
    p = str(tmp_path / "test_containment.db")
    init_db(p)
    return p

def test_generate_firewall_scripts():
    scripts = generate_firewall_scripts("198.51.100.99")
    assert "iptables" in scripts["Linux iptables"]
    assert "198.51.100.99" in scripts["Linux iptables"]
    assert "netsh advfirewall" in scripts["Windows Defender Firewall"]
    assert "access-list" in scripts["Cisco IOS ACL"]

def test_execute_containment_ip_block(setup_db):
    res = execute_ip_block_action("203.0.113.55", "Brute-force attacker", "analyst", "ALT-TEST-1", db_path=setup_db)
    assert res["status"] == "success"

def test_execute_containment_user_suspension(setup_db):
    admin_res = execute_user_suspension_action("admin", "test", "analyst", db_path=setup_db)
    assert admin_res["status"] == "error"

    u_res = execute_user_suspension_action("compromised_user", "Token leak", "analyst", "ALT-TEST-2", db_path=setup_db)
    assert u_res["status"] == "success"

def test_execute_mfa_reset(setup_db):
    mfa_res = execute_mfa_reset_action("target_user", "analyst", "ALT-TEST-3", db_path=setup_db)
    assert mfa_res["status"] == "success"
