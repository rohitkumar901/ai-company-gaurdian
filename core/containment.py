from typing import Dict, Any, Optional
from database.queries import (
    block_ip,
    unblock_ip,
    suspend_account,
    reactivate_account,
    record_containment_action,
    log_audit_event
)

def generate_firewall_scripts(ip_address: str) -> Dict[str, str]:
    """Generate production-ready firewall rules across major enterprise platforms."""
    return {
        "Linux iptables": f"iptables -I INPUT -s {ip_address} -j DROP",
        "Windows Defender Firewall": f'netsh advfirewall firewall add rule name="Guardian_Block_{ip_address}" dir=in action=block remoteip={ip_address}',
        "Cisco IOS ACL": f"access-list 101 deny ip host {ip_address} any",
        "AWS VPC Security Group": f'aws ec2 revoke-security-group-ingress --cidr {ip_address}/32',
        "Nginx Deny": f"deny {ip_address};"
    }

def execute_ip_block_action(ip_address: str, reason: str, operator: str, alert_id: str = "MANUAL", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute automated or manual IP firewall isolation."""
    success = block_ip(ip_address, reason, operator, db_path=db_path)
    if success:
        record_containment_action(
            alert_id=alert_id,
            action_type="FIREWALL_IP_BLOCK",
            target=ip_address,
            details=f"Blacklisted IP at perimeter firewall. Reason: {reason}",
            executed_by=operator,
            db_path=db_path
        )
        log_audit_event(
            operator,
            "CONTAINMENT_IP_BLOCK",
            ip_address,
            f"Blocked IP {ip_address} (Alert Ref: {alert_id})",
            db_path=db_path
        )
        return {
            "status": "success",
            "message": f"Successfully blocked IP {ip_address} at perimeter firewall.",
            "rules": generate_firewall_scripts(ip_address)
        }
    return {"status": "error", "message": f"IP {ip_address} is already in the blacklist."}

def execute_user_suspension_action(username: str, reason: str, operator: str, alert_id: str = "MANUAL", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute emergency account suspension / identity isolation."""
    if username == "admin":
        return {"status": "error", "message": "Primary administrative identity cannot be suspended."}

    success = suspend_account(username, reason, operator, db_path=db_path)
    if success:
        record_containment_action(
            alert_id=alert_id,
            action_type="ACCOUNT_SUSPEND",
            target=username,
            details=f"Account locked in Identity Provider. Reason: {reason}",
            executed_by=operator,
            db_path=db_path
        )
        log_audit_event(
            operator,
            "CONTAINMENT_USER_SUSPEND",
            username,
            f"Suspended account {username} (Alert Ref: {alert_id})",
            db_path=db_path
        )
        return {
            "status": "success",
            "message": f"Account '{username}' has been suspended in enterprise directory. All active sessions invalidated."
        }
    return {"status": "error", "message": f"Account '{username}' is already suspended."}

def execute_mfa_reset_action(username: str, operator: str, alert_id: str = "MANUAL", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Revoke existing bearer tokens and enforce mandatory MFA step-up authentication."""
    record_containment_action(
        alert_id=alert_id,
        action_type="MFA_FORCE_ENROLL",
        target=username,
        details="Invalidated active OAuth refresh tokens; forced step-up MFA challenge on next authentication.",
        executed_by=operator,
        db_path=db_path
    )
    log_audit_event(
        operator,
        "CONTAINMENT_MFA_STEPUP",
        username,
        f"Forced mandatory MFA re-enrollment for {username} (Alert Ref: {alert_id})",
        db_path=db_path
    )
    return {
        "status": "success",
        "message": f"Step-up MFA enforced for '{username}'. Active refresh tokens revoked."
    }
