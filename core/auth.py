import hashlib
import streamlit as st
from typing import Optional, Dict
from database.db import hash_password, get_connection
from database.queries import get_user_by_username, log_audit_event

def legacy_hash(password: str) -> str:
    """Fallback legacy hash for backward compatibility."""
    salt = "guardian_secure_salt_2026"
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Verify username and password against the database.
    Supports auto-migration if password was hashed with previous salt.
    """
    u_clean = username.strip()
    user = get_user_by_username(u_clean)
    if not user:
        return None

    current_hash = hash_password(password)
    stored_hash = user["password_hash"]

    # Match with current salt
    if stored_hash == current_hash:
        return user

    # Backward compatibility with legacy salt
    if stored_hash == legacy_hash(password):
        # Auto-upgrade stored hash to current salt
        conn = get_connection()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (current_hash, user["id"]))
        conn.commit()
        conn.close()
        user["password_hash"] = current_hash
        return user

    return None

def init_session_state():
    """Initialize default session state keys for auth and navigation."""
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Dashboard"

def login_user(user: Dict):
    """Set logged-in user in session state and record audit log."""
    st.session_state["authenticated"] = True
    st.session_state["user"] = user
    log_audit_event(user["username"], "LOGIN", str(user["id"]), f"User {user['username']} logged in successfully.")

def logout_user():
    """Clear session state and record audit log."""
    if st.session_state.get("user"):
        log_audit_event(st.session_state["user"]["username"], "LOGOUT", str(st.session_state["user"]["id"]), "User logged out.")
    st.session_state["authenticated"] = False
    st.session_state["user"] = None
    st.rerun()

def get_current_user() -> Optional[Dict]:
    """Return the currently logged-in user."""
    return st.session_state.get("user")

def is_admin() -> bool:
    """Return True if the current user has 'admin' role."""
    user = get_current_user()
    return user is not None and user.get("role") == "admin"

def is_analyst_or_admin() -> bool:
    """Return True if user is analyst or admin."""
    user = get_current_user()
    return user is not None and user.get("role") in ("admin", "analyst")
