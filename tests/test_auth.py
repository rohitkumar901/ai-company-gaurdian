import pytest
from database.db import hash_password, init_db
from database.queries import create_user, get_user_by_username, update_user_password, delete_user
from core.auth import authenticate_user

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    test_db = str(tmp_path / "test_guardian.db")
    init_db(test_db)
    return test_db

def test_password_hashing():
    pw1 = "MySecurePassword123"
    hash1 = hash_password(pw1)
    hash2 = hash_password(pw1)
    assert hash1 == hash2
    assert hash1 != pw1
    assert len(hash1) == 64 # SHA-256 hex string

def test_user_creation_and_auth(setup_test_db):
    db_path = setup_test_db
    # Create test analyst
    success = create_user("test_analyst", "AnalystPass123", "analyst", db_path=db_path)
    assert success is True

    # Duplicate creation should fail
    dup = create_user("test_analyst", "AnotherPass", "analyst", db_path=db_path)
    assert dup is False

    # Retrieve user
    u = get_user_by_username("test_analyst", db_path=db_path)
    assert u is not None
    assert u["role"] == "analyst"

    # Password update
    up_ok = update_user_password("test_analyst", "NewPass456", db_path=db_path)
    assert up_ok is True

    # User deletion
    del_ok = delete_user("test_analyst", db_path=db_path)
    assert del_ok is True
    assert get_user_by_username("test_analyst", db_path=db_path) is None

    # Protecting primary admin from deletion
    assert delete_user("admin", db_path=db_path) is False
