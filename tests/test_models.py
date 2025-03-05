from app.models import User, PasswordEntry
from app import db

def test_user_creation():
    user = User(username="testuser")
    user.set_password("testpass")
    assert user.username == "testuser"
    assert user.check_password("testpass")

def test_password_entry_encryption():
    entry = PasswordEntry(service="TestService", encrypted_password=b"encrypted_data")
    assert entry.service == "TestService"
    assert isinstance(entry.encrypted_password, bytes)

def test_2fa_secret_storage():
    user = User(username="2fa_user")
    user.totp_secret = "ABCDEFG123456"
    assert user.totp_secret == "ABCDEFG123456"