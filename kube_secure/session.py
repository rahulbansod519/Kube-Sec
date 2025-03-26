import keyring

SESSION_KEY = "kube-sec-session"

def set_session_active():
    """Mark the session as active (used in connect)."""
    keyring.set_password(SESSION_KEY, "status", "connected")

def clear_session():
    """Clear the session (used in disconnect)."""
    try:
        keyring.delete_password(SESSION_KEY, "status")
    except keyring.errors.PasswordDeleteError:
        pass

def is_session_active():
    """Check if a session is currently active."""
    try:
        return keyring.get_password(SESSION_KEY, "status") == "connected"
    except Exception:
        return False
