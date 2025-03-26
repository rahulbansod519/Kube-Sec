import keyring
import logging

# Define keys to store the session state
SESSION_KEY = "kube-sec-session"
CONNECTION_METHOD_KEY = "connection_method"  # Either 'kubeconfig' or 'token'

def set_session_active(connection_method):
    """Set the session to active and store the connection method."""
    keyring.set_password(SESSION_KEY, CONNECTION_METHOD_KEY, connection_method)
    logging.info(f"Session set as active using {connection_method}.")

def clear_session():
    """Clear the session."""
    keyring.delete_password(SESSION_KEY, CONNECTION_METHOD_KEY)
    logging.info("Session cleared.")

def get_connection_method():
    """Get the current connection method from the session."""
    return keyring.get_password(SESSION_KEY, CONNECTION_METHOD_KEY)

def is_session_active():
    """Check if the session is active."""
    return get_connection_method() is not None
