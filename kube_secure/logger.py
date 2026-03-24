import logging
import os
from datetime import datetime
import keyring

KEYRING_SERVICE = "kube-sec"
API_SERVER_KEY = "API_SERVER"
TOKEN_KEY = "KUBE_TOKEN"

# Ensure log directory exists
log_dir = os.path.join(os.getcwd(), "logs")
os.makedirs(log_dir, exist_ok=True)

# Define log file name with date
log_file = os.path.join(log_dir, f"kube-sec-{datetime.now().strftime('%Y-%m-%d')}.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Suppress excessive external library logs (optional)
for noisy_logger in ["urllib3", "kubernetes"]:
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def save_credentials(api_server, token):
    keyring.set_password(KEYRING_SERVICE, API_SERVER_KEY, api_server)
    keyring.set_password(KEYRING_SERVICE, TOKEN_KEY, token)
