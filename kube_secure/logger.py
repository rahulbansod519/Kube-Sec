import logging
import keyring

logging.basicConfig(
    filename="logs/security_scan.log",
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_issue(severity, message):
    logging.info(f"[{severity}] {message}")


def save_credentials(api_server, token):
    keyring.set_password("kube-sec", "API_SERVER", api_server)
    keyring.set_password("kube-sec", "KUBE_TOKEN", token)
    print("🔐 Credentials saved securely using system keyring.")
