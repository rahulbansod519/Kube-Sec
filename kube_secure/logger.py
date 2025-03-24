import logging


logging.basicConfig(
    filename="logs/securiy_scan.log",
    level = logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_issue(severity, message):
    logging.info(f"[{severity}] {message}")