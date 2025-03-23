import click
import logging
import os
import schedule
import time
import threading
import concurrent.futures
from dotenv import load_dotenv, set_key
from pathlib import Path
from kubernetes import config

from kube_secure.scanner import (
    check_cluster_connection,
    check_pods_running_as_root,
    check_rbac_misconfigurations,
    check_publicly_accessible_services,
    check_privileged_containers,
    check_host_pid_and_network,
    print_security_summary,
    save_json_report,
    save_csv_report
)

load_dotenv()
os.makedirs("logs", exist_ok=True)
dotenv_path = Path(".env")

def save_to_env(key, value):
    """Save key-value pair to .env file."""
    set_key(str(dotenv_path), key, value)
    click.echo(f"✅ {key} saved to .env")

@click.group()
def cli():
    """Kube-Secure: Kubernetes Security Hardening CLI"""
    pass

@click.command()
@click.argument('api_server', required=False)
@click.option('--token-path', type=click.Path(exists=True), help="Path to file containing the API token")
@click.option('--token', help="API token string")
def connect(api_server, token_path, token):
    """Connect to a Kubernetes cluster by saving API server and token."""
    if not api_server and not token and not token_path:
        try:
            config.load_kube_config()
            click.echo("✅ Using kubeconfig file for authentication.")
            click.echo("Cluster Authenticated Succesfully")
            return
        except Exception:
            click.echo("❌ No kubeconfig found. Provide --api-server and --token or --token-path.")
            return
    
    if token_path and token:
        click.echo("❌ Provide either --token-path or --token, not both.")
        return
    
    if token_path:
        with open(token_path, 'r') as f:
            token = f.read().strip()
    
    if not token:
        click.echo("❌ No token provided.")
        return
    
    save_to_env("API_SERVER", api_server)
    save_to_env("KUBE_TOKEN", token)
    click.echo("🔗 Kubernetes cluster connection details saved.")

@click.command()
@click.option('--disable-checks', '-d', multiple=True, help="Disable specific checks (e.g., --disable-checks privileged-containers)")
@click.option('--output-format', '-o', type=click.Choice(["json", "csv"], case_sensitive=False), help="Export report format")
@click.option('--schedule', '-s', "schedule_option", type=click.Choice(["daily", "weekly"], case_sensitive=False), help="Schedule security scans automatically")
def scan(disable_checks, output_format, schedule_option):
    """Run a Kubernetes security scan with optional filters."""
    click.echo("\n🚀 Running Kubernetes Security Scan...\n")

    if not check_cluster_connection():
        click.echo("\n❌ Exiting: Cannot proceed without cluster access.")
        logging.error("Cluster connection failed. Exiting.")
        return

    def run_scan():
        click.echo("\n✅ Cluster connection verified. Running security checks...\n")
        logging.info("Cluster connection verified. Running security checks.")

        security_checks = {
            "privileged-containers": check_privileged_containers,
            "host-pid": check_host_pid_and_network,
            "pods-running-as-root": check_pods_running_as_root,
            "rbac-misconfig": check_rbac_misconfigurations,
            "public-services": check_publicly_accessible_services
        }

        enabled_checks = [func for name, func in security_checks.items() if name not in disable_checks]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_check = {executor.submit(func): func.__name__ for func in enabled_checks}
            for future in concurrent.futures.as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error running {check_name}: {e}")

        print_security_summary()
        logging.info("Security scan completed.")

        if output_format == "json":
            save_json_report()
            logging.info("Security report saved as JSON.")
        elif output_format == "csv":
            save_csv_report()
            logging.info("Security report saved as CSV.")

    if schedule_option:
        schedule_times = {"daily": "02:00", "weekly": "03:00"}
        scan_time = schedule_times.get(schedule_option)

        if schedule_option == "daily":
            schedule.every().day.at(scan_time).do(run_scan)
        elif schedule_option == "weekly":
            schedule.every().monday.at(scan_time).do(run_scan)

        click.echo(f"\n📅 Scheduled scan set to run {schedule_option} at {scan_time}. Running in background.")
        logging.info(f"Scheduled scan set to run {schedule_option} at {scan_time}.")

        def background_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)

        thread = threading.Thread(target=background_scheduler, daemon=True)
        thread.start()
    else:
        run_scan()

cli.add_command(scan)
cli.add_command(connect)

if __name__ == "__main__":
    cli()
