import click
import logging
import os
import schedule
import time
import threading
import concurrent.futures

from kubernetes import config, client
import json
import yaml
import keyring
from datetime import datetime
from tabulate import tabulate
from keyring.errors import PasswordDeleteError
from kube_secure.check_metadata import check_descriptions


from kube_secure.scanner import (
    check_cluster_connection,
    check_pods_running_as_root,
    check_rbac_misconfigurations,
    check_publicly_accessible_services,
    check_privileged_containers_and_hostpath,
    check_host_pid_and_network,
    check_open_ports,
    check_weak_firewall_rules,
    security_issues,
    # check_kubernetes_version,
    check_pods_running_as_non_root,
    check_rbac_least_privilege,
    check_network_exposure
)
from kube_secure.logger import save_credentials

os.makedirs("logs", exist_ok=True)

@click.group()
def cli():
    """Kube-Secure: Kubernetes Security Hardening CLI"""
    pass

@click.command()
@click.argument('api_server', required=False)
@click.option('--token-path', type=click.Path(exists=True), help="Path to file containing the API token")
@click.option('--token', help="API token string")
@click.option('--insecure', is_flag=True, help="Disable SSL verification (Not recommended)")
def connect(api_server, token_path, token, insecure):
    if not api_server and not token and not token_path:
        try:
            config.load_kube_config()
            click.echo("✅ Using kubeconfig file for authentication.")
            click.echo("Cluster Authenticated Successfully")
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

    save_credentials(api_server, token)
    keyring.set_password("kube-sec", "SSL_VERIFY", "false" if insecure else "true")
    click.echo("🔐 Credentials saved securely using system keyring.")
    if insecure:
        click.echo("⚠️  SSL verification disabled. This is not recommended for production.")

@click.command()
def disconnect():
    deleted = 0
    for key in ["API_SERVER", "KUBE_TOKEN", "SSL_VERIFY"]:
        try:
            keyring.delete_password("kube-sec", key)
            deleted += 1
        except PasswordDeleteError:
            continue
        except Exception as e:
            logging.error(f"Error deleting key {key}: {e}")

    if deleted > 0:
        click.secho("🔓 Disconnected: credentials removed from system keyring.", fg="green")
    else:
        click.secho("ℹ️ You were using kubeconfig. Nothing to disconnect.", fg="yellow")

@click.command()
@click.option('--disable-checks', '-d', multiple=True, help="Disable specific checks (e.g., --disable-checks privileged-containers)")
@click.option('--output-format', '-o', type=click.Choice(["json", "yaml"], case_sensitive=False), help="Export report format")
@click.option('--schedule', '-s', "schedule_option", type=click.Choice(["daily", "weekly"], case_sensitive=False), help="Schedule security scans automatically")
def scan(disable_checks, output_format, schedule_option):
    if not output_format:
        click.secho("\n🚀 Starting Kubernetes Security Scan...\n", fg="cyan", bold=True)

    nodes = check_cluster_connection()
    if not nodes:
        error_report = {
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "error",
            "message": "Unable to connect to cluster",
            "scan_results": {}
        }
        if output_format == "json":
            with open("output.json", 'w') as f:
                json.dump(error_report, f, indent=4)
        elif output_format == "yaml":
            with open("output.yaml", 'w') as f:
                yaml.dump(error_report, f, default_flow_style=False, sort_keys=False)
        if not output_format:
            click.secho("\n❌ Cannot proceed without cluster access.", fg="red", bold=True)
        return

    def run_scan():
        if not output_format:
            click.secho("✅ Cluster connection verified.", fg="green")
            click.secho("\n🔍 Running Security Checks...", fg="cyan", bold=True)
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        logging.info("Cluster connection verified. Running security checks.")

        security_checks = {
            "host-pid-and-network-exposure": check_host_pid_and_network,
            "root-user-pods": check_pods_running_as_root,  
            "non-root-enforcement": check_pods_running_as_non_root,  
            "rbac-privileges": check_rbac_misconfigurations,  
            "rbac-least-privilege": check_rbac_least_privilege,  
            "public-service-exposure": check_publicly_accessible_services,  
            "open-network-ports": check_open_ports,  
            "internal-traffic-controls": check_weak_firewall_rules,  
            # "kubernetes-version": check_kubernetes_version,  
            "external-service-exposure": check_network_exposure,  
            "privileged-containers-and-hostpath-mounts": check_privileged_containers_and_hostpath  
        }


        enabled_checks = {name: func for name, func in security_checks.items() if name not in disable_checks}

        results = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_check = {executor.submit(func): name for name, func in enabled_checks.items()}
            for future in concurrent.futures.as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    results[check_name] = future.result()
                except Exception as e:
                    logging.error(f"Error running {check_name}: {e}")
                    results[check_name] = {"error": str(e)}

        critical = sum(1 for severity, _ in security_issues if severity == "Critical")
        warning = sum(1 for severity, _ in security_issues if severity == "Warning")

        if not output_format:
            click.echo("\n✅ Scan Completed")
            click.secho("\n📊 Security Summary:", bold=True)
            click.secho(f"   🔴 {critical} Critical Issues", fg="red")
            click.secho(f"   🟡 {warning} Warnings", fg="yellow")

            if security_issues:
                click.echo("\n🚨 Issues Detected:")
                for severity, message in security_issues:
                    color = "red" if severity == "Critical" else "yellow"
                    click.secho(f"[{severity.upper()}] {message}", fg=color)
            else:
                click.secho("\n✅ No security issues found.", fg="green")
        if not output_format:
            click.secho("\n📦 Detailed Check Results:", fg="cyan", bold=True)
            for check, output in results.items():
                description = check_descriptions.get(check, "")
                click.secho(f"\n🔍 {check}", fg="cyan", bold=True)
                if description:
                    click.echo(f"   ⤷ {description}")

                if isinstance(output, list) and output and isinstance(output[0], dict):
                    click.echo(tabulate(output, headers="keys", tablefmt="grid"))
                elif isinstance(output, list) and output:
                    for item in output:
                        click.echo(f" - {item}")
                elif output:
                    click.echo(str(output))
                else:
                    click.secho("✅ No issues found.", fg="green")


        logging.info("Security scan completed.")

        if output_format in ["json", "yaml"]:
            enriched_report = {
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "status": "completed",
                "api_server_version": client.VersionApi().get_code().git_version,
                "node_count": len(nodes),
                "pod_count": len(client.CoreV1Api().list_pod_for_all_namespaces().items),
                "issues_summary": {
                    "critical": critical,
                    "warnings": warning
                },
                "scan_results": results
            }
            json_data = json.dumps(enriched_report, indent=4)

            if output_format == "json":
                with open("output.json", 'w') as file:
                    file.write(json_data)
                logging.info("Security report saved as JSON.")

            elif output_format == "yaml":
                data = json.loads(json_data)
                with open("output.yaml", 'w') as file:
                    yaml.dump(data, file, default_flow_style=False, sort_keys=False)
                logging.info("Security report saved as YAML.")

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
cli.add_command(disconnect)

if __name__ == "__main__":
    cli()