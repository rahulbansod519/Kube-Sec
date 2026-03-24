import concurrent.futures
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import click
import keyring
import schedule
import yaml
from keyring.errors import PasswordDeleteError
from tabulate import tabulate
from kubernetes import client

from kube_secure import __version__
from kube_secure.check_metadata import check_descriptions
from kube_secure.custom_rules_engine import load_custom_rules, run_custom_scan
from kube_secure.logger import save_credentials
from kube_secure.scanner import (
    check_cluster_connection,
    check_host_pid_and_network,
    check_network_exposure,
    check_open_ports,
    check_pods_running_as_non_root,
    check_pods_running_as_root,
    check_privileged_containers_and_hostpath,
    check_publicly_accessible_services,
    check_rbac_least_privilege,
    check_rbac_misconfigurations,
    check_weak_firewall_rules,
    get_issue_counts,
    get_security_issues,
    reset_security_issues,
)
from kube_secure.session import clear_session, is_session_active, set_session_active

KEYRING_SERVICE = "kube-sec"
SSL_VERIFY_KEY = "SSL_VERIFY"
DEFAULT_REPORTS_DIR = "reports"
SCHEDULE_TIMES = {"daily": "02:00", "weekly": "03:00"}


@click.group()
@click.version_option(__version__, prog_name="kube-sec")
def cli():
    """Kube-Sec: Kubernetes security scanning for fast-moving teams."""


def build_security_checks():
    return {
        "host-pid-and-network-exposure": check_host_pid_and_network,
        "root-user-pods": check_pods_running_as_root,
        "non-root-enforcement": check_pods_running_as_non_root,
        "rbac-privileges": check_rbac_misconfigurations,
        "rbac-least-privilege": check_rbac_least_privilege,
        "public-service-exposure": check_publicly_accessible_services,
        "open-network-ports": check_open_ports,
        "internal-traffic-controls": check_weak_firewall_rules,
        "external-service-exposure": check_network_exposure,
        "privileged-containers-and-hostpath-mounts": check_privileged_containers_and_hostpath,
    }


def write_report(payload, output_format, report_file):
    default_name = f"kube-sec-report.{output_format}"
    destination = report_file or os.path.join(DEFAULT_REPORTS_DIR, default_name)
    report_dir = os.path.dirname(destination)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)

    with open(destination, "w", encoding="utf-8") as handle:
        if output_format == "json":
            json.dump(payload, handle, indent=2)
        else:
            yaml.safe_dump(payload, handle, default_flow_style=False, sort_keys=False)

    return destination


def render_results(results):
    click.secho("\n📦 Detailed Check Results:", fg="cyan", bold=True)
    for check_name, output in results.items():
        description = check_descriptions.get(check_name, "")
        click.secho(f"\n🔍 {check_name}", fg="cyan", bold=True)
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


def render_summary():
    critical, warning = get_issue_counts()
    issues = get_security_issues()

    click.echo("\n✅ Scan Completed")
    click.secho("\n📊 Security Summary:", bold=True)
    click.secho(f"   🔴 {critical} Critical Issues", fg="red")
    click.secho(f"   🟡 {warning} Warnings", fg="yellow")

    if not issues:
        click.secho("\n✅ No security issues found.", fg="green")
        return

    click.echo("\n🚨 Issues Detected:")
    for severity, message in issues:
        color = "red" if severity == "Critical" else "yellow"
        click.secho(f"[{severity.upper()}] {message}", fg=color)


def save_standard_scan_report(results, output_format, report_file, nodes):
    critical, warning = get_issue_counts()
    payload = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "api_server_version": results.get("_cluster", {}).get("api_server_version"),
        "node_count": len(nodes),
        "pod_count": results.get("_cluster", {}).get("pod_count"),
        "issues_summary": {
            "critical": critical,
            "warnings": warning,
        },
        "issues": [
            {"severity": severity, "message": message}
            for severity, message in get_security_issues()
        ],
        "scan_results": {
            key: value for key, value in results.items() if key != "_cluster"
        },
    }
    path = write_report(payload, output_format, report_file)
    click.secho(f"\n📝 Security report saved to {path}", fg="green")
    logging.info(f"Security report saved to {path}")


@click.command()
@click.argument("api_server", required=False)
@click.option("--token-path", type=click.Path(exists=True), help="Path to file containing the API token")
@click.option("--token", help="API token string")
@click.option("--insecure", is_flag=True, help="Disable SSL verification (not recommended)")
def connect(api_server, token_path, token, insecure):
    """Store cluster credentials or validate local kubeconfig access."""
    if is_session_active():
        click.secho("🔁 You are already connected to the cluster.", fg="yellow")
        logging.info("Connect command skipped: already connected.")
        return

    if not api_server and not token and not token_path:
        try:
            from kubernetes import config

            config.load_kube_config()
            set_session_active()
            click.secho("✅ Using kubeconfig for authentication.", fg="green")
            logging.info("Connected to cluster using kubeconfig.")
            return
        except Exception as exc:
            raise click.ClickException(
                f"No working kubeconfig found. Provide an API server with a token instead. Details: {exc}"
            )

    if token_path and token:
        raise click.ClickException("Provide either --token-path or --token, not both.")

    if not api_server:
        raise click.ClickException("An API server URL is required when using token-based authentication.")

    if token_path:
        try:
            with open(token_path, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise click.ClickException(f"Unable to read token file: {exc}") from exc

    if not token:
        raise click.ClickException("No token provided.")

    save_credentials(api_server, token)
    keyring.set_password(KEYRING_SERVICE, SSL_VERIFY_KEY, "false" if insecure else "true")
    set_session_active()

    click.secho("🔐 Credentials saved securely using system keyring.", fg="green")
    if insecure:
        click.secho("⚠️  SSL verification disabled. This is not recommended for production.", fg="yellow")

    logging.info("Connected to cluster using token-based credentials.")


@click.command()
def disconnect():
    """Clear any stored credentials and local session state."""
    session_was_active = is_session_active()

    deleted = 0
    for key in ["API_SERVER", "KUBE_TOKEN", "SSL_VERIFY"]:
        try:
            keyring.delete_password(KEYRING_SERVICE, key)
            deleted += 1
        except PasswordDeleteError:
            continue
        except Exception as exc:
            logging.error(f"Error deleting key {key}: {exc}")

    clear_session()
    if session_was_active:
        click.secho("🔓 Disconnected: session ended.", fg="green")
        logging.info("Session disconnected.")
    else:
        click.secho("ℹ️ No active session marker was found. Stored credentials were still checked.", fg="yellow")
        logging.info("Disconnect called without an active session marker.")

    if deleted > 0:
        click.secho("🔓 Token-based credentials removed from system keyring.", fg="green")
    else:
        click.secho("ℹ️ No stored token credentials were found. kubeconfig-based access is unchanged.", fg="yellow")


@click.command()
@click.option(
    "--disable-checks",
    "-d",
    multiple=True,
    help="Disable specific checks (for example: --disable-checks rbac-privileges)",
)
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["json", "yaml"], case_sensitive=False),
    help="Export report format",
)
@click.option(
    "--report-file",
    type=click.Path(dir_okay=False),
    help="Custom path for the exported report file",
)
@click.option(
    "--custom-rules",
    type=click.Path(exists=True),
    help="Path to a YAML file with custom resource validation rules",
)
@click.option(
    "--schedule",
    "-s",
    "schedule_option",
    type=click.Choice(["daily", "weekly"], case_sensitive=False),
    help="Run scans on a recurring schedule and keep the scheduler alive",
)
def scan(disable_checks, output_format, report_file, custom_rules, schedule_option):
    """Run the built-in security checks or evaluate a custom ruleset."""
    if report_file and not output_format:
        raise click.ClickException("--report-file requires --output-format.")

    security_checks = build_security_checks()
    unknown_checks = sorted(set(disable_checks) - set(security_checks))
    if unknown_checks:
        raise click.ClickException(
            f"Unknown check name(s): {', '.join(unknown_checks)}. Use the documented built-in check names."
        )

    def run_standard_scan():
        reset_security_issues()

        if not output_format:
            click.secho("\n🚀 Starting Kubernetes Security Scan...\n", fg="cyan", bold=True)

        logging.info("Standard scan initiated.")
        nodes = check_cluster_connection(show_details=not output_format)
        if not nodes:
            raise click.ClickException("Cannot proceed without cluster access.")

        if not output_format:
            click.secho("✅ Cluster connection verified.", fg="green")
            click.secho("\n🔍 Running Security Checks...", fg="cyan", bold=True)
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        enabled_checks = {
            name: func for name, func in security_checks.items() if name not in disable_checks
        }
        results = {}

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(len(enabled_checks), 8))
        ) as executor:
            future_to_check = {
                executor.submit(func): name for name, func in enabled_checks.items()
            }
            for future in concurrent.futures.as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    results[check_name] = future.result()
                except Exception as exc:
                    logging.error(f"Error running {check_name}: {exc}")
                    results[check_name] = {"error": str(exc)}

        results["_cluster"] = {
            "api_server_version": client.VersionApi().get_code().git_version,
            "pod_count": len(client.CoreV1Api().list_pod_for_all_namespaces().items),
        }

        if not output_format:
            render_results({key: value for key, value in results.items() if key != "_cluster"})
            render_summary()
        else:
            save_standard_scan_report(results, output_format.lower(), report_file, nodes)

        logging.info("Standard scan completed.")

    def run_custom_rules_scan():
        reset_security_issues()

        if not output_format:
            click.secho("\n🚀 Starting Custom Rule Scan...\n", fg="cyan", bold=True)

        nodes = check_cluster_connection(show_details=not output_format)
        if not nodes:
            raise click.ClickException("Cannot proceed without cluster access.")

        rule_def = load_custom_rules(custom_rules)
        if not rule_def:
            raise click.ClickException("Failed to load the custom rule file.")

        results = run_custom_scan(rule_def)

        if not output_format:
            click.secho("\n📦 Custom Rule Scan Results:", fg="cyan", bold=True)
            if not results:
                click.secho("✅ All custom rules passed!", fg="green")
                return

            grouped = defaultdict(list)
            for item in results:
                grouped[f"{item['Namespace']}/{item['Deployment']}"].append(
                    f"❌ {item['Rule']}: {item['Message']}"
                )

            for group, messages in grouped.items():
                namespace, deployment = group.split("/", 1)
                click.secho(f"\n📦 Namespace: {namespace}", fg="cyan", bold=True)
                click.secho(f"   └── Deployment: {deployment}", fg="yellow")
                for message in messages:
                    click.echo(f"       - {message}")
            return

        payload = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "scan_type": "custom-rules",
            "custom_rules_file": custom_rules,
            "results": results,
        }
        path = write_report(payload, output_format.lower(), report_file)
        click.secho(f"\n📝 Custom scan results saved to {path}", fg="green")
        logging.info(f"Custom scan results saved to {path}")

    run_scan = run_custom_rules_scan if custom_rules else run_standard_scan

    if not schedule_option:
        run_scan()
        return

    schedule.clear("kube-sec")
    scan_time = SCHEDULE_TIMES[schedule_option.lower()]
    if schedule_option.lower() == "daily":
        schedule.every().day.at(scan_time).do(run_scan).tag("kube-sec")
    else:
        schedule.every().monday.at(scan_time).do(run_scan).tag("kube-sec")

    click.echo(
        f"\n📅 Scheduled scan set to run {schedule_option.lower()} at {scan_time}. "
        "An initial scan will run now. Press Ctrl+C to stop the scheduler."
    )
    logging.info(f"Scheduled scan set to run {schedule_option.lower()} at {scan_time}.")

    run_scan()

    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        schedule.clear("kube-sec")
        click.secho("\n🛑 Scheduler stopped.", fg="yellow")
        logging.info("Scheduler stopped by user.")


cli.add_command(scan)
cli.add_command(connect)
cli.add_command(disconnect)


if __name__ == "__main__":
    cli()
