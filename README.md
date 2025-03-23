# Kubernetes Security Hardening CLI

## Overview
Kubernetes Security Hardening CLI is a tool designed to scan Kubernetes clusters for security misconfigurations and vulnerabilities. It helps identify issues such as:

- Privileged containers
- RBAC misconfigurations
- Publicly accessible services
- Pods running as root
- Host PID/network exposure

## Features
- **Cluster Connection:** Supports kubeconfig and Service Account authentication.
- **Security Scan:** Detects potential misconfigurations and vulnerabilities.
- **Scheduled Scans:** Runs daily or weekly background scans.// Not completed
- **Logging & Reporting:** Logs security scan results and exports reports in JSON/CSV formats.
- **Customizable Checks:** Allows users to disable specific security checks.

## Installation

```sh
# Clone the repository
git clone https://github.com/rahulbansod519/Kube-Sec.git
cd kube-sec/kube-secure

# Install 
pip install -e .
```

## Usage

### Connect to a Cluster
You can connect using kubeconfig or a Service Account.

```sh
# Connect using kubeconfig (default)
kube-sec connect

# Connect using Service Account
kube-sec connect <API_SERVER> --token-path <TOKEN-PATH>
```

For instructions on creating a Service Account, see [Service Account Setup](SERVICE_ACCOUNT.md).

### Run Security Scan

```sh
# Run a full security scan
kube-sec scan

# Disable specific checks (example: ignore RBAC misconfigurations)
## Security Checks
security_checks = {
            privileged-containers
            host-pid
            pods-running-as-root
            rbac-misconfig
            public-services
        }
kube-scan scan --disable rbac-misconfig

# Export results in JSON format
python main.py scan --output report.json
```

### Schedule a Scan

```sh
# Schedule a daily scan
kube-sec scan -s daily

# Schedule a weekly scan
kube-sec scan -s --weekly
```

## CLI Commands Cheatsheet
For a full list of available commands, see [Command Cheatsheet](COMMANDS.md).

## Service Account Setup
For creating a Service Account and retrieving its token, see [Service Account Setup](SERVICE_ACCOUNT.md).



