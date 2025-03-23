# Kubernetes Security Hardening CLI


https://github.com/user-attachments/assets/c55b8fa9-2dfc-4497-bb4b-b9684b7c8ef2



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

For instructions on creating a Service Account, see [Service Account Setup](https://github.com/rahulbansod519/Kube-Sec/blob/main/Service%20Account%20Setup.md).

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
For a full list of available commands, see [Command Cheatsheet](https://github.com/rahulbansod519/Kube-Sec/blob/main/COMMANDS.md).

## Service Account Setup
For creating a Service Account and retrieving its token, see [Service Account Setup](https://github.com/rahulbansod519/Kube-Sec/blob/main/Service%20Account%20Setup.md).

## Disclaimer

This is a basic project, and more features are yet to come. It is not production-ready. We welcome feedback and suggestions on what features you would like to see in future updates.



