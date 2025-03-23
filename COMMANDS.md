# Kube-Sec CLI - Commands Cheat Sheet

## Running Security Scans

### Run All Security Checks
```sh
kube-secure scan
```

### Disable Specific Checks
```sh
kube-secure scan --disable-checks privileged-containers
```

### Export Report in JSON Format
```sh
kube-secure scan --output-format json
```

### Export Report in CSV Format
```sh
kube-secure scan --output-format csv
```

### Schedule Daily Scan
```sh
kube-secure scan --schedule daily
```

### Schedule Weekly Scan
```sh
kube-secure scan --schedule weekly
```

---

## Kubernetes Security Checks Explained

- **Privileged Containers:** Identifies containers running with privileged mode enabled.
- **Host PID/Network Sharing:** Detects pods sharing the host process or network namespaces.
- **Pods Running as Root:** Finds pods running as root user.
- **RBAC Misconfigurations:** Analyzes misconfigured RBAC roles.
- **Publicly Accessible Services:** Identifies services exposed to public networks.

---

## Logs and Reports

### View Logs
```sh
tail -f logs/kube-secure.log
```

### View JSON Report
```sh
cat reports/security-report.json
```

### View CSV Report
```sh
cat reports/security-report.csv
```

