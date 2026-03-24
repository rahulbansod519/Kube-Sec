# Kube-Sec CLI Command Guide

## Authentication

Use local kubeconfig:

```bash
kube-sec connect
```

Use a service account token:

```bash
kube-sec connect https://your-api-server:6443 --token-path /path/to/token
```

Pass a raw token directly:

```bash
kube-sec connect https://your-api-server:6443 --token "$KUBE_TOKEN"
```

Clear stored session state and token-based credentials:

```bash
kube-sec disconnect
```

## Standard Scans

Run all built-in checks:

```bash
kube-sec scan
```

Disable specific checks:

```bash
kube-sec scan --disable-checks rbac-privileges
```

Disable multiple checks:

```bash
kube-sec scan --disable-checks rbac-privileges --disable-checks open-network-ports
```

## Reports

Export JSON:

```bash
kube-sec scan --output-format json
```

Export YAML:

```bash
kube-sec scan --output-format yaml
```

Write the report to a custom path:

```bash
kube-sec scan --output-format json --report-file reports/staging-scan.json
```

## Custom Rules

Run custom YAML-based checks:

```bash
kube-sec scan --custom-rules deployment-rules.yaml
```

Export custom-rule results:

```bash
kube-sec scan --custom-rules deployment-rules.yaml --output-format yaml
```

## Scheduling

Run an immediate scan, then keep scheduling daily scans at 02:00:

```bash
kube-sec scan --schedule daily
```

Run an immediate scan, then keep scheduling weekly scans on Monday at 03:00:

```bash
kube-sec scan --schedule weekly
```

Press `Ctrl+C` to stop the scheduler.

## Built-In Check Names

- `host-pid-and-network-exposure`
- `root-user-pods`
- `non-root-enforcement`
- `rbac-privileges`
- `rbac-least-privilege`
- `public-service-exposure`
- `open-network-ports`
- `internal-traffic-controls`
- `external-service-exposure`
- `privileged-containers-and-hostpath-mounts`

## Logs And Reports

- Logs are written under `logs/`
- Reports are written under `reports/` by default when `--output-format` is used
