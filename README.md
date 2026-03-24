# Kube-Sec

Kube-Sec is a lightweight Kubernetes security CLI for teams that want fast signal on risky cluster configurations without standing up a full platform first.

It focuses on practical day-one checks: privileged workloads, root containers, weak RBAC, public services, exposed ports, and ineffective network policies. You can run the built-in checks, add your own YAML rules, and export reports for triage or automation.

## Why It Matters

- Fast first scan with `kubeconfig` or token-based authentication
- Startup-friendly CLI that works well for local audits and CI experiments
- Actionable findings across workload, network, and RBAC exposure
- JSON or YAML reports for sharing, pipelines, or follow-up automation
- Extensible custom rule engine for deployment-level policy checks

## Built-In Checks

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

## Installation

```bash
git clone https://github.com/rahulbansod519/Kube-Sec.git
cd Kube-Sec
python3 -m pip install -e .
```

## Quickstart

Use local kubeconfig:

```bash
kube-sec connect
kube-sec scan
```

Use a service account token:

```bash
kube-sec connect https://your-api-server:6443 --token-path /path/to/token
kube-sec scan
```

You can also run `kube-sec scan` directly when your local `kubeconfig` is already valid.

## Common Workflows

Run the full built-in scan:

```bash
kube-sec scan
```

Skip one or more checks:

```bash
kube-sec scan --disable-checks rbac-privileges --disable-checks open-network-ports
```

Export a report:

```bash
kube-sec scan --output-format json
kube-sec scan --output-format yaml --report-file reports/prod-scan.yaml
```

Run custom rules:

```bash
kube-sec scan --custom-rules deployment-rules.yaml
```

Keep a recurring scheduler alive:

```bash
kube-sec scan --schedule daily
```

## Example Output

```text
📊 Security Summary:
   🔴 2 Critical Issues
   🟡 4 Warnings
```

Reports are written to `reports/kube-sec-report.json` or `reports/kube-sec-report.yaml` by default.

## Documentation

- [Commands](COMMANDS.md)
- [Service Account Setup](Service%20Account%20Setup.md)
- [Project Docs](kube-sec-docs/README.md)
- [OWASP Checks Notes](OWASP_checks.md)

## Near-Term Product Direction

- Add CI-ready exit codes and severity thresholds
- Expand custom-rule support beyond deployments
- Introduce richer report metadata and trend comparison
- Package official examples for common cluster hardening baselines

## Status

This project is still early, but the CLI and docs are now set up as a stronger foundation for a security-focused startup prototype: fast onboarding, clearer outputs, and more reliable scan behavior.
