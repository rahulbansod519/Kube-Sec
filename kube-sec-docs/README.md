# Kube-Sec Docs

Kube-Sec is a Kubernetes security CLI focused on quick misconfiguration scanning for engineering and platform teams.

## What You’ll Find Here

- Installation and quickstart guidance
- Authentication patterns for kubeconfig and service accounts
- Built-in security checks and custom rules
- Logging, troubleshooting, and roadmap notes

## Suggested Reading Order

1. `installation.md`
2. `authentication.md`
3. `scanning.md`
4. `builtin-checks.md`
5. `custom-rules.md`

## Quickstart

```bash
python3 -m pip install -e .
kube-sec connect
kube-sec scan
```
