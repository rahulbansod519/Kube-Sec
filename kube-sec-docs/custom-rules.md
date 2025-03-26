# Custom Rule Scanning

Define custom rules like:
```yaml
resource: Deployment
rules:
  - field: spec.replicas
    min: 2
    message: Must have at least 2 replicas
```

Then run:
```bash
kube-sec scan --custom-rules deployment-rules.yaml
```