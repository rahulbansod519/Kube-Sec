check_descriptions = {
    "host-pid-and-network-exposure": "Detects pods using hostPID or hostNetwork, which can break container isolation.",
    "root-user-pods": "Identifies pods running as root (UID 0), which can lead to privilege escalation.",
    "non-root-enforcement": "Ensures containers are explicitly set to run as non-root (runAsNonRoot: true).",
    "rbac-privileges": "Flags users or service accounts assigned overly permissive roles like cluster-admin.",
    "rbac-least-privilege": "Validates that RBAC follows the principle of least privilege.",
    "public-service-exposure": "Detects services exposed externally via NodePort or LoadBalancer.",
    "open-network-ports": "Lists open service ports that may be reachable externally.",
    "internal-traffic-controls": "Checks for missing or weak NetworkPolicies allowing unrestricted traffic.",
    "kubernetes-version": "Checks if the Kubernetes version is outdated or unsupported.",
    "external-service-exposure": "Detects LoadBalancer or NodePort services with public IPs.",
    "privileged-containers-and-hostpath-mounts": "Identifies containers running privileged or mounting hostPath volumes."
}
